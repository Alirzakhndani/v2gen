import Foundation
import NetworkExtension

// ════════════════════════════════════════════════════════════════════════════
// TunnelProvider — the NEPacketTunnelProvider: the real VPN.
//
// Lifecycle:
//   startTunnel → read the app's command (App Group) → parse the sub link →
//   engine + TCP stack + FakeDNS → TUN settings (198.18.0.1, default routes
//   v4+v6, DNS hijacked to the fake resolver) → packet loop.
//
//   Hot-swap: the app rewrites the command file and posts a Darwin
//   notification — the engine swaps the active config for NEW dials while
//   live flows drain through their old connections (Lantern-style member
//   switch without a TUN teardown).
//
//   Stats: 1-second snapshots to the App Group + Darwin notification on
//   state changes (connected / failing) so the app's failover ladder reacts
//   to REAL dial outcomes, not just probes.
// ════════════════════════════════════════════════════════════════════════════

final class TunnelProvider: NEPacketTunnelProvider {

  private enum ProviderError: Error, CustomStringConvertible {
    case noCommand
    case badLink

    var description: String {
      switch self {
      case .noCommand: return "missing tunnel command"
      case .badLink: return "unsupported config link"
      }
    }
  }

  private let stackQueue = DispatchQueue(label: "v2gen.tun.stack")
  /// Stats publishing runs OFF the stack queue — flowCount syncs onto it.
  private let statsQueue = DispatchQueue(label: "v2gen.tun.stats")
  private var stack: TCPStack?
  private var engine: ProxyEngine?
  private let fakeDNS = FakeDNS()
  private var statsTimer: DispatchSourceTimer?
  private var reloadObserver: DarwinObservationToken?
  private var lastPostedState: V2GenTunnelStats.State?
  private var currentCommandID = 0

  // ── Stable Connect (background failover) / Kill Switch (fail-closed) ──
  private var command: V2GenTunnelCommand?
  /// When we first saw the persistent .failing state on the CURRENT link —
  /// the auto-advance waits a short grace window so a single flaky dial
  /// does not rotate the config.
  private var failingSince: Date?
  /// Index into command.failoverLinks (0 = the primary link that started
  /// this tunnel). Never walks backwards — a link that failed stays benched
  /// for the life of the session.
  private var failoverIndex = 0

  // MARK: - Start / stop

  override func startTunnel(
    _ options: [String: Any],
    completionHandler: @escaping (Error?) -> Void
  ) {
    // Command transport, in priority order:
    //   1. the App Group file (freshest — the app just wrote it)
    //   2. the profile's providerConfiguration (survives signers without
    //      App Groups AND on-demand restarts while the app is suspended)
    //   3. the startVPNTunnel options dictionary (same JSON, cold path #2)
    let command = V2GenIPCFile.read(
      V2GenTunnelCommand.self, from: V2GenIPC.commandURL
    ) ?? Self.commandFromProfile(self) ?? Self.commandFromOptions(options)

    guard let command else {
      completionHandler(ProviderError.noCommand)
      return
    }
    self.command = command
    self.failoverIndex = 0
    self.failingSince = nil

    // Kill Switch fail-closed: even an UNPARSEABLE link must not tear the
    // tunnel down (a dead tunnel = traffic leaks through the physical
    // interface). Bring the TUN up with no engine — every dial fails, so
    // nothing leaves the device. The app's ladder will hot-swap a good
    // config in as soon as it has one.
    guard let config = LinkConfig.parse(command.link) else {
      if command.killSwitch == true {
        bringUpBlackhole(command: command, completionHandler: completionHandler)
      } else {
        completionHandler(ProviderError.badLink)
      }
      return
    }
    currentCommandID = command.id

    let engine = ProxyEngine()
    engine.update(config: config, commandID: command.id, tag: command.tag)
    engine.resolveHost = { [weak self] ip in
      self?.fakeDNS.domain(for: ip)
    }

    let stack = TCPStack(queue: stackQueue)
    stack.onDial = { [weak engine] _, targetIP, targetPort, onReady, onError in
      engine?.dial(
        targetIP: targetIP, targetPort: targetPort,
        onReady: onReady, onError: onError
      )
    }
    stack.onBytes = { [weak engine] up, down in
      engine?.addBytes(up: up, down: down)
    }
    stack.onSendPackets = { [weak self] packets in
      self?.send(packets)
    }
    stack.onDNSPacket = { [weak self] ip in
      guard let self, let response = self.fakeDNS.response(to: ip) else { return }
      self.send([Data(response)])
    }

    self.engine = engine
    self.stack = stack

    installTunnelSettings { [weak self] error in
      guard let self else {
        completionHandler(nil)
        return
      }
      if let error {
        completionHandler(error)
        return
      }
      self.installReloadObserver()
      self.startStatsLoop()
      self.startReadLoop()
      completionHandler(nil)
    }
  }

  /// Default routes v4+v6 through the TUN, DNS hijacked to the fake
  /// resolver — shared by the normal start and the Kill Switch blackhole.
  private func installTunnelSettings(
    completion: @escaping (Error?) -> Void
  ) {
    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: "198.18.0.1"
    )

    let ipv4 = NEIPv4Settings(
      addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"]
    )
    ipv4.includedRoutes = [NEIPv4Route.default()]
    settings.ipv4Settings = ipv4

    // Capture IPv6 too (no leak path), even though the data plane answers
    // AAAA with an empty NOERROR and only carries IPv4.
    let ipv6 = NEIPv6Settings(
      addresses: ["fdfe:dcba:9876:5432::1"], networkPrefixLengths: [64]
    )
    ipv6.includedRoutes = [NEIPv6Route.default()]
    settings.ipv6Settings = ipv6

    let dns = NEDNSSettings(servers: ["198.18.0.1"])
    dns.matchDomains = [""]          // every lookup lands in the fake pool
    settings.dnsSettings = dns

    settings.mtu = 1500

    setTunnelNetworkSettings(settings) { error in
      completion(error)
    }
  }

  override func stopTunnel(
    _ reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    reloadObserver = nil
    statsTimer?.cancel()
    statsTimer = nil
    stack?.resetAll()
    stack = nil
    engine = nil
    completionHandler()
  }

  // MARK: - Command transports (cold paths)

  /// The command JSON riding inside the saved VPN profile — set by the app
  /// on every start, so on-demand restarts always find the LATEST config
  /// even with the app suspended and/or no App Group.
  private static func commandFromProfile(
    _ provider: NEPacketTunnelProvider
  ) -> V2GenTunnelCommand? {
    guard let dict = provider.protocolConfiguration?.providerConfiguration
      as? [String: Any] else { return nil }
    return V2GenTunnelCommand.fromProviderConfiguration(dict)
  }

  private static func commandFromOptions(
    _ options: [String: Any]
  ) -> V2GenTunnelCommand? {
    V2GenTunnelCommand.fromProviderConfiguration(options)
  }

  // MARK: - Kill Switch blackhole

  /// TUN up, NO engine: every TCP dial fails inside the stack, DNS answers
  /// nothing usable — the device is quiet while the app finds a good
  /// config. Never call this when killSwitch is off (a dead link should
  /// then fail honestly so iOS stops retrying).
  private func bringUpBlackhole(
    command: V2GenTunnelCommand,
    completionHandler: @escaping (Error?) -> Void
  ) {
    self.command = command
    currentCommandID = command.id
    let stack = TCPStack(queue: stackQueue)
    stack.onDial = { _, _, _, _, onError in onError("blackhole") }   // fail-closed
    stack.onBytes = { _, _ in }
    stack.onSendPackets = { [weak self] packets in
      self?.send(packets)
    }
    stack.onDNSPacket = { _ in }                          // no answers
    self.stack = stack

    installTunnelSettings { [weak self] error in
      guard error == nil else {
        completionHandler(error)
        return
      }
      self?.installReloadObserver()   // the app may hot-swap a good config in
      self?.startStatsLoop()
      self?.startReadLoop()
      completionHandler(nil)
    }
  }

  // MARK: - Packet plumbing

  private func startReadLoop() {
    packetFlow.readPackets { [weak self] packets, _ in
      guard let self, let stack = self.stack else { return }
      self.stackQueue.async {
        for packet in packets {
          stack.handlePacket([UInt8](packet))
        }
      }
      self.startReadLoop()
    }
  }

  private func send(_ packets: [Data]) {
    let protocols = packets.map { _ in NSNumber(value: AF_INET) }
    packetFlow.writePackets(packets, withProtocols: protocols)
  }

  // MARK: - Hot-swap (app → tunnel)

  private func installReloadObserver() {
    reloadObserver = V2GenDarwin.observe(V2GenNotifyReload) { [weak self] in
      DispatchQueue.main.async { self?.reloadConfig() }
    }
  }

  private func reloadConfig() {
    guard let command = V2GenIPCFile.read(
      V2GenTunnelCommand.self, from: V2GenIPC.commandURL
    ) else { return }
    guard command.id != currentCommandID else { return }
    guard let config = LinkConfig.parse(command.link) else { return }
    currentCommandID = command.id
    engine?.update(config: config, commandID: command.id, tag: command.tag)
    stack?.noteConfigChanged()
  }

  // MARK: - Stats (tunnel → app)

  private func startStatsLoop() {
    let timer = DispatchSource.makeTimerSource(queue: statsQueue)
    timer.schedule(deadline: .now() + 1.0, repeating: 1.0)
    timer.setEventHandler { [weak self] in
      self?.publishStats()
    }
    timer.resume()
    statsTimer = timer
  }

  private func publishStats() {
    // Blackhole mode (Kill Switch with no parseable config): no engine, but
    // the app still deserves honest stats — failing + blackholed tag.
    guard let engine else {
      let blackhole = V2GenTunnelStats(
        commandID: currentCommandID,
        tag: command?.tag ?? "blackhole",
        state: .failing,
        bytesUp: 0, bytesDown: 0, flows: 0,
        lastError: "kill-switch blackhole — no working config",
        updatedAt: Date().timeIntervalSince1970
      )
      V2GenIPCFile.write(blackhole, to: V2GenIPC.statsURL)
      if lastPostedState != blackhole.state {
        lastPostedState = blackhole.state
        V2GenDarwin.post(V2GenNotifyStats)
      }
      return
    }
    // flowCount syncs onto the stack queue — safe here (stats queue ≠ stack).
    let snapshot = engine.snapshot(flows: stack?.flowCount ?? 0)
    V2GenIPCFile.write(snapshot, to: V2GenIPC.statsURL)
    if snapshot.state != lastPostedState {
      lastPostedState = snapshot.state
      V2GenDarwin.post(V2GenNotifyStats)
    }
    // Stable Connect: the CURRENT link has been failing for a grace window
    // → rotate to the next ranked link (update() hot-swaps the engine's
    // config; live flows drain through their old connections).
    maybeAdvanceFailover(snapshot: snapshot)
  }

  // MARK: - Stable Connect auto-advance

  /// Grace window before rotating: a single flaky dial must not bounce the
  /// user between configs.
  private static let failoverGrace: TimeInterval = 4.0

  private func maybeAdvanceFailover(snapshot: V2GenTunnelStats) {
    guard let command, command.stableConnect == true else { return }
    guard let links = command.failoverLinks, !links.isEmpty else { return }

    if snapshot.state != .failing {
      failingSince = nil
      return
    }
    // Count the primary link as index 0 — the next candidate is
    // failoverIndex + 1.
    let next = failoverIndex + 1
    guard next <= links.count else { return }   // list exhausted — keep trying

    let now = Date()
    if let since = failingSince {
      guard now.timeIntervalSince(since) >= Self.failoverGrace else { return }
    } else {
      failingSince = now
      return
    }

    let link = links[next - 1]
    let tag = command.failoverTags.map { $0[min(next - 1, $0.count - 1)] }
      ?? "failover-\(next)"
    guard let config = LinkConfig.parse(link) else {
      // Unparseable candidate — skip it and keep walking.
      failoverIndex = next
      failingSince = now
      return
    }
    failoverIndex = next
    failingSince = now
    // NOTE: do NOT touch currentCommandID — it guards reload staleness
    // against the app's monotonic ids. Failover rotations reuse the SAME
    // command id; the tag in stats names the live member.
    engine?.update(config: config, commandID: command.id, tag: tag)
    stack?.noteConfigChanged()
  }
}
