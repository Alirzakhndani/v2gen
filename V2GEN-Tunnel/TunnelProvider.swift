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

  // MARK: - Start / stop

  override func startTunnel(
    with options: [String : NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    guard let command = V2GenIPCFile.read(
      V2GenTunnelCommand.self, from: V2GenIPC.commandURL
    ) else {
      completionHandler(ProviderError.noCommand)
      return
    }
    guard let config = LinkConfig.parse(command.link) else {
      completionHandler(ProviderError.badLink)
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

    setTunnelNetworkSettings(settings) { [weak self] error in
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

  override func stopTunnel(
    with reason: NEProviderStopReason,
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
    stack?.resetAll()
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
    guard let engine else { return }
    // flowCount syncs onto the stack queue — safe here (stats queue ≠ stack).
    let snapshot = engine.snapshot(flows: stack?.flowCount ?? 0)
    V2GenIPCFile.write(snapshot, to: V2GenIPC.statsURL)
    if snapshot.state != lastPostedState {
      lastPostedState = snapshot.state
      V2GenDarwin.post(V2GenNotifyStats)
    }
  }
}
