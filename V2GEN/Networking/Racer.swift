import Foundation
import Network
import Security

// ── Lantern-style config racer — probe layer ──────────────────────────────
// Mirrors Lantern's probe model (mutableautoselect_probe.go + internal/
// probe/probe.go), ported from the web app and upgraded to the full
// mechanism we extracted from the lantern-box fork:
//   · parallel probes (6 workers — Lantern probeConcurrency)
//   · per-protocol timeouts (Lantern behaviorFor: vless/vmess/ss sit in
//     the 2000 ms class, unknown links in the 3000 ms class)
//   · TLS-aware probe: links that carry TLS/Reality are measured through
//     the handshake — a raw TCP connect cannot see the censorship pattern
//     where SYN passes but the handshake is reset
//   · optional TOTAL budget (Lantern's ladder re-probe runs every member
//     in parallel under a 10 s budget)
// The selection policy itself (hysteresis, demotion tiers, failover)
// lives in AutoSelect.swift — this file only measures.
//
// `nonisolated`: the project builds with MainActor-by-default isolation
// (write-swift skill); the racer must NOT hop to the main actor between
// probes, so the whole type opts out.

nonisolated enum Racer {
  static let probeConcurrency = 6   // Lantern probeConcurrency

  /// The physical interface the user's internet currently rides ("en0",
  /// "pdp_ip0", …). Probes bind to it so that while the VPN tunnel is up
  /// they measure the RAW internet, not a loop through our own tunnel —
  /// the exact same reachability the race would see before connecting.
  private static let interfaceLock = NSLock()
  nonisolated(unsafe) private static var _physicalInterfaceName: String?

  static func setPhysicalInterface(_ name: String?) {
    interfaceLock.lock()
    _physicalInterfaceName = name
    interfaceLock.unlock()
  }

  static func physicalInterfaceName() -> String? {
    interfaceLock.lock()
    defer { interfaceLock.unlock() }
    return _physicalInterfaceName
  }

  /// Lantern `behaviorFor` — per-protocol probe timeout classes.
  static func behaviorTimeout(for config: ParsedConfig) -> TimeInterval {
    switch config.proto {
    case .vless, .vmess, .ss: 2      // Lantern: Shadowsocks/VMess/VLESS/Trojan → 2000 ms
    case .other: 3                   // Lantern: protocol-specific long class
    }
  }

  /// Time a single connect (TCP, or TCP+TLS handshake for TLS configs) to
  /// the config's endpoint — a real reachability signal from the user's
  /// own internet.
  static func probe(_ config: ParsedConfig, timeout: TimeInterval? = nil) async -> ProbeResult {
    guard !config.host.isEmpty, (1...65535).contains(config.port) else {
      return ProbeResult(config: config, rttMs: nil)
    }
    let limit = timeout ?? behaviorTimeout(for: config)
    let start = ContinuousClock.now
    let ready = await connectReady(
      host: config.host,
      port: config.port,
      parameters: probeParameters(for: config),
      timeout: limit
    )
    let d = start.duration(to: .now)
    let ms = Int(d.components.seconds * 1000
      + d.components.attoseconds / 1_000_000_000_000)
    return ProbeResult(config: config, rttMs: ready ? max(ms, 1) : nil)
  }

  /// Race all configs with a worker pool. `budget` caps the TOTAL wait
  /// (Lantern's ladderTotalBudget = 10 s); nil means per-probe timeouts
  /// only. Returns successes sorted by RTT.
  static func race(_ configs: [ParsedConfig], budget: TimeInterval? = nil) async -> [ProbeResult] {
    guard !configs.isEmpty else { return [] }
    let deadline = budget.map { Date().addingTimeInterval($0) }
    let cursor = ProbeCursor(configs)
    return await withTaskGroup(of: [ProbeResult].self) { group in
      for _ in 0..<min(probeConcurrency, configs.count) {
        group.addTask {
          var mine: [ProbeResult] = []
          while let config = await cursor.take() {
            let remaining = deadline?.timeIntervalSinceNow ?? .infinity
            guard remaining > 0 else { break }   // budget spent — keep what we have
            mine.append(await probe(config, timeout: min(behaviorTimeout(for: config), remaining)))
          }
          return mine
        }
      }
      var results: [ProbeResult] = []
      for await batch in group { results += batch }
      return results
        .filter { $0.rttMs != nil }
        .sorted { ($0.rttMs ?? .max) < ($1.rttMs ?? .max) }
    }
  }
}

/// Work cursor shared by the probe workers.
private actor ProbeCursor {
  private var configs: [ParsedConfig]

  init(_ configs: [ParsedConfig]) {
    self.configs = configs
  }

  func take() -> ParsedConfig? {
    configs.isEmpty ? nil : configs.removeFirst()
  }
}

extension Racer {
  /// TCP parameters for plain configs, TLS parameters for links that
  /// carry `security=tls|reality` (vless) or `tls:"tls"` (vmess).
  ///
  /// Certificate identity is deliberately NOT verified: the probe
  /// measures whether the transport comes up on the user's internet —
  /// self-signed, origin-certificate and Reality endpoints must all
  /// probe clean. The SNI comes from the link (`sni`/`peer`), falling
  /// back to the host.
  private static func probeParameters(for config: ParsedConfig) -> NWParameters {
    let parameters: NWParameters
    if config.isTLS {
      let tls = NWProtocolTLS.Options()
      let options = tls.securityProtocolOptions
      sec_protocol_options_set_verify_block(
        options,
        { _, _, complete in complete(true) },
        DispatchQueue.global()
      )
      let name = config.sni ?? config.host
      if !name.isEmpty {
        sec_protocol_options_set_tls_server_name(options, name)
      }
      parameters = NWParameters(tls: tls)
    } else {
      parameters = .tcp
    }
    // NOTE: binding to the physical interface by name isn't possible in the
    // app process (NWInterface objects can't be constructed from a name).
    // Live-session probes may route through the tunnel — acceptable, since
    // the failover ladder primarily reacts to real dial outcomes in tunnel
    // stats rather than these probes.
    return parameters
  }

  /// True when the connection reaches `.ready` before the timeout. For
  /// TLS parameters `.ready` fires only after the handshake completes.
  /// The connection is always cancelled exactly once and the continuation
  /// resumes exactly once (queue-guarded).
  private static func connectReady(
    host: String,
    port: Int,
    parameters: NWParameters,
    timeout: TimeInterval
  ) async -> Bool {
    guard let endpoint = NWEndpoint.Port(rawValue: UInt16(port)) else { return false }
    let connection = NWConnection(
      host: NWEndpoint.Host(host),
      port: endpoint,
      using: parameters
    )
    let queue = DispatchQueue(label: "v2gen.probe")
    return await withCheckedContinuation { continuation in
      let state = ProbeState()
      let finish: @Sendable (Bool) -> Void = { ok in
        guard state.finish() else { return }
        connection.cancel()
        continuation.resume(returning: ok)
      }
      connection.stateUpdateHandler = { st in
        switch st {
        case .ready: finish(true)
        case .failed, .cancelled: finish(false)
        default: break
        }
      }
      queue.asyncAfter(deadline: .now() + timeout) { finish(false) }
      connection.start(queue: queue)
    }
  }
}

/// Once-only latch guarding continuation resumption.
private final class ProbeState: @unchecked Sendable {
  private let lock = NSLock()
  private var done = false

  /// Returns true exactly the first time it is called.
  func finish() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    if done { return false }
    done = true
    return true
  }
}
