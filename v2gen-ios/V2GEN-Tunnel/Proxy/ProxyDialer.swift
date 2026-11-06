import Foundation

// ════════════════════════════════════════════════════════════════════════════
// ProxyDialer / ProxyEngine — the outbound side of the tunnel.
//
// Dialer: transport chain per flow —
//   NWConnection (TCP, optional TLS) → [WebSocket upgrade] → protocol codec
// → ProxyPipe (the ByteStream the TCP stack pumps through).
//
// Engine: owns the ACTIVE config (hot-swappable mid-session via IPC reload,
// without touching the TUN), the byte counters, and the dial-health state
// that grounds the app's Lantern failover ladder in real outcomes:
//   · every dial success  → resets the failure streak, state = connected
//   · consecutive failures with no live dials → state = failing (+ lastError)
// Existing flows keep their own (old-config) connections until they end —
// a swap only affects NEW dials, exactly like a Lantern member switch.
// ════════════════════════════════════════════════════════════════════════════

// MARK: - The pipe the TCP stack sees

final class ProxyPipe {
  private let stream: ByteStream
  fileprivate init(_ stream: ByteStream) {
    self.stream = stream
  }

  func write(_ data: Data, completion: @escaping (Error?) -> Void) {
    stream.write(data, completion: completion)
  }

  func read(completion: @escaping (Data?, Error?) -> Void) {
    stream.read(completion: completion)
  }

  func close() {
    stream.close()
  }
}

// MARK: - Dial pipeline

enum ProxyDialer {

  static func open(
    config: LinkConfig,
    targetHost: String,
    targetPort: UInt16,
    timeout: TimeInterval,
    onReady: @escaping (ProxyPipe) -> Void,
    onError: @escaping (String) -> Void
  ) {
    let queue = DispatchQueue(label: "v2gen.dial")
    let transport = NWByteStream(
      host: config.host, port: config.port,
      tls: config.tls, sni: config.sni, verifyTLS: config.verifyTLS,
      queue: queue
    )

    var settled = false
    func fail(_ message: String) {
      guard !settled else { return }
      settled = true
      transport.close()
      onError(message)
    }
    func ready(_ stream: ByteStream) {
      guard !settled else {
        stream.close()
        return
      }
      settled = true
      onReady(ProxyPipe(stream))
    }

    transport.ready(timeout: timeout) { error in
      if let error {
        fail("transport: \(error.localizedDescription)")
        return
      }

      func buildCodec(over base: ByteStream) {
        switch config.creds {
        case .vless(let uuid):
          ready(VLESSStream(
            underlying: base, uuid: uuid, host: targetHost, port: targetPort
          ))
        case .trojan(let password):
          ready(TrojanStream(
            underlying: base, password: password, host: targetHost, port: targetPort
          ))
        case .vmess(let uuid, let security):
          ready(VMessStream(
            underlying: base, uuid: uuid, security: security,
            host: targetHost, port: targetPort
          ))
        case .ss(let method, let password):
          if method.is2022 {
            ready(SS2022Stream(
              underlying: base, method: method, psk: password,
              host: targetHost, port: targetPort
            ))
          } else {
            ready(SSStream(
              underlying: base, method: method, password: password,
              host: targetHost, port: targetPort
            ))
          }
        }
      }

      if config.network == .ws {
        let wsHost = config.wsHost.isEmpty
          ? (config.tls ? (config.sni.isEmpty ? config.host : config.sni) : config.host)
          : config.wsHost
        WSStream.upgrade(
          over: transport,
          queue: queue,
          path: config.wsPath,
          host: wsHost,
          earlyDataBase64: nil,   // early data is an optional optimization;
                                  // correctness rides normal frames
          timeout: timeout
        ) { result in
          switch result {
          case .success(let ws):
            buildCodec(over: ws)
          case .failure(let error):
            fail("ws: \(error.localizedDescription)")
          }
        }
      } else {
        buildCodec(over: transport)
      }
    }
  }
}

// MARK: - Engine

final class ProxyEngine {
  private let lock = NSLock()

  // Active config (hot-swapped by IPC reload).
  private(set) var config: LinkConfig?
  private var commandID = 0
  private var tag = ""

  // Counters + health
  private var bytesUp = 0
  private var bytesDown = 0
  private var liveDials = 0
  private var failureStreak = 0
  private var lastError: String?
  private var state: V2GenTunnelStats.State = .starting
  private var everConnected = false

  /// Fake-IP → domain (installed by the provider at start).
  var resolveHost: (UInt32) -> String? = { _ in nil }

  // MARK: - Config

  func update(config: LinkConfig, commandID: Int, tag: String) {
    lock.lock()
    defer { lock.unlock() }
    guard self.commandID != commandID else { return }   // stale reload
    self.config = config
    self.commandID = commandID
    self.tag = tag
    self.failureStreak = 0
    self.lastError = nil
    self.state = everConnected ? .connected : .starting
  }

  // MARK: - Dial (stack hook)

  func dial(
    targetIP: UInt32,
    targetPort: UInt16,
    onReady: @escaping (ProxyPipe) -> Void,
    onError: @escaping (String) -> Void
  ) {
    lock.lock()
    guard let config = config else {
      lock.unlock()
      onError("no active config")
      return
    }
    liveDials += 1
    lock.unlock()

    // Fake-IP → domain; literal targets stay numeric (the proxy routes
    // the raw IP, no local resolution, no leak).
    let host = resolveHost(targetIP) ?? ProxyEngine.ipString(targetIP)

    ProxyDialer.open(
      config: config,
      targetHost: host,
      targetPort: targetPort,
      timeout: 10,
      onReady: { [weak self] pipe in
        guard let self else { return }
        self.lock.lock()
        self.liveDials -= 1
        self.failureStreak = 0
        self.everConnected = true
        self.state = .connected
        self.lock.unlock()
        onReady(pipe)
      },
      onError: { [weak self] message in
        guard let self else { return }
        self.lock.lock()
        self.liveDials -= 1
        self.failureStreak += 1
        self.lastError = message
        if self.failureStreak >= 2 && self.liveDials <= 0 {
          self.state = .failing
        }
        self.lock.unlock()
        onError(message)
      }
    )
  }

  // MARK: - Bytes + stats

  func addBytes(up: Int, down: Int) {
    lock.lock()
    bytesUp += up
    bytesDown += down
    lock.unlock()
  }

  func snapshot(flows: Int) -> V2GenTunnelStats {
    lock.lock()
    defer { lock.unlock() }
    return V2GenTunnelStats(
      commandID: commandID, tag: tag, state: state,
      bytesUp: bytesUp, bytesDown: bytesDown, flows: flows,
      lastError: lastError,
      updatedAt: Date().timeIntervalSince1970
    )
  }

  static func ipString(_ v: UInt32) -> String {
    let b = TCPStack.ip4Bytes(v)
    return "\(b[0]).\(b[1]).\(b[2]).\(b[3])"
  }
}
