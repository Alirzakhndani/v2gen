import Foundation
import Network

// ════════════════════════════════════════════════════════════════════════════
// NWTransport — the ByteStream implementation over Network.framework.
//
// One NWConnection per outbound proxy session: plain TCP, or TLS with the
// config's SNI. Inside a packet-tunnel provider these sockets dial out the
// physical interface (iOS exempts the provider's own traffic from the tunnel
// routes — with `includeAllNetworks` left off, as it is here).
// ════════════════════════════════════════════════════════════════════════════

final class NWByteStream: ByteStream {
  private let connection: NWConnection
  private let queue: DispatchQueue
  private var closed = false
  private var pendingRead: ((Data?, Error?) -> Void)?
  private var failed: Error?

  init(host: String, port: UInt16, tls: Bool, sni: String, verifyTLS: Bool,
       queue: DispatchQueue) {
    self.queue = queue

    let parameters: NWParameters
    if tls {
      let tlsOptions = NWProtocolTLS.Options()
      let sec = tlsOptions.securityProtocolOptions
      let name = sni.isEmpty ? host : sni
      if !name.isEmpty {
        sec_protocol_options_set_tls_server_name(sec, name)
      }
      if !verifyTLS {
        // Self-signed / origin-certificate endpoints (allowInsecure=1 links):
        // accept whatever the server presents. The proxy protocol itself is
        // authenticated, so this is the same trust model xray uses for
        // allowInsecure.
        sec_protocol_options_set_verify_block(
          sec, { _, _, complete in complete(true) }, queue
        )
      }
      parameters = NWParameters(tls: tlsOptions)
    } else {
      parameters = .tcp
    }
    parameters.allowLocalEndpointReuse = true

    connection = NWConnection(
      host: NWEndpoint.Host(host),
      port: NWEndpoint.Port(rawValue: port) ?? 443,
      using: parameters
    )
  }

  // MARK: - ByteStream

  func write(_ data: Data, completion: @escaping (Error?) -> Void) {
    queue.async { [weak self] in
      guard let self, !self.closed else {
        completion(StreamEOFError())
        return
      }
      self.connection.send(
        content: data,
        completion: .contentProcessed { error in
          completion(self.closed ? StreamEOFError() : error)
        }
      )
    }
  }

  func read(completion: @escaping (Data?, Error?) -> Void) {
    queue.async { [weak self] in
      guard let self, !self.closed else {
        completion(nil, self?.failed ?? StreamEOFError())
        return
      }
      guard self.pendingRead == nil else {
        // Protocol violation by a codec — treat as fatal.
        self.fail(NWError.posix(.EPROTO), closeNow: true)
        completion(nil, self.failed)
        return
      }
      self.pendingRead = completion
      self.connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
        data, _, isComplete, error in
        self.queue.async {
          guard let handler = self.pendingRead else { return }
          self.pendingRead = nil
          if let data, !data.isEmpty {
            handler(data, nil)
          } else if let error {
            self.fail(error, closeNow: true)
            handler(nil, self.failed)
          } else if isComplete {
            self.fail(StreamEOFError(), closeNow: true)
            handler(nil, self.failed)
          } else {
            // Zero-length receive with no error and not complete — keep reading.
            self.pumpRead(handler: handler)
          }
        }
      }
    }
  }

  private func pumpRead(handler: @escaping (Data?, Error?) -> Void) {
    if closed {
      handler(nil, failed ?? StreamEOFError())
      return
    }
    pendingRead = handler
    connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
      data, _, isComplete, error in
      self.queue.async {
        guard let handler = self.pendingRead else { return }
        self.pendingRead = nil
        if let data, !data.isEmpty {
          handler(data, nil)
        } else if let error {
          self.fail(error, closeNow: true)
          handler(nil, self.failed)
        } else if isComplete {
          self.fail(StreamEOFError(), closeNow: true)
          handler(nil, self.failed)
        } else {
          self.pumpRead(handler: handler)
        }
      }
    }
  }

  func close() {
    queue.async { [weak self] in
      guard let self, !self.closed else { return }
      self.closed = true
      self.connection.cancel()
      if let pending = self.pendingRead {
        self.pendingRead = nil
        pending(nil, StreamEOFError())
      }
    }
  }

  // MARK: - Lifecycle

  /// Wait for the transport to be ready (TCP + optional TLS handshake).
  /// Timeout is enforced by the caller (they race a timer).
  func ready(timeout: TimeInterval, completion: @escaping (Error?) -> Void) {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    var settled = false
    timer.schedule(deadline: .now() + timeout)
    timer.setEventHandler { [weak self] in
      guard let self, !settled else { return }
      settled = true
      timer.cancel()
      self.fail(NWError.posix(.ETIMEDOUT), closeNow: true)
      completion(NWError.posix(.ETIMEDOUT))
    }
    timer.resume()

    connection.stateUpdateHandler = { [weak self] state in
      guard let self else { return }
      self.queue.async {
        guard !settled else { return }
        switch state {
        case .ready:
          settled = true
          timer.cancel()
          completion(nil)
        case .failed(let error):
          settled = true
          timer.cancel()
          self.fail(error, closeNow: true)
          completion(error)
        case .cancelled:
          settled = true
          timer.cancel()
          completion(StreamEOFError())
        default:
          break
        }
      }
    }
    connection.start(queue: queue)
  }

  private func fail(_ error: Error, closeNow: Bool) {
    if failed == nil { failed = error }
    if closeNow && !closed {
      closed = true
      connection.cancel()
    }
  }
}
