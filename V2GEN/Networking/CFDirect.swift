import Foundation
import Network
import Security

// ── Cloudflare IP-fronted HTTPS — the Iranian "clean IP" path ─────────────
// WHY THIS EXISTS: Iranian ISPs block Cloudflare NON-uniformally — some
// edge subnets are blocked, others stay open (the reason "clean CF IP"
// scanners are a whole genre in Iran), and the worker domain's DNS can
// also be poisoned. A login that rides only the DNS-resolved URL dies on
// the wrong ISP; with a filter-breaker on, everything works (the owner's
// exact symptom).
//
// THE TRICK: any Cloudflare edge IP serves the zone when the TLS SNI
// carries the real host — so a connection pinned to a chosen edge IP
// needs NO DNS at all and sidesteps both range-blocks and DNS pollution.
// PanelAPI races this against the plain URL path and keeps the winner.
//
// ALT PORTS: Cloudflare proxies HTTPS on 443 + 2053/2083/2087/2096/8443.
// Iranian ISP blocks are often (IP-range, port) specific — a front on an
// alternate port walks straight through a 443-only block. All verified
// live against the worker before shipping.
//
// TRANSPORT: NWConnection + system TLS (SNI = the real host, which is
// also the certificate-verification name). HTTP/1.0 with
// `Connection: close` keeps the response framing trivial: no chunked
// encoding — the body ends at EOF. One request per connection.
//
// The pool below was VERIFIED edge-by-edge (each IP answered the worker
// with SNI fronting) and is spread across CF ranges so a per-ISP block
// on one range leaves the others racing.

// The whole namespace is transport plumbing on background queues — it
// must NOT inherit the app's default MainActor isolation.
nonisolated enum CFDirect {

  enum CFDirectError: Error {
    case timeout
    case badResponse
  }

  /// Verified Cloudflare edge IPs — spread across 104.18/19/21.x,
  /// 162.159.x, 172.66.x, 188.114.x, 190.93.x, 103.21.x.
  static let pool: [String] = [
    "104.21.1.1",
    "104.21.14.201",
    "104.21.32.5",
    "104.21.48.1",
    "104.21.63.3",
    "104.18.32.7",
    "104.19.142.100",
    "172.66.0.96",
    "162.159.135.234",
    "162.159.136.7",
    "162.159.140.199",
    "188.114.96.3",
    "188.114.96.7",
    "188.114.97.100",
    "190.93.246.4",
    "103.21.244.10",
  ]

  /// Cloudflare's proxied HTTPS ports (all verified answering the worker).
  /// 443 first; the alternates dodge (range, port)-specific ISP blocks.
  static let httpsPorts: [UInt16] = [443, 2053, 2083, 2087, 2096, 8443]

  /// A parsed HTTP response — deliberately minimal (status, headers,
  /// body). Header keys lowercased.
  struct Response: Sendable {
    let status: Int
    let headers: [String: String]
    let body: Data

    func header(_ name: String) -> String? {
      headers[name.lowercased()]
    }
  }

  // MARK: - Request

  static func request(
    ip: String,
    host: String,
    path: String,
    method: String = "GET",
    body: Data? = nil,
    port: UInt16 = 443,
    timeout: TimeInterval = 12
  ) async throws -> Response {
    let conn = makeConnection(ip: ip, host: host, port: port)
    let session = NWSession(conn: conn)

    // Build the wire payload once (HTTP/1.0 — the body ends at EOF, no
    // chunked parsing).
    var head = "\(method) \(path) HTTP/1.0\r\n"
    head += "Host: \(host)\r\n"
    head += "User-Agent: V2GEN-iOS/1.0\r\n"
    if let body {
      head += "Content-Type: application/json\r\n"
      head += "Content-Length: \(body.count)\r\n"
    }
    head += "Connection: close\r\n\r\n"
    var payload = Data(head.utf8)
    if let body { payload.append(body) }

    // Race the exchange against a deadline (NWConnection has no built-in
    // request timeout); cancelling the task (lost race) kills the socket.
    return try await withThrowingTaskGroup(of: Response.self) { group in
      group.addTask {
        try await withTaskCancellationHandler {
          try await session.awaitReady()
          try await session.send(payload)
          let raw = try await session.receiveAll()
          session.cancel()
          return try Self.parse(raw)
        } onCancel: {
          session.cancel()
        }
      }
      group.addTask {
        try await Task.sleep(for: .seconds(timeout))
        session.cancel()
        throw CFDirectError.timeout
      }
      guard let first = try await group.next() else {
        throw CFDirectError.timeout
      }
      group.cancelAll()
      return first
    }
  }

  // MARK: - Connection

  private static func makeConnection(ip: String, host: String, port: UInt16) -> NWConnection {
    let params = NWParameters.tls
    // SNI = the real host: the edge routes the zone by it, and the
    // system verifier validates the certificate against it.
    if let tls = params.defaultProtocolStack.applicationProtocols
      .compactMap({ $0 as? NWProtocolTLS.Options }).first {
      sec_protocol_options_set_tls_server_name(
        tls.securityProtocolOptions, host
      )
    }
    return NWConnection(
      host: NWEndpoint.Host(ip),
      port: NWEndpoint.Port(rawValue: port) ?? 443,
      using: params
    )
  }

  // MARK: - Parsing

  private static func parse(_ raw: Data) throws -> Response {
    guard let range = raw.range(of: Data("\r\n\r\n".utf8)) else {
      throw CFDirectError.badResponse
    }
    let headData = raw[raw.startIndex..<range.lowerBound]
    let body = Data(raw[range.upperBound...])

    guard let headText = String(data: headData, encoding: .utf8) else {
      throw CFDirectError.badResponse
    }
    var lines = headText.components(separatedBy: "\r\n")
    guard !lines.isEmpty else { throw CFDirectError.badResponse }

    // Status line: "HTTP/1.1 200 OK"
    let statusParts = lines.removeFirst().split(separator: " ")
    guard statusParts.count >= 2, let status = Int(statusParts[1]) else {
      throw CFDirectError.badResponse
    }

    var headers: [String: String] = [:]
    for line in lines {
      guard let colon = line.firstIndex(of: ":") else { continue }
      let name = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
      let value = String(line[line.index(after: colon)...])
        .trimmingCharacters(in: .whitespaces)
      headers[name.lowercased()] = value
    }
    return Response(status: status, headers: headers, body: body)
  }
}

// ── One connection's async lifecycle ──────────────────────────────────────
// NWConnection reports through callbacks on its own queue; this bridges
// them to async/await with lock-guarded one-shot continuations (a state
// event must never resume twice) and a lock-guarded receive buffer.
// (nonisolated: transport plumbing on background queues — it must not
// inherit the app's default MainActor isolation.)
private nonisolated final class NWSession: @unchecked Sendable {
  private let conn: NWConnection
  private let lock = NSLock()
  private var connectResumed = false
  private var buffer = Data()

  /// Cancel the underlying socket (lost race / deadline) — callable
  /// from any task (NWSession is Sendable; NWConnection is not).
  func cancel() { conn.cancel() }

  init(conn: NWConnection) { self.conn = conn }

  func awaitReady() async throws {
    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
      conn.stateUpdateHandler = { [weak self] state in
        guard let self else { return }
        switch state {
        case .ready: self.finishConnect(cont, nil)
        case .failed(let error): self.finishConnect(cont, error)
        case .cancelled: self.finishConnect(cont, CFDirect.CFDirectError.timeout)
        default: break
        }
      }
      conn.start(queue: DispatchQueue(label: "v2gen.cfdirect"))
    }
  }

  private func finishConnect(
    _ cont: CheckedContinuation<Void, Error>, _ error: Error?
  ) {
    lock.lock()
    defer { lock.unlock() }
    guard !connectResumed else { return }
    connectResumed = true
    if let error { cont.resume(throwing: error) } else { cont.resume() }
  }

  func send(_ data: Data) async throws {
    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
      conn.send(content: data, completion: .contentProcessed { error in
        if let error { cont.resume(throwing: error) } else { cont.resume() }
      })
    }
  }

  /// Read until EOF (Connection: close). The connection's callbacks are
  /// serialized on its queue, so the recursion is single-threaded; the
  /// buffer lock only separates the queue from the awaiting caller.
  func receiveAll() async throws -> Data {
    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
      receiveChunk(cont)
    }
    lock.lock()
    let out = buffer
    lock.unlock()
    return out
  }

  private func receiveChunk(_ cont: CheckedContinuation<Void, Error>) {
    conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
      guard let self else { return }
      if let data {
        self.lock.lock()
        self.buffer.append(data)
        self.lock.unlock()
      }
      if let error {
        cont.resume(throwing: error)
      } else if isComplete {
        cont.resume()
      } else {
        self.receiveChunk(cont)
      }
    }
  }
}
