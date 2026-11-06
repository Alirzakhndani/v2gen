import Foundation

// ════════════════════════════════════════════════════════════════════════════
// ByteStream — the one transport abstraction the protocol codecs depend on.
// Implementations:
//   · NWByteStream  (iOS, Network.framework — TCP / TLS)   [Support/NWTransport.swift]
//   · PosixStream   (Linux verification harness only)
// The codecs (SS2022 / VLESS / VMess / Trojan / WebSocket) are written against
// this protocol ONLY, which is what allows the exact shipping code to be
// compiled and exercised against real servers on Linux.
// ════════════════════════════════════════════════════════════════════════════

protocol ByteStream: AnyObject {
  /// Queue bytes; completion fires exactly once (nil error = accepted).
  /// Implementations preserve write ordering.
  func write(_ data: Data, completion: @escaping (Error?) -> Void)
  /// Deliver whatever arrives (up to a few buffers worth); `nil` data = EOF.
  /// Exactly one outstanding read at a time.
  func read(completion: @escaping (Data?, Error?) -> Void)
  func close()
}

struct StreamEOFError: Error {}

// ════════════════════════════════════════════════════════════════════════════
// StreamReader — buffered exact-size reads over a ByteStream.
// Single-consumer: the tunnel runs each connection's reader on one logical
// path at a time (readExact chains). All state is confined to the callback
// chain started at `start()`.
// ════════════════════════════════════════════════════════════════════════════

final class StreamReader {
  private let stream: ByteStream
  private var buffer = Data()
  private var started = false
  private var closed = false

  // Pending request (one at a time — chained by the protocol layer).
  private var needed: Int?
  private var onExact: ((Data?, Error?) -> Void)?

  init(stream: ByteStream) {
    self.stream = stream
  }

  /// Begin consuming the stream. Subsequent `readExact` calls are served
  /// from the internal buffer and fresh reads.
  func start() {
    guard !started else { return }
    started = true
    pumpRead()
  }

  private func pumpRead() {
    stream.read { [weak self] data, error in
      guard let self else { return }
      if let data, !data.isEmpty {
        self.buffer.append(data)
        self.servePendingIfPossible()
        if !self.closed { self.pumpRead() }
      } else {
        // EOF or error — fail any pending request.
        self.closed = true
        self.failPending(error ?? StreamEOFError())
      }
    }
  }

  /// Read exactly `count` bytes (nil on EOF before count).
  func readExact(_ count: Int, completion: @escaping (Data?, Error?) -> Void) {
    if buffer.count >= count {
      let head = buffer.prefix(count)
      buffer.removeFirst(count)
      completion(Data(head), nil)
      return
    }
    guard !closed else {
      completion(nil, StreamEOFError())
      return
    }
    // One pending request at a time — a second call before the first
    // completes is a programming error in the protocol layer.
    precondition(needed == nil, "overlapping readExact calls")
    needed = count
    onExact = { data, error in
      completion(data, error)
    }
    servePendingIfPossible()
  }

  private func servePendingIfPossible() {
    guard let count = needed else { return }
    if buffer.count >= count {
      let head = buffer.prefix(count)
      buffer.removeFirst(count)
      let cb = onExact
      needed = nil
      onExact = nil
      cb?(Data(head), nil)
    }
  }

  private func failPending(_ error: Error) {
    guard let cb = onExact else { return }
    needed = nil
    onExact = nil
    cb(nil, error)
  }
}

// ════════════════════════════════════════════════════════════════════════════
// Small helpers shared by the protocol codecs.
// ════════════════════════════════════════════════════════════════════════════

enum Wire {
  /// SOCKS5-style address bytes: [1 IPv4 | 3 domain | 4 IPv6] + addr + portBE.
  static func socksAddress(host: String, port: UInt16) -> [UInt8]? {
    let parts = host.split(separator: ".", omittingEmptySubsequences: false)
    if parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) {
      return [1, UInt8(parts[0])!, UInt8(parts[1])!, UInt8(parts[2])!, UInt8(parts[3])!,
              UInt8(port >> 8), UInt8(port & 0xFF)]
    }
    if host.hasPrefix("[") && host.hasSuffix("]") {
      // Bare IPv6 literal without a scope — pack 16 bytes.
      let groups = host.dropFirst().dropLast()
        .split(separator: ":", omittingEmptySubsequences: false)
      var bytes = [UInt8]()
      var hextets: [UInt16] = []
      for g in groups {
        if let v = UInt16(g, radix: 16) { hextets.append(v) }
        else { return nil }
      }
      if hextets.count == 8 {
        for hx in hextets {
          bytes.append(UInt8(hx >> 8)); bytes.append(UInt8(hx & 0xFF))
        }
        return [4] + bytes + [UInt8(port >> 8), UInt8(port & 0xFF)]
      }
      return nil   // compressed IPv6 (e.g. 2600::1) — not emitted by our links
    }
    guard let asciiHost = host.data(using: .utf8), asciiHost.count <= 255,
          host.range(of: "^[a-zA-Z0-9._-]+$", options: .regularExpression) != nil
    else { return nil }
    var out = [UInt8]([3, UInt8(asciiHost.count)])
    out.append(contentsOf: asciiHost)
    out.append(UInt8(port >> 8))
    out.append(UInt8(port & 0xFF))
    return out
  }

  static func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
  }
}
