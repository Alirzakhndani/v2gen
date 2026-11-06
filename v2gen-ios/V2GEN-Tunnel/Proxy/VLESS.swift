import Foundation

// ════════════════════════════════════════════════════════════════════════════
// VLESS + Trojan — the two simplest proxy codecs (both are "request header
// then raw pipe" protocols).
//
// VLESS  (xray proxy/vless/encoding):
//   request  = [ver=0][uuid16][addonLen=0][cmd=1(tcp)][port BE16]
//              [atyp][addr][payload…]
//   response = [ver=0][addonLen=0][payload…]
//
// Trojan (trojan-gfw spec):
//   request  = hex(SHA224(password)) [\r\n] [cmd=1][atyp][addr][port BE16]
//              [\r\n] [payload…]
//   response = payload… (raw)
// ════════════════════════════════════════════════════════════════════════════

// MARK: - Shared address encoding (SOCKS5-style, v2ray flavor)

enum SocksAddr {
  /// atyp + address + port, exactly as VLESS/Trojan/SS/VMess serialize it.
  static func encode(host: String, port: UInt16) -> [UInt8] {
    var out: [UInt8] = []
    if let v4 = ipv4Bytes(host) {
      out.append(0x01)
      out.append(contentsOf: v4)
    } else if host.contains(":") {
      out.append(0x03)
      out.append(contentsOf: ipv6Bytes(host) ?? [UInt8](repeating: 0, count: 16))
    } else {
      out.append(0x02)
      let name = Array(host.utf8)
      out.append(UInt8(min(name.count, 255)))
      out.append(contentsOf: name.prefix(255))
    }
    out.append(UInt8(port >> 8))
    out.append(UInt8(port & 0xFF))
    return out
  }

  static func ipv4Bytes(_ host: String) -> [UInt8]? {
    var addr = in_addr()
    guard host.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { return nil }
    return withUnsafeBytes(of: &addr) { Array($0.prefix(4)) }
  }

  static func ipv6Bytes(_ host: String) -> [UInt8]? {
    var addr = in6_addr()
    guard host.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else { return nil }
    return withUnsafeBytes(of: &addr) { Array($0) }
  }
}

// MARK: - VLESS

final class VLESSStream: ByteStream {
  private let underlying: ByteStream
  private let header: [UInt8]
  private var requestSent = false
  private var responsePrefixLeft = 2   // [ver][addonLen] before payload
  private var closed = false
  private var pendingRead: ((Data?, Error?) -> Void)?

  init(underlying: ByteStream, uuid: [UInt8], host: String, port: UInt16) {
    self.underlying = underlying
    var h: [UInt8] = [0x00]                    // version
    h.append(contentsOf: uuid)                 // 16-byte user id
    h.append(0x00)                             // addon length (no addons)
    h.append(0x01)                             // command: TCP
    h.append(UInt8(port >> 8))
    h.append(UInt8(port & 0xFF))
    h.append(contentsOf: SocksAddr.encode(host: host, port: port))
    self.header = h
  }

  func write(_ data: Data, completion: @escaping (Error?) -> Void) {
    if !requestSent {
      requestSent = true
      var first = Data(header)
      first.append(data)
      underlying.write(first) { error in
        if error != nil { self.teardown() }
        completion(error)
      }
      return
    }
    underlying.write(data) { error in
      if error != nil { self.teardown() }
      completion(error)
    }
  }

  func read(completion: @escaping (Data?, Error?) -> Void) {
    guard !closed else {
      completion(nil, StreamEOFError())
      return
    }
    guard pendingRead == nil else {
      completion(nil, StreamEOFError())
      return
    }
    pendingRead = completion
    pump()
  }

  private func pump() {
    underlying.read { [weak self] data, error in
      guard let self, let handler = self.pendingRead else { return }
      if let error {
        self.pendingRead = nil
        self.teardown()
        handler(nil, error)
        return
      }
      guard let data, !data.isEmpty else {
        self.pendingRead = nil
        self.teardown()
        handler(nil, StreamEOFError())
        return
      }
      // First bytes carry the response header: [ver][addonLen(=0)].
      // A non-zero addon length is honoured by skipping that many bytes too.
      var out = data
      if responsePrefixLeft > 0 {
        var consumed = 0
        var trimmed = Data()
        for byte in out {
          if responsePrefixLeft > 0 {
            responsePrefixLeft -= 1
            consumed += 1
            if consumed == 2 && byte != 0 {
              // addonLen != 0 — skip `byte` more bytes.
              responsePrefixLeft += Int(byte)
            }
            continue
          }
          trimmed.append(byte)
        }
        out = trimmed
      }
      if out.isEmpty {
        self.pump()   // whole buffer was the response header
        return
      }
      self.pendingRead = nil
      handler(out, nil)
    }
  }

  func close() {
    guard !closed else { return }
    teardown()
    if let handler = pendingRead {
      pendingRead = nil
      handler(nil, StreamEOFError())
    }
  }

  private func teardown() {
    closed = true
    underlying.close()
  }
}

// MARK: - Trojan

final class TrojanStream: ByteStream {
  private let underlying: ByteStream
  private let header: [UInt8]
  private var requestSent = false
  private var closed = false

  init(underlying: ByteStream, password: String, host: String, port: UInt16) {
    self.underlying = underlying
    var h: [UInt8] = Array(SHA224.hexDigest(password).utf8)   // 56 hex chars
    h.append(contentsOf: [0x0D, 0x0A])          // CRLF
    h.append(0x01)                              // command: TCP connect
    h.append(contentsOf: SocksAddr.encode(host: host, port: port))
    h.append(contentsOf: [0x0D, 0x0A])          // CRLF
    self.header = h
  }

  func write(_ data: Data, completion: @escaping (Error?) -> Void) {
    if !requestSent {
      requestSent = true
      var first = Data(header)
      first.append(data)
      underlying.write(first) { error in
        if error != nil { self.teardown() }
        completion(error)
      }
      return
    }
    underlying.write(data) { error in
      if error != nil { self.teardown() }
      completion(error)
    }
  }

  func read(completion: @escaping (Data?, Error?) -> Void) {
    guard !closed else {
      completion(nil, StreamEOFError())
      return
    }
    underlying.read { data, error in
      if error != nil || data == nil || data!.isEmpty {
        self.teardown()
        completion(nil, error ?? StreamEOFError())
        return
      }
      completion(data, nil)
    }
  }

  func close() {
    guard !closed else { return }
    teardown()
  }

  private func teardown() {
    closed = true
    underlying.close()
  }
}
