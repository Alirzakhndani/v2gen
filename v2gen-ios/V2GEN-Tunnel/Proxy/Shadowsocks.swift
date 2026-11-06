import Foundation
import Security

// ════════════════════════════════════════════════════════════════════════════
// Shadowsocks — classic AEAD (SIP004) and Shadowsocks-2022 (SIP022).
//
// Wire formats ported 1:1 from sing-shadowsocks (the verified reference):
//
// Classic AEAD:
//   request  = [salt(keyLen)] chunk(socksAddr ‖ firstPayload) chunk …
//   response = [salt(keyLen)] chunk …
//   chunk    = [len BE16 ‖ tag] [payload ‖ tag]
//              (nonce: LE96 counter — one increment per Seal/Open; the
//               length block and the data block each consume one)
//   subkey   = HKDF-SHA1(key=EVP_BytesToKey(password), salt=salt,
//                        info="ss-subkey", keyLen)
//
// Shadowsocks-2022 (psk = password bytes, length == key length):
//   request  = [salt(keyLen)]
//              bareAEAD(type=0 ‖ ts BE64 ‖ varLen BE16)          — 11 bytes
//              bareAEAD(socksAddr ‖ padLen BE16 ‖ pad ‖ payload)
//              chunk …
//   response = [salt(keyLen)]
//              bareAEAD(type=1 ‖ ts BE64 ‖ requestSalt ‖ varLen BE16)
//              bareAEAD(varLen bytes)                            — padding
//              chunk …
//   subkey   = blake3.derive_key("shadowsocks 2022 session subkey",
//                                psk ‖ salt)
//   (bareAEAD = one AEAD block without a length prefix, one nonce step)
// ════════════════════════════════════════════════════════════════════════════

// MARK: - Shared AEAD plumbing

/// 96-bit little-endian AEAD nonce counter (SIP004 / SIP022).
struct AEADNonce {
  private var bytes = [UInt8](repeating: 0, count: 12)

  mutating func next() -> [UInt8] {
    let current = bytes
    increment()
    return current
  }

  mutating func increment() {
    for i in 0..<12 {
      bytes[i] &+= 1
      if bytes[i] != 0 { break }
    }
  }
}

/// Cipher dispatch for every Shadowsocks method (classic and 2022).
enum SSCipher {
  case aesGCM(key: [UInt8])
  case chaCha20(key: [UInt8])

  func seal(_ plaintext: [UInt8], nonce: [UInt8]) -> [UInt8]? {
    switch self {
    case .aesGCM(let key):
      return V2Crypto.aesGCMSeal(plaintext: plaintext, key: key, nonce: nonce)
    case .chaCha20(let key):
      return V2Crypto.chaChaSeal(plaintext: plaintext, key: key, nonce: nonce)
    }
  }

  func open(_ combined: [UInt8], nonce: [UInt8]) -> [UInt8]? {
    switch self {
    case .aesGCM(let key):
      return V2Crypto.aesGCMOpen(combined: combined, key: key, nonce: nonce)
    case .chaCha20(let key):
      return V2Crypto.chaChaOpen(combined: combined, key: key, nonce: nonce)
    }
  }

  static func make(method: LinkConfig.SSMethod, key: [UInt8]) -> SSCipher {
    switch method {
    case .aes128gcm, .aes192gcm, .aes256gcm,
         .blake3aes128gcm, .blake3aes256gcm:
      return .aesGCM(key: key)
    case .chacha20poly1305, .xchacha20poly1305, .blake3chacha20:
      return .chaCha20(key: key)
    }
  }
}

/// [len BE16 ‖ tag] [payload ‖ tag] — the classic chunk. Returns nil when
/// encryption fails (impossible with well-formed keys — callers fail closed).
func ssChunk(_ plain: [UInt8], cipher: SSCipher, nonce: inout AEADNonce) -> [UInt8]? {
  let lenBytes = [UInt8(plain.count >> 8), UInt8(plain.count & 0xFF)]
  guard let sealedLen = cipher.seal(lenBytes, nonce: nonce.next()),
        let sealedBody = cipher.seal(plain, nonce: nonce.next())
  else { return nil }
  return sealedLen + sealedBody
}

// MARK: - Classic AEAD

final class SSStream: ByteStream {
  private let underlying: ByteStream
  private let method: LinkConfig.SSMethod
  private let keyLen: Int
  private let masterKey: [UInt8]      // EVP_BytesToKey(password)
  private let address: [UInt8]
  private var writeCipher: SSCipher?
  private var writeNonce = AEADNonce()
  private var readCipher: SSCipher?
  private var readNonce = AEADNonce()

  private var requestSent = false
  private var closed = false

  private enum ReadPhase {
    case salt(remaining: Int)
    case lengthPrefix(remaining: Int)   // 2 + 16 bytes
    case body(remaining: Int)           // length + 16 bytes
  }
  private var readPhase: ReadPhase
  private var readBuffer = [UInt8]()
  private var pendingLength = 0
  private var pendingRead: ((Data?, Error?) -> Void)?

  init(underlying: ByteStream, method: LinkConfig.SSMethod, password: [UInt8],
       host: String, port: UInt16) {
    self.underlying = underlying
    self.method = method
    self.keyLen = method.keyLength
    self.masterKey = V2Crypto.evpBytesToKey(password: password, length: method.keyLength)
    self.address = SocksAddr.encode(host: host, port: port)
    self.readPhase = .salt(remaining: method.keyLength)
  }

  func write(_ data: Data, completion: @escaping (Error?) -> Void) {
    if !requestSent {
      requestSent = true
      var salt = [UInt8](repeating: 0, count: keyLen)
      _ = SecRandomCopyBytes(kSecRandomDefault, keyLen, &salt)
      let subkey = V2Crypto.hkdfSHA1(
        ikm: masterKey, salt: salt, info: Array("ss-subkey".utf8), length: keyLen
      )
      writeCipher = SSCipher.make(method: method, key: subkey)
      writeNonce = AEADNonce()

      var plain = address
      plain.append(contentsOf: data)
      guard let cipher = writeCipher,
            let chunk = ssChunk(plain, cipher: cipher, nonce: &writeNonce)
      else {
        completion(StreamEOFError())
        teardown()
        return
      }
      var first = Data(salt)
      first.append(contentsOf: chunk)
      underlying.write(first) { error in
        if error != nil { self.teardown() }
        completion(error)
      }
      return
    }

    guard let cipher = writeCipher else {
      completion(StreamEOFError())
      return
    }
    var out = [UInt8]()
    let bytes = [UInt8](data)
    if bytes.isEmpty {
      guard let chunk = ssChunk([], cipher: cipher, nonce: &writeNonce) else {
        completion(StreamEOFError())
        teardown()
        return
      }
      out.append(contentsOf: chunk)
    } else {
      var offset = 0
      while offset < bytes.count {
        let take = min(0x3FFF, bytes.count - offset)
        var slice = Array(bytes[offset..<(offset + take)])
        guard let chunk = ssChunk(slice, cipher: cipher, nonce: &writeNonce) else {
          completion(StreamEOFError())
          teardown()
          return
        }
        out.append(contentsOf: chunk)
        slice.removeAll()
        offset += take
      }
    }
    underlying.write(Data(out)) { error in
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
      guard let self, !self.closed, let handler = self.pendingRead else { return }
      if let error {
        self.failRead(handler, error)
        return
      }
      guard let data, !data.isEmpty else {
        self.failRead(handler, StreamEOFError())
        return
      }
      self.readBuffer.append(contentsOf: data)
      self.drain()
    }
  }

  private func failRead(_ handler: (Data?, Error?) -> Void, _ error: Error) {
    pendingRead = nil
    teardown()
    handler(nil, error)
  }

  private func drain() {
    while !closed, let handler = pendingRead {
      switch readPhase {
      case .salt(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let salt = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        let subkey = V2Crypto.hkdfSHA1(
          ikm: masterKey, salt: salt, info: Array("ss-subkey".utf8), length: keyLen
        )
        readCipher = SSCipher.make(method: method, key: subkey)
        readNonce = AEADNonce()
        readPhase = .lengthPrefix(remaining: 2 + 16)

      case .lengthPrefix(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        guard let cipher = readCipher,
              let plain = cipher.open(block, nonce: readNonce.next()),
              plain.count == 2
        else { failRead(handler, StreamEOFError()); return }
        pendingLength = Int(plain[0]) << 8 | Int(plain[1])
        readPhase = .body(remaining: pendingLength + 16)

      case .body(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        guard let cipher = readCipher,
              let plain = cipher.open(block, nonce: readNonce.next())
        else { failRead(handler, StreamEOFError()); return }
        readPhase = .lengthPrefix(remaining: 2 + 16)
        pendingRead = nil
        handler(Data(plain), nil)
      }
    }
  }

  func close() {
    guard !closed else { return }
    if let handler = pendingRead {
      pendingRead = nil
      handler(nil, StreamEOFError())
    }
    teardown()
  }

  private func teardown() {
    closed = true
    underlying.close()
  }
}

// MARK: - Shadowsocks-2022

final class SS2022Stream: ByteStream {
  private let underlying: ByteStream
  private let method: LinkConfig.SSMethod
  private let psk: [UInt8]
  private let keyLen: Int
  private let address: [UInt8]

  private var writeCipher: SSCipher?
  private var writeNonce = AEADNonce()
  private var readCipher: SSCipher?
  private var readNonce = AEADNonce()

  private var requestSent = false
  private var closed = false

  private enum ReadPhase {
    case salt(remaining: Int)
    case fixedHeader(remaining: Int)   // (1+8+keyLen+2) + 16
    case varHeader(remaining: Int)     // varLen + 16
    case lengthPrefix(remaining: Int)
    case body(remaining: Int)
  }
  private var readPhase: ReadPhase
  private var readBuffer = [UInt8]()
  private var pendingLength = 0
  private var pendingRead: ((Data?, Error?) -> Void)?

  init(underlying: ByteStream, method: LinkConfig.SSMethod, psk: [UInt8],
       host: String, port: UInt16) {
    self.underlying = underlying
    self.method = method
    self.psk = psk
    self.keyLen = method.keyLength
    self.address = SocksAddr.encode(host: host, port: port)
    self.readPhase = .salt(remaining: method.keyLength)
  }

  static func sessionSubkey(psk: [UInt8], salt: [UInt8]) -> [UInt8] {
    var material = psk
    material.append(contentsOf: salt)
    return BLAKE3.deriveKey(
      context: "shadowsocks 2022 session subkey", material: material
    )
  }

  func write(_ data: Data, completion: @escaping (Error?) -> Void) {
    if !requestSent {
      requestSent = true
      var salt = [UInt8](repeating: 0, count: keyLen)
      _ = SecRandomCopyBytes(kSecRandomDefault, keyLen, &salt)
      let subkey = Self.sessionSubkey(psk: psk, salt: salt)
      writeCipher = SSCipher.make(method: method, key: subkey)
      writeNonce = AEADNonce()

      // Variable header: socksAddr ‖ padLen ‖ padding ‖ first payload
      let payload = [UInt8](data)
      let padLen: Int = payload.count < 900 ? Int.random(in: 1...900) : 0
      var padding = [UInt8](repeating: 0, count: padLen)
      if padLen > 0 { _ = SecRandomCopyBytes(kSecRandomDefault, padLen, &padding) }

      var varHeader: [UInt8] = address
      varHeader.append(UInt8(padLen >> 8))
      varHeader.append(UInt8(padLen & 0xFF))
      varHeader.append(contentsOf: padding)
      varHeader.append(contentsOf: payload)

      // Fixed header: type(0) ‖ timestamp BE64 ‖ varLen BE16
      let ts = UInt64(Date().timeIntervalSince1970)
      var fixed: [UInt8] = [0x00]
      for shift in stride(from: 56, through: 0, by: -8) {
        fixed.append(UInt8(truncatingIfNeeded: ts >> UInt64(shift)))
      }
      fixed.append(UInt8(varHeader.count >> 8))
      fixed.append(UInt8(varHeader.count & 0xFF))

      guard let cipher = writeCipher,
            let sealedFixed = cipher.seal(fixed, nonce: writeNonce.next()),
            let sealedVar = cipher.seal(varHeader, nonce: writeNonce.next())
      else {
        completion(StreamEOFError())
        teardown()
        return
      }

      var out = Data(salt)
      out.append(contentsOf: sealedFixed)
      out.append(contentsOf: sealedVar)
      underlying.write(out) { error in
        if error != nil { self.teardown() }
        completion(error)
      }
      return
    }

    guard let cipher = writeCipher else {
      completion(StreamEOFError())
      return
    }
    var out = [UInt8]()
    let bytes = [UInt8](data)
    if bytes.isEmpty {
      guard let chunk = ssChunk([], cipher: cipher, nonce: &writeNonce) else {
        completion(StreamEOFError())
        teardown()
        return
      }
      out.append(contentsOf: chunk)
    } else {
      var offset = 0
      while offset < bytes.count {
        let take = min(0x3FFF, bytes.count - offset)
        var slice = Array(bytes[offset..<(offset + take)])
        guard let chunk = ssChunk(slice, cipher: cipher, nonce: &writeNonce) else {
          completion(StreamEOFError())
          teardown()
          return
        }
        out.append(contentsOf: chunk)
        slice.removeAll()
        offset += take
      }
    }
    underlying.write(Data(out)) { error in
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
      guard let self, !self.closed, self.pendingRead != nil else { return }
      if let error {
        self.failRead(error)
        return
      }
      guard let data, !data.isEmpty else {
        self.failRead(StreamEOFError())
        return
      }
      self.readBuffer.append(contentsOf: data)
      self.drain()
    }
  }

  private func drain() {
    while !closed, let handler = pendingRead {
      switch readPhase {
      case .salt(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let salt = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        let subkey = Self.sessionSubkey(psk: psk, salt: salt)
        readCipher = SSCipher.make(method: method, key: subkey)
        readNonce = AEADNonce()
        readPhase = .fixedHeader(remaining: 1 + 8 + keyLen + 2 + 16)

      case .fixedHeader(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        guard let cipher = readCipher,
              let plain = cipher.open(block, nonce: readNonce.next()),
              plain.first == 0x01,
              plain.count == 1 + 8 + keyLen + 2
        else { failRead2(handler); return }
        let varLen = Int(plain[plain.count - 2]) << 8 | Int(plain[plain.count - 1])
        guard varLen <= 4 * 1024 else { failRead2(handler); return }
        readPhase = .varHeader(remaining: varLen + 16)

      case .varHeader(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        guard let cipher = readCipher,
              cipher.open(block, nonce: readNonce.next()) != nil
        else { failRead2(handler); return }
        readPhase = .lengthPrefix(remaining: 2 + 16)

      case .lengthPrefix(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        guard let cipher = readCipher,
              let plain = cipher.open(block, nonce: readNonce.next()),
              plain.count == 2
        else { failRead2(handler); return }
        pendingLength = Int(plain[0]) << 8 | Int(plain[1])
        readPhase = .body(remaining: pendingLength + 16)

      case .body(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        guard let cipher = readCipher,
              let plain = cipher.open(block, nonce: readNonce.next())
        else { failRead2(handler); return }
        readPhase = .lengthPrefix(remaining: 2 + 16)
        pendingRead = nil
        handler(Data(plain), nil)
      }
    }
  }

  private func failRead(_ error: Error) {
    guard let handler = pendingRead else { return }
    pendingRead = nil
    teardown()
    handler(nil, error)
  }

  private func failRead2(_ handler: (Data?, Error?) -> Void) {
    pendingRead = nil
    teardown()
    handler(nil, StreamEOFError())
  }

  func close() {
    guard !closed else { return }
    if let handler = pendingRead {
      pendingRead = nil
      handler(nil, StreamEOFError())
    }
    teardown()
  }

  private func teardown() {
    closed = true
    underlying.close()
  }
}
