import Foundation
import Security

// ════════════════════════════════════════════════════════════════════════════
// VMess (AEAD, xray-core compatible) — the full client encoding.
//
// Ported 1:1 from xray-core proxy/vmess (encoding/client.go + aead/*.go):
//
//   authID     = AES-ECB(KDF16(cmdKey, "AES Auth ID Encryption"),
//                        ts BE64 ‖ rand4 ‖ crc32 BE32)
//   cmdKey     = MD5(uuid)
//   request    = authID(16) ‖ GCM(lenKey, lenNonce, BE16(hdrLen), aad=authID)
//                ‖ nonce8 ‖ GCM(keyKey, keyNonce, headerPlain, aad=authID)
//   headerPlain= [ver=1][reqIV 16][reqKey 16][respHdr 1][opt=0x01]
//                [(pad<<4)|security][0x00][cmd=0x01][atyp][addr][port BE16]
//                [padding][fnv1a32 BE32]
//   body chunk = [len BE16 plain][AEAD(bodyKey, nonce) ‖ tag]
//                nonce = reqIV[0…12] with a BE16 counter at [0…2],
//                one increment per chunk
//   response   = GCM-chunk(lenKey/lenIV from responseBodyKey/IV) …
//                … then body chunks with respBodyIV-derived nonces
//
// The KDF is the nested-HMAC construction from aead/kdf.go, implemented in
// V2Crypto.vmessKDF and verified against xray's official test vector.
// ════════════════════════════════════════════════════════════════════════════

final class VMessStream: ByteStream {
  private let underlying: ByteStream
  private let security: LinkConfig.VMessSecurity

  // Session keys
  private let requestBodyKey: [UInt8]
  private let requestBodyIV: [UInt8]
  private let responseHeaderByte: UInt8
  private let responseBodyKey: [UInt8]     // SHA256(reqKey)[0…16]
  private let responseBodyIV: [UInt8]      // SHA256(reqIV)[0…16]

  private var headerSent = false
  private var responseHeaderConsumed = false
  private var closed = false

  // Body AEAD state
  private var bodySeal: ([UInt8], [UInt8]) -> [UInt8]? = { _, _ in nil }
  private var bodyOpen: ([UInt8], [UInt8]) -> [UInt8]? = { _, _ in nil }
  private var writeCounter: UInt16 = 0
  private var readCounter: UInt16 = 0

  // Read state machine
  private enum ReadPhase {
    case respLenBlock(remaining: Int)    // 18 bytes (2 + tag)
    case respPayBlock(remaining: Int)    // len + 16
    case chunkLen(remaining: Int)        // 2 plain
    case chunkBody(remaining: Int)       // len + 16
  }
  private var readPhase: ReadPhase = .respLenBlock(remaining: 18)
  private var readBuffer = [UInt8]()
  private var pendingLength = 0
  private var pendingRead: ((Data?, Error?) -> Void)?

  init(underlying: ByteStream, uuid: [UInt8], security: LinkConfig.VMessSecurity,
       host: String, port: UInt16) {
    self.underlying = underlying
    self.security = security

    var key = [UInt8](repeating: 0, count: 16)
    var iv = [UInt8](repeating: 0, count: 16)
    var respByte = [UInt8](repeating: 0, count: 1)
    _ = SecRandomCopyBytes(kSecRandomDefault, 16, &key)
    _ = SecRandomCopyBytes(kSecRandomDefault, 16, &iv)
    _ = SecRandomCopyBytes(kSecRandomDefault, 1, &respByte)
    let reqKey = key
    let respKey = Array(V2Crypto.sha256(key).prefix(16))
    let respIV = Array(V2Crypto.sha256(iv).prefix(16))
    self.requestBodyKey = reqKey
    self.requestBodyIV = iv
    self.responseHeaderByte = respByte[0]
    self.responseBodyKey = respKey
    self.responseBodyIV = respIV

    // Body AEAD direction lambdas:
    //   request  body → requestBodyKey
    //   response body → responseBodyKey      (xray DecodeResponseBody)
    // ChaCha20 uses GenerateChacha20Poly1305Key: MD5(k) ‖ MD5(MD5(k)).
    switch security {
    case .aes128gcm:
      self.bodySeal = { V2Crypto.aesGCMSeal(plaintext: $0, key: reqKey, nonce: $1) }
      self.bodyOpen = { V2Crypto.aesGCMOpen(combined: $0, key: respKey, nonce: $1) }
    case .chacha20:
      self.bodySeal = { V2Crypto.chaChaSeal(
        plaintext: $0, key: Self.chachaKey(from: reqKey), nonce: $1
      ) }
      self.bodyOpen = { V2Crypto.chaChaOpen(
        combined: $0, key: Self.chachaKey(from: respKey), nonce: $1
      ) }
    }

    self.header = Self.buildHeader(
      uuid: uuid, security: security, host: host, port: port,
      requestKey: reqKey, requestIV: iv, responseByte: respByte[0]
    )
  }

  private let header: [UInt8]

  // MARK: - Header construction

  private static func chachaKey(from key: [UInt8]) -> [UInt8] {
    let mid = V2Crypto.md5(key)
    return mid + V2Crypto.md5(mid)
  }

  private static func buildHeader(
    uuid: [UInt8], security: LinkConfig.VMessSecurity,
    host: String, port: UInt16,
    requestKey: [UInt8], requestIV: [UInt8], responseByte: UInt8
  ) -> [UInt8] {
    let cmdKey = V2Crypto.md5(uuid)
    let securityValue: UInt8 = security == .aes128gcm ? 3 : 4
    let paddingLen: UInt8 = 0

    var h: [UInt8] = []
    h.append(0x01)                                   // version
    h.append(contentsOf: requestIV)                  // 16
    h.append(contentsOf: requestKey)                 // 16
    h.append(responseByte)                           // 1
    h.append(0x01)                                   // option: chunk stream
    h.append((paddingLen << 4) | securityValue)      // security + padding length
    h.append(0x00)                                   // reserved
    h.append(0x01)                                   // command: TCP
    h.append(contentsOf: SocksAddr.encode(host: host, port: port))
    // fnv1a-32 over everything so far
    let fnv = V2Crypto.fnv1a32(h)
    h.append(UInt8((fnv >> 24) & 0xFF))
    h.append(UInt8((fnv >> 16) & 0xFF))
    h.append(UInt8((fnv >> 8) & 0xFF))
    h.append(UInt8(fnv & 0xFF))

    return sealHeader(cmdKey: cmdKey, header: h)
  }

  private static func sealHeader(cmdKey: [UInt8], header: [UInt8]) -> [UInt8] {
    // authID = AES-ECB(KDF16(cmdKey, "AES Auth ID Encryption"),
    //                  ts ‖ rand4 ‖ crc32)
    var tsRand = [UInt8]()
    let ts = UInt64(Date().timeIntervalSince1970)
    for shift in stride(from: 56, through: 0, by: -8) {
      tsRand.append(UInt8(truncatingIfNeeded: ts >> UInt64(shift)))
    }
    var r4 = [UInt8](repeating: 0, count: 4)
    _ = SecRandomCopyBytes(kSecRandomDefault, 4, &r4)
    tsRand.append(contentsOf: r4)
    let crc = V2Crypto.crc32(tsRand)
    tsRand.append(UInt8((crc >> 24) & 0xFF))
    tsRand.append(UInt8((crc >> 16) & 0xFF))
    tsRand.append(UInt8((crc >> 8) & 0xFF))
    tsRand.append(UInt8(crc & 0xFF))

    let authKey = V2Crypto.vmessKDF16(
      key: cmdKey, paths: [Array("AES Auth ID Encryption".utf8)]
    )
    guard let authID = V2Crypto.aesECBEncryptBlock(tsRand, key: authKey) else {
      return []
    }

    var nonce8 = [UInt8](repeating: 0, count: 8)
    _ = SecRandomCopyBytes(kSecRandomDefault, 8, &nonce8)

    let lenSalt = Array("VMess Header AEAD Key_Length".utf8)
    let lenNonceSalt = Array("VMess Header AEAD Nonce_Length".utf8)
    let keySalt = Array("VMess Header AEAD Key".utf8)
    let keyNonceSalt = Array("VMess Header AEAD Nonce".utf8)

    let lenKey = V2Crypto.vmessKDF16(key: cmdKey, paths: [lenSalt, authID, nonce8])
    let lenNonce = Array(V2Crypto.vmessKDF(
      key: cmdKey, paths: [lenNonceSalt, authID, nonce8]
    ).prefix(12))
    let payKey = V2Crypto.vmessKDF16(key: cmdKey, paths: [keySalt, authID, nonce8])
    let payNonce = Array(V2Crypto.vmessKDF(
      key: cmdKey, paths: [keyNonceSalt, authID, nonce8]
    ).prefix(12))

    let lenPlain = [UInt8(header.count >> 8), UInt8(header.count & 0xFF)]
    guard let sealedLen = V2Crypto.aesGCMSeal(
      plaintext: lenPlain, key: lenKey, nonce: lenNonce, aad: authID
    ), let sealedHeader = V2Crypto.aesGCMSeal(
      plaintext: header, key: payKey, nonce: payNonce, aad: authID
    ) else {
      return []
    }

    var out: [UInt8] = []
    out.append(contentsOf: authID)          // 16
    out.append(contentsOf: sealedLen)       // 2 + 16
    out.append(contentsOf: nonce8)          // 8
    out.append(contentsOf: sealedHeader)    // headerLen + 16
    return out
  }

  // MARK: - Body nonces

  private func nextBodyNonce() -> [UInt8] {
    var nonce = requestBodyIV
    nonce.replaceSubrange(0..<2, with: [
      UInt8(writeCounter >> 8), UInt8(writeCounter & 0xFF)
    ])
    writeCounter &+= 1
    return Array(nonce.prefix(12))
  }

  private func nextRespNonce() -> [UInt8] {
    var nonce = responseBodyIV
    nonce.replaceSubrange(0..<2, with: [
      UInt8(readCounter >> 8), UInt8(readCounter & 0xFF)
    ])
    readCounter &+= 1
    return Array(nonce.prefix(12))
  }

  // MARK: - Write

  func write(_ data: Data, completion: @escaping (Error?) -> Void) {
    var out = [UInt8]()
    if !headerSent {
      headerSent = true
      out.append(contentsOf: header)
    }
    let bytes = [UInt8](data)
    if !bytes.isEmpty {
      var offset = 0
      while offset < bytes.count {
        let take = min(0x3FFF, bytes.count - offset)
        let slice = Array(bytes[offset..<(offset + take)])
        guard let sealed = bodySeal(slice, nextBodyNonce()) else {
          completion(StreamEOFError())
          teardown()
          return
        }
        out.append(UInt8(slice.count >> 8))
        out.append(UInt8(slice.count & 0xFF))
        out.append(contentsOf: sealed)
        offset += take
      }
    }
    guard !out.isEmpty else {
      completion(nil)
      return
    }
    underlying.write(Data(out)) { error in
      if error != nil { self.teardown() }
      completion(error)
    }
  }

  // MARK: - Read

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

  private func drain() {
    while !closed, let handler = pendingRead {
      switch readPhase {
      case .respLenBlock(let remaining):
        // 2-byte encrypted length + tag, keys derived from responseBody*.
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        let lenKey = V2Crypto.vmessKDF16(
          key: responseBodyKey, paths: [Array("AEAD Resp Header Len Key".utf8)]
        )
        let lenIV = Array(V2Crypto.vmessKDF(
          key: responseBodyIV, paths: [Array("AEAD Resp Header Len IV".utf8)]
        ).prefix(12))
        guard let plain = V2Crypto.aesGCMOpen(
          combined: block, key: lenKey, nonce: lenIV
        ), plain.count == 2
        else { failRead(handler, StreamEOFError()); return }
        pendingLength = Int(plain[0]) << 8 | Int(plain[1])
        guard pendingLength <= 1024 else { failRead(handler, StreamEOFError()); return }
        readPhase = .respPayBlock(remaining: pendingLength + 16)

      case .respPayBlock(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        let payKey = V2Crypto.vmessKDF16(
          key: responseBodyKey, paths: [Array("AEAD Resp Header Key".utf8)]
        )
        let payIV = Array(V2Crypto.vmessKDF(
          key: responseBodyIV, paths: [Array("AEAD Resp Header IV".utf8)]
        ).prefix(12))
        guard let plain = V2Crypto.aesGCMOpen(
          combined: block, key: payKey, nonce: payIV
        ), !plain.isEmpty
        else { failRead(handler, StreamEOFError()); return }
        // [responseByte][option][cmdId?][cmdLen][cmd…] — the response header
        // echoes our random byte; a mismatch means the stream is garbage.
        guard plain[0] == responseHeaderByte else {
          failRead(handler, StreamEOFError())
          return
        }
        responseHeaderConsumed = true
        readCounter = 0
        readPhase = .chunkLen(remaining: 2)

      case .chunkLen(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        pendingLength = Int(block[0]) << 8 | Int(block[1])
        guard pendingLength <= 0xFFFF else {
          failRead(handler, StreamEOFError())
          return
        }
        readPhase = .chunkBody(remaining: pendingLength + 16)

      case .chunkBody(let remaining):
        guard readBuffer.count >= remaining else { pump(); return }
        let block = Array(readBuffer.prefix(remaining))
        readBuffer.removeFirst(remaining)
        guard let plain = bodyOpen(block, nextRespNonce()) else {
          failRead(handler, StreamEOFError())
          return
        }
        readPhase = .chunkLen(remaining: 2)
        pendingRead = nil
        handler(Data(plain), nil)
      }
    }
  }

  private func failRead(_ handler: (Data?, Error?) -> Void, _ error: Error) {
    pendingRead = nil
    teardown()
    handler(nil, error)
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
