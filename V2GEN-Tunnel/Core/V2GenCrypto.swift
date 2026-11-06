import Foundation
import CryptoKit
import CommonCrypto

// ════════════════════════════════════════════════════════════════════════════
// V2GenCrypto — every primitive the proxy codecs need, on top of CryptoKit
// and CommonCrypto. No third-party dependencies; everything here is verified
// against the reference implementations (xray-core / sing-shadowsocks) byte
// for byte — see docs/worklog/vpn-ipa.md for the derivation notes.
// ════════════════════════════════════════════════════════════════════════════

enum V2Crypto {

  // MARK: - Hashes

  static func md5(_ data: [UInt8]) -> [UInt8] {
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    data.withUnsafeBufferPointer { ptr in
      _ = CC_MD5(ptr.baseAddress, CC_LONG(data.count), &digest)
    }
    return digest
  }

  static func sha1(_ data: [UInt8]) -> [UInt8] {
    Insecure.SHA1.hash(data: data).map { $0 }
  }

  static func sha256(_ data: [UInt8]) -> [UInt8] {
    SHA256.hash(data: data).map { $0 }
  }

  static func hmacSHA256(key: [UInt8], message: [UInt8]) -> [UInt8] {
    Array(
      HMAC<SHA256>.authenticationCode(
        for: Data(message), using: SymmetricKey(data: Data(key))
      )
    )
  }

  static func hmacSHA1(key: [UInt8], message: [UInt8]) -> [UInt8] {
    Array(
      HMAC<Insecure.SHA1>.authenticationCode(
        for: Data(message), using: SymmetricKey(data: Data(key))
      )
    )
  }

  /// FNV-1a 32-bit — VMess request-header integrity tag.
  static func fnv1a32(_ data: [UInt8]) -> UInt32 {
    var hash: UInt32 = 0x811C9DC5
    for b in data {
      hash = (hash ^ UInt32(b)) &* 0x01000193
    }
    return hash
  }

  /// CRC-32 (IEEE, zlib polynomial) — VMess auth block checksum.
  static func crc32(_ data: [UInt8]) -> UInt32 {
    var crc: UInt32 = 0xFFFFFFFF
    for b in data {
      crc ^= UInt32(b)
      for _ in 0..<8 {
        crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1
      }
    }
    return ~crc
  }

  // MARK: - Key derivation

  /// EVP_BytesToKey (MD5, no salt, 1 iteration) — classic Shadowsocks keys.
  static func evpBytesToKey(password: [UInt8], length: Int) -> [UInt8] {
    var out: [UInt8] = []
    var last: [UInt8] = []
    while out.count < length {
      var input = last
      input.append(contentsOf: password)
      let d = md5(input)
      out.append(contentsOf: d)
      last = d
    }
    return Array(out.prefix(length))
  }

  /// HKDF-SHA1 (RFC 5869) — classic Shadowsocks AEAD subkey:
  /// subkey = HKDF(key, salt, "ss-subkey", keyLength).
  static func hkdfSHA1(ikm: [UInt8], salt: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
    // Extract
    let prk = hmacSHA1(key: salt, message: ikm)
    // Expand
    var out: [UInt8] = []
    var t: [UInt8] = []
    var counter: UInt8 = 1
    while out.count < length {
      var input = t
      input.append(contentsOf: info)
      input.append(counter)
      t = hmacSHA1(key: prk, message: input)
      out.append(contentsOf: t)
      counter &+= 1
    }
    return Array(out.prefix(length))
  }

  // MARK: - AES (ECB single block — VMess auth id)

  /// Encrypt exactly one 16-byte AES block in ECB mode (the VMess auth id
  /// construction). Returns nil on any size mismatch.
  static func aesECBEncryptBlock(_ block: [UInt8], key: [UInt8]) -> [UInt8]? {
    guard block.count == kCCBlockSizeAES128, key.count == 16 || key.count == 32 else {
      return nil
    }
    var out = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
    var moved = 0
    let status = block.withUnsafeBufferPointer { inPtr in
      key.withUnsafeBufferPointer { keyPtr in
        out.withUnsafeMutableBufferPointer { outPtr in
          CCCrypt(
            CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
            keyPtr.baseAddress, key.count,
            nil,
            inPtr.baseAddress, block.count,
            outPtr.baseAddress, outPtr.count, &moved
          )
        }
      }
    }
    guard status == CCCryptorStatus(kCCSuccess), moved == kCCBlockSizeAES128 else { return nil }
    return out
  }

  // MARK: - AEAD (AES-GCM, ChaCha20-Poly1305)

  /// AES-GCM seal with an explicit 12-byte nonce. Returns ciphertext||tag.
  static func aesGCMSeal(plaintext: [UInt8], key: [UInt8], nonce: [UInt8],
                         aad: [UInt8]? = nil) -> [UInt8]? {
    guard let nonce = try? AES.GCM.Nonce(data: Data(nonce)) else { return nil }
    do {
      let sealed = try AES.GCM.seal(
        Data(plaintext),
        using: SymmetricKey(data: Data(key)),
        nonce: nonce,
        authenticating: Data(aad ?? [])
      )
      var out = sealed.ciphertext.map { $0 }
      out.append(contentsOf: sealed.tag.map { $0 })
      return out
    } catch {
      return nil
    }
  }

  /// AES-GCM open of ciphertext||tag with an explicit 12-byte nonce.
  static func aesGCMOpen(combined: [UInt8], key: [UInt8], nonce: [UInt8],
                         aad: [UInt8]? = nil) -> [UInt8]? {
    guard combined.count >= 16,
          let nonce = try? AES.GCM.Nonce(data: Data(nonce)) else { return nil }
    let ct = combined.prefix(combined.count - 16)
    let tag = combined.suffix(16)
    do {
      let box = try AES.GCM.SealedBox(
        nonce: nonce, ciphertext: Data(ct), tag: Data(tag)
      )
      let opened = try AES.GCM.open(
        box, using: SymmetricKey(data: Data(key)), authenticating: Data(aad ?? [])
      )
      return opened.map { $0 }
    } catch {
      return nil
    }
  }

  /// ChaCha20-Poly1305 seal. Returns ciphertext||tag.
  static func chaChaSeal(plaintext: [UInt8], key: [UInt8], nonce: [UInt8]) -> [UInt8]? {
    guard key.count == 32, nonce.count == 12,
          let nonce = try? ChaChaPoly.Nonce(data: Data(nonce)) else { return nil }
    do {
      let sealed = try ChaChaPoly.seal(
        Data(plaintext), using: SymmetricKey(data: Data(key)), nonce: nonce
      )
      var out = sealed.ciphertext.map { $0 }
      out.append(contentsOf: sealed.tag.map { $0 })
      return out
    } catch {
      return nil
    }
  }

  /// ChaCha20-Poly1305 open of ciphertext||tag.
  static func chaChaOpen(combined: [UInt8], key: [UInt8], nonce: [UInt8]) -> [UInt8]? {
    guard combined.count >= 16, key.count == 32, nonce.count == 12,
          let nonce = try? ChaChaPoly.Nonce(data: Data(nonce)) else { return nil }
    let ct = combined.prefix(combined.count - 16)
    let tag = combined.suffix(16)
    do {
      let box = try ChaChaPoly.SealedBox(
        nonce: nonce, ciphertext: Data(ct), tag: Data(tag)
      )
      let opened = try ChaChaPoly.open(box, using: SymmetricKey(data: Data(key)))
      return opened.map { $0 }
    } catch {
      return nil
    }
  }

  // MARK: - VMess AEAD KDF (verified against xray-core test vectors)

  /// The xray-core `KDF` — a nested-HMAC construction (aead/kdf.go) whose
  /// exact byte stream was derived from the Go implementation and verified
  /// against the official test vector
  ///   53e9d7e1…  (KDF("Demo Key…", "Demo Path…", 2, 3))
  /// plus randomized cross-checks for K=0…4 against a faithful Go-port.
  ///
  /// Closed form implemented here:
  ///   H(m) = HMAC-SHA256("VMess AEAD KDF", m)
  ///   M0   = ipad(v1) || … || ipad(vK) || key
  ///   rec(j, M):
  ///     j == 0 → H(M)
  ///     else   → d = rec(j-1, M);  rec(j-1, ipad(v1..v[j-1]) || opad(vj) || d)
  ///   KDF = rec(K, M0)
  /// (ipad/opad = key XOR-padded to 64 bytes, exactly as Go's hmac schedule.)
  static func vmessKDF(key: [UInt8], paths: [[UInt8]]) -> [UInt8] {
    let kdfSalt = Array("VMess AEAD KDF".utf8)

    func pad64(_ v: [UInt8]) -> [UInt8] {
      var b = [UInt8](repeating: 0, count: 64)
      for i in 0..<min(v.count, 64) { b[i] = v[i] }
      return b
    }
    func xorPad(_ v: [UInt8], _ c: UInt8) -> [UInt8] {
      pad64(v).map { $0 ^ c }
    }

    let ipads = paths.map { xorPad($0, 0x36) }
    let opads = paths.map { xorPad($0, 0x5c) }

    var m0: [UInt8] = []
    for ipad in ipads { m0.append(contentsOf: ipad) }
    m0.append(contentsOf: key)

    func rec(_ j: Int, _ message: [UInt8]) -> [UInt8] {
      if j == 0 { return hmacSHA256(key: kdfSalt, message: message) }
      let d = rec(j - 1, message)
      var m2: [UInt8] = []
      for i in 0..<(j - 1) { m2.append(contentsOf: ipads[i]) }
      m2.append(contentsOf: opads[j - 1])
      m2.append(contentsOf: d)
      return rec(j - 1, m2)
    }

    return rec(paths.count, m0)
  }

  /// KDF16 — first 16 bytes of KDF (AES-128 keys).
  static func vmessKDF16(key: [UInt8], paths: [[UInt8]]) -> [UInt8] {
    Array(vmessKDF(key: key, paths: paths).prefix(16))
  }
}
