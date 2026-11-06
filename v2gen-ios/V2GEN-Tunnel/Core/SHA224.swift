import Foundation

// ════════════════════════════════════════════════════════════════════════════
// SHA-224 — pure Swift (FIPS 180-4). Trojan needs hex(SHA224(password)) as
// the user-id line; CryptoKit has no SHA224. SHA-256 itself comes from
// CryptoKit; only the 224 variant lives here.
// ════════════════════════════════════════════════════════════════════════════

enum SHA224 {
  private static let k: [UInt32] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
  ]

  private static let h0: [UInt32] = [
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
  ]

  /// SHA-224 digest (28 bytes) of the input bytes.
  static func digest(_ message: [UInt8]) -> [UInt8] {
    var h = h0
    var message = message
    // Padding: 0x80, zeros, 64-bit BE bit length.
    let bitLength = UInt64(message.count) * 8
    message.append(0x80)
    while message.count % 64 != 56 { message.append(0) }
    for shift in stride(from: 56, through: 0, by: -8) {
      message.append(UInt8(truncatingIfNeeded: bitLength >> UInt64(shift)))
    }

    var w = [UInt32](repeating: 0, count: 64)
    for blockStart in stride(from: 0, to: message.count, by: 64) {
      for i in 0..<16 {
        let o = blockStart + i * 4
        w[i] = UInt32(message[o]) << 24
          | UInt32(message[o + 1]) << 16
          | UInt32(message[o + 2]) << 8
          | UInt32(message[o + 3])
      }
      for i in 16..<64 {
        let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
      }
      var a = h[0], b = h[1], c = h[2], d = h[3]
      var e = h[4], f = h[5], g = h[6], hh = h[7]
      for i in 0..<64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        let ch = (e & f) ^ (~e & g)
        let t1 = hh &+ s1 &+ ch &+ k[i] &+ w[i]
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        let maj = (a & b) ^ (a & c) ^ (b & c)
        let t2 = s0 &+ maj
        hh = g; g = f; f = e
        e = d &+ t1
        d = c; c = b; b = a
        a = t1 &+ t2
      }
      h[0] = h[0] &+ a; h[1] = h[1] &+ b; h[2] = h[2] &+ c; h[3] = h[3] &+ d
      h[4] = h[4] &+ e; h[5] = h[5] &+ f; h[6] = h[6] &+ g; h[7] = h[7] &+ hh
    }

    var out = [UInt8]()
    out.reserveCapacity(28)
    for i in 0..<7 {
      out.append(UInt8(truncatingIfNeeded: h[i] >> 24))
      out.append(UInt8(truncatingIfNeeded: h[i] >> 16))
      out.append(UInt8(truncatingIfNeeded: h[i] >> 8))
      out.append(UInt8(truncatingIfNeeded: h[i]))
    }
    return out
  }

  static func hexDigest(_ string: String) -> String {
    digest(Array(string.utf8)).map { String(format: "%02x", $0) }.joined()
  }

  private static func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 {
    (x >> n) | (x << (32 - n))
  }
}
