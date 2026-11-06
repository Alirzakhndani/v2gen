import Foundation

// ════════════════════════════════════════════════════════════════════════════
// BLAKE3 — pure Swift port of the official reference implementation.
// Verified against the official test vectors (hash / keyed / derive_key) on
// Linux before shipping. Needed by Shadowsocks-2022:
//   subkey = blake3.derive_key("shadowsocks 2022 session subkey", psk || salt)
// (Xray-core's exact construction — confirmed empirically against the
// production servers; see docs/worklog/vpn-ipa.md.)
// ════════════════════════════════════════════════════════════════════════════

enum BLAKE3 {

  // MARK: - Constants

  private static let OUT_LEN = 32
  private static let KEY_LEN = 32
  private static let BLOCK_LEN = 64
  private static let CHUNK_LEN = 1024

  private static let CHUNK_START: UInt32 = 1 << 0
  private static let CHUNK_END: UInt32 = 1 << 1
  private static let PARENT: UInt32 = 1 << 2
  private static let ROOT: UInt32 = 1 << 3
  private static let KEYED_HASH: UInt32 = 1 << 4
  private static let DERIVE_KEY_CONTEXT: UInt32 = 1 << 5
  private static let DERIVE_KEY_MATERIAL: UInt32 = 1 << 6

  private static let IV: [UInt32] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
  ]

  private static let MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

  // MARK: - Low-level compression

  private static func g(
    _ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int,
    _ mx: UInt32, _ my: UInt32
  ) {
    state[a] = state[a] &+ state[b] &+ mx
    state[d] = (state[d] ^ state[a]).rotatedRight(16)
    state[c] = state[c] &+ state[d]
    state[b] = (state[b] ^ state[c]).rotatedRight(12)
    state[a] = state[a] &+ state[b] &+ my
    state[d] = (state[d] ^ state[a]).rotatedRight(8)
    state[c] = state[c] &+ state[d]
    state[b] = (state[b] ^ state[c]).rotatedRight(7)
  }

  private static func round(_ state: inout [UInt32], _ m: [UInt32]) {
    // Mix the columns.
    g(&state, 0, 4, 8, 12, m[0], m[1])
    g(&state, 1, 5, 9, 13, m[2], m[3])
    g(&state, 2, 6, 10, 14, m[4], m[5])
    g(&state, 3, 7, 11, 15, m[6], m[7])
    // Mix the diagonals.
    g(&state, 0, 5, 10, 15, m[8], m[9])
    g(&state, 1, 6, 11, 12, m[10], m[11])
    g(&state, 2, 7, 8, 13, m[12], m[13])
    g(&state, 3, 4, 9, 14, m[14], m[15])
  }

  private static func permute(_ m: inout [UInt32]) {
    var permuted = [UInt32](repeating: 0, count: 16)
    for i in 0..<16 { permuted[i] = m[MSG_PERMUTATION[i]] }
    m = permuted
  }

  private static func compress(
    chainingValue: [UInt32], blockWords: [UInt32],
    counter: UInt64, blockLen: UInt32, flags: UInt32
  ) -> [UInt32] {
    var state = [
      chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3],
      chainingValue[4], chainingValue[5], chainingValue[6], chainingValue[7],
      IV[0], IV[1], IV[2], IV[3],
      UInt32(truncatingIfNeeded: counter),
      UInt32(truncatingIfNeeded: counter >> 32),
      blockLen, flags,
    ]
    var block = blockWords
    for i in 0..<7 {
      round(&state, block)
      if i < 6 { permute(&block) }
    }
    for i in 0..<8 {
      state[i] ^= state[i + 8]
      state[i + 8] ^= chainingValue[i]
    }
    return state
  }

  private static func first8Words(_ words: [UInt32]) -> [UInt32] {
    Array(words[0..<8])
  }

  // MARK: - Output (chaining value + XOF reader)

  private struct Output {
    let inputChainingValue: [UInt32]
    let blockWords: [UInt32]
    let counter: UInt64
    let blockLen: UInt32
    let flags: UInt32

    func chainingValue() -> [UInt32] {
      first8Words(compress(
        chainingValue: inputChainingValue, blockWords: blockWords,
        counter: counter, blockLen: blockLen, flags: flags
      ))
    }

    func rootBytes(into out: inout [UInt8], offset: Int, length: Int) {
      var outputBlockCounter: UInt64 = 0
      var pos = offset
      let end = offset + length
      while pos < end {
        let words = compress(
          chainingValue: inputChainingValue, blockWords: blockWords,
          counter: outputBlockCounter, blockLen: blockLen, flags: flags | ROOT
        )
        for w in words {
          if pos >= end { break }
          let le = w.littleEndianBytes
          for i in 0..<4 {
            if pos + i < end { out[pos + i] = le[i] }
          }
          pos += 4
        }
        outputBlockCounter += 1
      }
    }
  }

  // MARK: - Chunk state

  private struct ChunkState {
    var chainingValue: [UInt32]
    var chunkCounter: UInt64
    var block: [UInt32]
    var blockLen: Int
    var blocksCompressed: Int
    var flags: UInt32

    init(keyWords: [UInt32], chunkCounter: UInt64, flags: UInt32) {
      chainingValue = keyWords
      self.chunkCounter = chunkCounter
      block = [UInt32](repeating: 0, count: 16)
      blockLen = 0
      blocksCompressed = 0
      self.flags = flags
    }

    var length: Int { BLOCK_LEN * blocksCompressed + blockLen }

    var startFlag: UInt32 { blocksCompressed == 0 ? CHUNK_START : 0 }

    mutating func update(_ input: ArraySlice<UInt8>) {
      var input = input
      while !input.isEmpty {
        if blockLen == BLOCK_LEN {
          let blockCV = first8Words(compress(
            chainingValue: chainingValue, blockWords: block,
            counter: chunkCounter, blockLen: UInt32(blockLen),
            flags: flags | startFlag
          ))
          chainingValue = blockCV
          blocksCompressed += 1
          block = [UInt32](repeating: 0, count: 16)
          blockLen = 0
        }
        let want = BLOCK_LEN - blockLen
        let take = min(want, input.count)
        for b in input.prefix(take) {
          block[blockLen / 4] |= UInt32(b) << UInt32(8 * (blockLen % 4))
          blockLen += 1
        }
        input = input.dropFirst(take)
      }
    }

    func output() -> Output {
      Output(
        inputChainingValue: chainingValue, blockWords: block,
        counter: chunkCounter, blockLen: UInt32(blockLen),
        flags: flags | startFlag | CHUNK_END
      )
    }
  }

  // MARK: - Hasher

  public final class Hasher {
    private var chunkState: ChunkState
    private var keyWords: [UInt32]
    private var cvStack: [[UInt32]]
    private var cvStackLen: Int
    private var flags: UInt32

    private init(keyWords: [UInt32], flags: UInt32) {
      self.keyWords = keyWords
      self.flags = flags
      chunkState = ChunkState(keyWords: keyWords, chunkCounter: 0, flags: flags)
      cvStack = [[UInt32]](repeating: [UInt32](repeating: 0, count: 8), count: 54)
      cvStackLen = 0
    }

    /// Standard hash mode.
    public convenience init() {
      self.init(keyWords: IV, flags: 0)
    }

    /// Keyed MAC mode. Key must be 32 bytes.
    public convenience init(key: [UInt8]) {
      precondition(key.count == KEY_LEN, "BLAKE3 key must be 32 bytes")
      self.init(keyWords: BLAKE3.wordsFromLE(key), flags: KEYED_HASH)
    }

    /// Key-derivation mode — the context string is hashed with the
    /// DERIVE_KEY_CONTEXT flag, and the material is then hashed as keyed
    /// input with the DERIVE_KEY_MATERIAL flag
    /// (`blake3::Hasher::new_derive_key(context)`).
    public convenience init(deriveKeyContext context: String) {
      let contextHasher = Hasher()
      contextHasher.update(Array(context.utf8))
      var contextKey = [UInt8](repeating: 0, count: KEY_LEN)
      contextHasher.finalize(into: &contextKey, offset: 0, length: KEY_LEN)
      self.init(keyWords: BLAKE3.wordsFromLE(contextKey), flags: DERIVE_KEY_MATERIAL)
    }

    private func pushStack(_ cv: [UInt32]) {
      cvStack[cvStackLen] = cv
      cvStackLen += 1
    }

    private func popStack() -> [UInt32] {
      cvStackLen -= 1
      return cvStack[cvStackLen]
    }

    private func addChunkChainingValue(_ newCV: [UInt32], totalChunks: UInt64) {
      var cv = newCV
      var total = totalChunks
      while total & 1 == 0 {
        cv = parentOutput(leftCV: popStack(), rightCV: cv).chainingValue()
        total >>= 1
      }
      pushStack(cv)
    }

    private func parentOutput(leftCV: [UInt32], rightCV: [UInt32]) -> Output {
      var blockWords = [UInt32](repeating: 0, count: 16)
      for i in 0..<8 {
        blockWords[i] = leftCV[i]
        blockWords[8 + i] = rightCV[i]
      }
      return Output(
        inputChainingValue: keyWords, blockWords: blockWords,
        counter: 0, blockLen: UInt32(BLOCK_LEN), flags: flags | PARENT
      )
    }

    public func update(_ input: [UInt8]) {
      var data = input[...]
      while !data.isEmpty {
        // If the current chunk is complete, finalize it and reset.
        if chunkState.length == CHUNK_LEN {
          let chunkCV = chunkState.output().chainingValue()
          let totalChunks = chunkState.chunkCounter + 1
          addChunkChainingValue(chunkCV, totalChunks: totalChunks)
          chunkState = ChunkState(
            keyWords: keyWords, chunkCounter: totalChunks, flags: flags
          )
        }
        let want = CHUNK_LEN - chunkState.length
        let take = min(want, data.count)
        chunkState.update(data.prefix(take))
        data = data.dropFirst(take)
      }
    }

    public func finalize(into out: inout [UInt8], offset: Int, length: Int) {
      var output = chunkState.output()
      var parentNodesRemaining = cvStackLen
      while parentNodesRemaining > 0 {
        parentNodesRemaining -= 1
        output = parentOutput(
          leftCV: cvStack[parentNodesRemaining],
          rightCV: output.chainingValue()
        )
      }
      output.rootBytes(into: &out, offset: offset, length: length)
    }

    public func finalize() -> [UInt8] {
      var out = [UInt8](repeating: 0, count: OUT_LEN)
      finalize(into: &out, offset: 0, length: OUT_LEN)
      return out
    }
  }

  // MARK: - Public convenience API

  /// blake3(input) — standard 32-byte hash.
  public static func hash(_ input: [UInt8]) -> [UInt8] {
    let h = Hasher()
    h.update(input)
    return h.finalize()
  }

  /// BLAKE3 derive_key: context is hashed with the derive-context flag, then
  /// the material is keyed-hashed with the derive-material flag.
  public static func deriveKey(
    context: String, material: [UInt8], outputLength: Int = 32
  ) -> [UInt8] {
    let h = Hasher(deriveKeyContext: context)
    h.update(material)
    var out = [UInt8](repeating: 0, count: outputLength)
    h.finalize(into: &out, offset: 0, length: outputLength)
    return out
  }

  // MARK: - Helpers

  fileprivate static func wordsFromLE(_ bytes: [UInt8]) -> [UInt32] {
    var words = [UInt32](repeating: 0, count: bytes.count / 4)
    for i in 0..<words.count {
      let b = i * 4
      words[i] = UInt32(bytes[b])
        | UInt32(bytes[b + 1]) << 8
        | UInt32(bytes[b + 2]) << 16
        | UInt32(bytes[b + 3]) << 24
    }
    return words
  }
}

private extension UInt32 {
  func rotatedRight(_ n: UInt32) -> UInt32 {
    (self >> n) | (self << (32 - n))
  }
  var littleEndianBytes: [UInt8] {
    [
      UInt8(truncatingIfNeeded: self),
      UInt8(truncatingIfNeeded: self >> 8),
      UInt8(truncatingIfNeeded: self >> 16),
      UInt8(truncatingIfNeeded: self >> 24),
    ]
  }
}
