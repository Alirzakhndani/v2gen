import Foundation
import Security

// ════════════════════════════════════════════════════════════════════════════
// WebSocket client (RFC 6455) over a ByteStream — the ws/wss transport of
// vless/vmess/trojan links.
//
// Handshake details that matter for xray servers:
//   · the request path is sent EXACTLY as the link carries it (the server
//     matches only the path component, so `?ed=2048` is harmless);
//   · early data (the `ed=2048` convention) rides the
//     Sec-WebSocket-Protocol header, base64 RawURL — exactly what xray's
//     dialer does (transport/internet/websocket/dialer.go).
// After the 101 the stream is a plain masked-frame pipe.
// ════════════════════════════════════════════════════════════════════════════

final class WSStream: ByteStream {
  private let underlying: ByteStream
  private let reader: StreamReader
  private let queue: DispatchQueue

  // Decoded payload buffered before the consumer asked for it.
  private var buffered = Data()
  private var closed = false
  private var failed: Error?

  private var pendingRead: ((Data?, Error?) -> Void)?
  // ALL raw-frame writes funnel through one queue — payload frames and
  // control frames (pong) alike — so they can never interleave on the wire.
  private var pendingFrames: [(Data, (Error?) -> Void)] = []
  private var writing = false

  private init(underlying: ByteStream, reader: StreamReader,
               queue: DispatchQueue, initialPayload: Data) {
    self.underlying = underlying
    self.reader = reader
    self.queue = queue
    self.buffered = initialPayload
  }

  enum WSError: Error, CustomStringConvertible {
    case timeout
    case closed
    case badStatus(String)
    case protocolViolation

    var description: String {
      switch self {
      case .timeout: return "ws handshake timeout"
      case .closed: return "ws handshake closed"
      case .badStatus(let s): return "ws handshake rejected: \(s)"
      case .protocolViolation: return "ws protocol violation"
      }
    }
  }

  // MARK: - Upgrade

  static func upgrade(
    over underlying: ByteStream,
    queue: DispatchQueue,
    path: String,
    host: String,
    earlyDataBase64: String?,
    timeout: TimeInterval,
    completion: @escaping (Result<WSStream, Error>) -> Void
  ) {
    var keyBytes = [UInt8](repeating: 0, count: 16)
    _ = SecRandomCopyBytes(kSecRandomDefault, 16, &keyBytes)
    let key = Data(keyBytes).base64EncodedString()

    var request = "GET \(path.isEmpty ? "/" : path) HTTP/1.1\r\n"
    request += "Host: \(host)\r\n"
    request += "Upgrade: websocket\r\n"
    request += "Connection: Upgrade\r\n"
    request += "Sec-WebSocket-Key: \(key)\r\n"
    request += "Sec-WebSocket-Version: 13\r\n"
    if let early = earlyDataBase64, !early.isEmpty {
      request += "Sec-WebSocket-Protocol: \(early)\r\n"
    }
    request += "\r\n"

    // ONE reader for the whole lifetime of this stream — adopted by the
    // WSStream on success so buffered bytes are never lost or double-read.
    let reader = StreamReader(stream: underlying)
    reader.start()

    let timer = DispatchSource.makeTimerSource(queue: queue)
    var settled = false
    timer.schedule(deadline: .now() + timeout)
    timer.setEventHandler {
      guard !settled else { return }
      settled = true
      timer.cancel()
      underlying.close()
      completion(.failure(WSError.timeout))
    }
    timer.resume()

    func finish(_ result: Result<WSStream, Error>) {
      guard !settled else { return }
      settled = true
      timer.cancel()
      switch result {
      case .success(let stream):
        completion(.success(stream))
      case .failure(let error):
        underlying.close()
        completion(.failure(error))
      }
    }

    func readResponse(_ accumulated: Data) {
      if let range = accumulated.range(of: Data("\r\n\r\n".utf8)) {
        let header = String(
          data: accumulated[accumulated.startIndex..<range.lowerBound], as: UTF8.self
        ) ?? ""
        let trailing = Data(accumulated[range.upperBound...])
        let statusLine = header.split(separator: "\r\n").first.map(String.init) ?? ""
        guard statusLine.contains(" 101 ") else {
          finish(.failure(WSError.badStatus(statusLine)))
          return
        }
        finish(.success(
          WSStream(underlying: underlying, reader: reader, queue: queue,
                   initialPayload: trailing)
        ))
        return
      }
      guard accumulated.count < 16 * 1024 else {
        finish(.failure(WSError.badStatus("header too large")))
        return
      }
      reader.readExact(64) { chunk, error in
        queue.async {
          guard !settled else { return }
          if let chunk, !chunk.isEmpty {
            readResponse(accumulated + chunk)
          } else {
            finish(.failure(error ?? WSError.closed))
          }
        }
      }
    }

    underlying.write(Data(request.utf8)) { error in
      queue.async {
        if let error {
          finish(.failure(error))
        } else {
          readResponse(Data())
        }
      }
    }
  }

  // MARK: - ByteStream

  func write(_ data: Data, completion: @escaping (Error?) -> Void) {
    queue.async { [weak self] in
      guard let self, !self.closed else {
        completion(StreamEOFError())
        return
      }
      // One binary frame (≤ 16 KiB chunks) per queue entry — write ordering
      // is preserved by the queue itself.
      if data.isEmpty {
        self.pendingFrames.append((Self.frame(.binary, fin: true, payload: Data()), completion))
      } else {
        var start = data.startIndex
        let end = data.endIndex
        var first = true
        while start < end {
          let chunkEnd = data.index(start, offsetBy: 16 * 1024, limitedBy: end) ?? end
          let chunk = data.subdata(in: start..<chunkEnd)
          let isLast = chunkEnd == end
          let op: WSOpcode = first ? .binary : .continuation
          first = false
          let frame = Self.frame(op, fin: isLast, payload: chunk)
          let done: (Error?) -> Void = isLast ? completion : { _ in }
          self.pendingFrames.append((frame, done))
          start = chunkEnd
        }
      }
      self.drainFrames()
    }
  }

  private func drainFrames() {
    guard !writing, !closed, !pendingFrames.isEmpty else { return }
    writing = true
    let (frame, completion) = pendingFrames.removeFirst()
    underlying.write(frame) { [weak self] error in
      guard let self else { return }
      self.queue.async {
        self.writing = false
        if let error {
          self.closed = true
          self.underlying.close()
          let pending = self.pendingFrames
          self.pendingFrames = []
          completion(error)
          for (_, c) in pending { c(error) }
          return
        }
        completion(nil)
        self.drainFrames()
      }
    }
  }

  func read(completion: @escaping (Data?, Error?) -> Void) {
    queue.async { [weak self] in
      guard let self, !self.closed else {
        completion(nil, self.failed ?? StreamEOFError())
        return
      }
      guard self.pendingRead == nil else {
        self.fail(WSError.protocolViolation)
        completion(nil, self.failed)
        return
      }
      if !self.buffered.isEmpty {
        let out = self.buffered
        self.buffered = Data()
        completion(out, nil)
        return
      }
      self.pendingRead = completion
      self.pullNextMessage()
    }
  }

  /// Pull the next complete message and route it to the pending consumer.
  /// Ping is answered transparently and pulling continues — the consumer
  /// only ever sees data payloads, close, or errors.
  private func pullNextMessage() {
    readMessage { [weak self] result in
      guard let self else { return }
      self.handleMessage(result)
    }
  }

  private func handleMessage(_ result: MessageResult) {
    guard !closed, let handler = pendingRead else { return }
    switch result {
    case .payload(let data):
      pendingRead = nil
      handler(data, nil)
    case .ping(let payload):
      pendingFrames.append((Self.frame(.pong, fin: true, payload: payload), { _ in }))
      drainFrames()
      pullNextMessage()
    case .close:
      fail(StreamEOFError())
      pendingRead = nil
      handler(nil, self.failed)
    case .error(let error):
      fail(error)
      pendingRead = nil
      handler(nil, error)
    }
  }

  private func fail(_ error: Error) {
    if failed == nil { failed = error }
    closed = true
    underlying.close()
  }

  func close() {
    queue.async { [weak self] in
      guard let self, !self.closed else { return }
      self.closed = true
      self.underlying.close()
      if let handler = self.pendingRead {
        self.pendingRead = nil
        handler(nil, StreamEOFError())
      }
      let pending = self.pendingFrames
      self.pendingFrames = []
      for (_, c) in pending { c(StreamEOFError()) }
    }
  }

  // MARK: - Frame reading

  private enum MessageResult {
    case payload(Data)
    case ping(Data)
    case close
    case error(Error)
  }

  /// Read one complete message (defragmenting continuations), then invoke
  /// the completion. Control frames are surfaced as their own results and
  /// the caller decides whether to keep reading.
  private func readMessage(completionHandler: @escaping (MessageResult) -> Void) {
    readFrame { [weak self] frame in
      guard let self else { return }
      switch frame {
      case .payload(let data):
        completionHandler(.payload(data))
      case .ping(let payload):
        completionHandler(.ping(payload))
      case .close:
        completionHandler(.close)
      case .error(let error):
        completionHandler(.error(error))
      case .continuation(let partial):
        self.readContinuation(into: partial, completion: completion)
      }
    }
  }

  private func readContinuation(into accumulated: Data,
                                completion: @escaping (MessageResult) -> Void) {
    readFrame { [weak self] frame in
      guard let self else { return }
      switch frame {
      case .continuation(let more):
        self.readContinuation(into: accumulated + more, completion: completion)
      case .payload(let data):
        completion(.payload(accumulated + data))
      case .ping(let payload):
        // Control frame mid-message — deliver it, caller resumes.
        completion(.ping(payload))
      case .close:
        completion(.close)
      case .error(let error):
        completion(.error(error))
      }
    }
  }

  private enum FrameResult {
    case payload(Data)        // a FIN data frame
    case continuation(Data)   // a non-FIN data frame (opcode text/binary/cont)
    case ping(Data)
    case close
    case error(Error)
  }

  private func readFrame(_ completion: @escaping (FrameResult) -> Void) {
    reader.readExact(2) { [weak self] head, error in
      guard let self else { return }
      self.queue.async {
        guard !self.closed else { return }
        guard let head, head.count == 2 else {
          completion(.error(error ?? StreamEOFError()))
          return
        }
        let b = [UInt8](head)
        let fin = (b[0] & 0x80) != 0
        let opcode = b[0] & 0x0F
        let masked = (b[1] & 0x80) != 0
        let len7 = Int(b[1] & 0x7F)

        guard !masked else {
          completion(.error(WSError.protocolViolation))
          return
        }

        func withLength(_ length: Int) {
          guard length <= 4 * 1024 * 1024 else {
            completion(.error(WSError.protocolViolation))
            return
          }
          guard length > 0 else { return self.finishFrame(fin, opcode, Data(), completion) }
          self.reader.readExact(length) { payload, readError in
            self.queue.async {
              guard !self.closed else { return }
              guard let payload, payload.count == length else {
                completion(.error(readError ?? StreamEOFError()))
                return
              }
              self.finishFrame(fin, opcode, payload, completion)
            }
          }
        }

        switch len7 {
        case 126:
          self.reader.readExact(2) { ext, extError in
            self.queue.async {
              guard !self.closed else { return }
              guard let ext, ext.count == 2 else {
                completion(.error(extError ?? StreamEOFError()))
                return
              }
              withLength(Int(ext[ext.startIndex]) << 8 | Int(ext[ext.index(after: ext.startIndex)]))
            }
          }
        case 127:
          self.reader.readExact(8) { ext, extError in
            self.queue.async {
              guard !self.closed else { return }
              guard let ext, ext.count == 8 else {
                completion(.error(extError ?? StreamEOFError()))
                return
              }
              var value = 0
              for byte in ext { value = value << 8 | Int(byte) }
              withLength(value)
            }
          }
        default:
          withLength(len7)
        }
      }
    }
  }

  private func finishFrame(_ fin: Bool, _ opcode: UInt8, _ payload: Data,
                           _ completion: @escaping (FrameResult) -> Void) {
    switch opcode {
    case 0x1, 0x2:
      completion(fin ? .payload(payload) : .continuation(payload))
    case 0x0:
      if fin {
        // A FIN continuation reaching here means the message started in a
        // previous frame — readFrame is only called for the first frame or
        // from readContinuation (which never lands in finishFrame's 0x0 FIN
        // branch because readContinuation maps via .payload). Treat a bare
        // FIN continuation as a complete message.
        completion(.payload(payload))
      } else {
        completion(.continuation(payload))
      }
    case 0x8:
      completion(.close)
    case 0x9:
      completion(.ping(payload))
    case 0xA:
      // Unsolicited pong — transparently keep reading.
      self.readFrame(completion)
    default:
      completion(.error(WSError.protocolViolation))
    }
  }

  // MARK: - Frame building (client → server: always masked)

  private enum WSOpcode: UInt8 {
    case continuation = 0x0
    case binary = 0x2
    case pong = 0xA
  }

  private static func frame(_ opcode: WSOpcode, fin: Bool, payload: Data) -> Data {
    var out = Data()
    out.append(fin ? (0x80 | opcode.rawValue) : opcode.rawValue)
    let len = payload.count
    var maskKey = [UInt8](repeating: 0, count: 4)
    _ = SecRandomCopyBytes(kSecRandomDefault, 4, &maskKey)

    if len < 126 {
      out.append(UInt8(0x80 | len))
    } else if len <= 0xFFFF {
      out.append(UInt8(0x80 | 126))
      out.append(UInt8((len >> 8) & 0xFF))
      out.append(UInt8(len & 0xFF))
    } else {
      out.append(UInt8(0x80 | 127))
      for shift in stride(from: 56, through: 0, by: -8) {
        out.append(UInt8((len >> shift) & 0xFF))
      }
    }
    out.append(contentsOf: maskKey)

    let payloadBytes = [UInt8](payload)
    out.reserveCapacity(out.count + len)
    for i in 0..<len {
      out.append(payloadBytes[i] ^ maskKey[i % 4])
    }
    return out
  }
}
