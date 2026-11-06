import Foundation

// ════════════════════════════════════════════════════════════════════════════
// FakeDNS — the tunnel's DNS authority.
//
// Every DNS query that arrives on the TUN (the configured server, or any
// hardcoded 8.8.8.8-style resolver an app insists on) is answered from the
// 198.18.0.0/15 benchmark pool. The domain→IP table feeds the TCP stack:
// a flow to a fake IP is translated back to its DOMAIN and sent to the
// proxy server, which resolves it remotely. No local upstream DNS — no
// leaks, no poisoning, and the real answer comes from the exit's network.
//
// AAAA gets a NOERROR/empty answer so stacks fall back to the A record.
// ════════════════════════════════════════════════════════════════════════════

final class FakeDNS {
  private var domainToIP: [String: UInt32] = [:]
  private var ipToDomain: [UInt32: String] = [:]
  private var order: [String] = []          // simple LRU for eviction
  private var nextIP: UInt32 = FakeDNS.poolStart
  private let lock = NSLock()

  /// 198.18.1.0 … 198.19.255.254 (0.0/24 keeps the TUN's own address safe).
  private static let poolStart: UInt32 = 0xC612_0100
  private static let poolEnd: UInt32 = 0xC613_FFFE
  private static let maxEntries = 40_000

  /// The TUN's own address (198.18.0.1) — never handed out.
  static let tunAddress: [UInt8] = [198, 18, 0, 1]

  // MARK: - Mapping

  func domain(for ip: UInt32) -> String? {
    lock.lock()
    defer { lock.unlock() }
    return ipToDomain[ip]
  }

  private func allocate(domain: String) -> UInt32 {
    if let existing = domainToIP[domain] { return existing }
    var ip = nextIP
    nextIP += 1
    if nextIP > FakeDNS.poolEnd {
      nextIP = FakeDNS.poolStart      // wrap (LRU keeps the hot set coherent)
    }
    // On collision with a live entry, just take the next slot.
    while ipToDomain[ip] != nil && ip < FakeDNS.poolEnd {
      ip += 1
    }
    domainToIP[domain] = ip
    ipToDomain[ip] = domain
    order.append(domain)
    if order.count > FakeDNS.maxEntries {
      let evict = order.removeFirst()
      if let ip = domainToIP[evict], ipToDomain[ip] == evict {
        ipToDomain[ip] = nil
        domainToIP[evict] = nil
      }
    }
    return ip
  }

  // MARK: - Query handling

  /// Build the response IP packet for a UDP DNS query. Returns nil for
  /// anything that isn't a well-formed query.
  func response(to ip: IPv4Packet) -> [UInt8]? {
    guard let udp = UDPPacket.parse(ip.payload), udp.dstPort == 53 else {
      return nil
    }
    let query = udp.payload
    guard query.count >= 12 else { return nil }

    let id = [query[0], query[1]]
    let flags = UInt16(query[2]) << 8 | UInt16(query[3])
    let isResponse = (flags & 0x8000) != 0
    guard !isResponse else { return nil }
    let rd = (flags & 0x0100) != 0
    let qdcount = Int(query[4]) << 8 | Int(query[5])
    guard qdcount == 1 else { return nil }   // one question at a time

    // Parse the QNAME.
    var idx = 12
    var labels: [String] = []
    while idx < query.count {
      let len = Int(query[idx])
      if len == 0 {
        idx += 1                            // root terminator
        break
      }
      guard len <= 63, idx + 1 + len <= query.count else { return nil }
      let label = String(
        bytes: query[(idx + 1)...(idx + len)], encoding: .utf8
      ) ?? ""
      labels.append(label.lowercased())
      idx += 1 + len
    }
    guard idx + 4 <= query.count, !labels.isEmpty else { return nil }
    let qtype = Int(query[idx]) << 8 | Int(query[idx + 1])
    let qclass = Int(query[idx + 2]) << 8 | Int(query[idx + 3])
    let domain = labels.joined(separator: ".")
    guard !domain.isEmpty, domain.count <= 253 else { return nil }

    // Header: same id, QR| Opcode(0) | RD | RA, rcode 0.
    var out: [UInt8] = []
    out.append(contentsOf: id)
    var respFlags: UInt16 = 0x8000 | (rd ? 0x0100 : 0) | 0x0080   // QR|RD|RA
    var answerCount: UInt16 = 0
    var answer: [UInt8] = []

    if qclass == 1 && (qtype == 1 || qtype == 28) {
      if qtype == 1 {
        let fakeIP = allocate(domain: domain)
        answerCount = 1
        // Name pointer to the question, TYPE A, CLASS IN, TTL 10, RDLENGTH 4.
        answer = [
          0xC0, 0x0C,             // pointer to qname
          0x00, 0x01,             // A
          0x00, 0x01,             // IN
          0x00, 0x00, 0x00, 0x0A, // TTL 10
          0x00, 0x04,             // RDLENGTH
        ]
        answer.append(contentsOf: TCPStack.ip4Bytes(fakeIP))
      } else {
        // AAAA: NOERROR with zero answers → stacks fall back to A.
        answerCount = 0
        _ = respFlags
      }
    } else {
      // Unknown type — NOERROR, no answers.
      answerCount = 0
    }
    respFlags |= 0
    out.append(UInt8(respFlags >> 8))
    out.append(UInt8(respFlags & 0xFF))
    out.append(0x00); out.append(0x01)   // QDCOUNT (echo the one question)
    out.append(UInt8(answerCount >> 8))
    out.append(UInt8(answerCount & 0xFF))
    out.append(0x00); out.append(0x00)   // NSCOUNT
    out.append(0x00); out.append(0x00)   // ARCOUNT

    // Question section, verbatim (name + qtype + qclass).
    let questionEnd = idx + 4
    out.append(contentsOf: query[12..<questionEnd])
    out.append(contentsOf: answer)

    // UDP + IPv4 wrapper. The response's source = the address the app
    // queried (tun IP or a spoofed hardcoded resolver) so its socket
    // accepts the reply.
    let udpSegment = UDPPacket.build(
      src: ip.dst, dst: ip.src,
      srcPort: udp.dstPort, dstPort: udp.srcPort, payload: out
    )
    return IPv4Packet.build(
      src: ip.dst, dst: ip.src,
      protoNum: IPProtocolNumber.udp.rawValue, payload: udpSegment
    )
  }
}
