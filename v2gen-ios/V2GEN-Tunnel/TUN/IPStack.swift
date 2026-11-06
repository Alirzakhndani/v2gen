import Foundation

// ════════════════════════════════════════════════════════════════════════════
// IPStack — IPv4/TCP/UDP header parse + build + checksum, the packet layer
// under the userspace TCP state machine.
//
// Only what the tunnel needs: IPv4 (no fragmentation — dropped), TCP
// (MSS/WScale options at SYN), UDP (DNS to the fake resolver only).
// ════════════════════════════════════════════════════════════════════════════

enum IPProtocolNumber: UInt8 {
  case icmp = 1
  case tcp = 6
  case udp = 17
}

struct IPv4Packet {
  var src: [UInt8]        // 4
  var dst: [UInt8]        // 4
  var protocol: UInt8
  var payload: [UInt8]    // transport segment

  /// Parse a raw IPv4 packet. Returns nil for anything the stack will not
  /// handle: non-IPv4, bad IHL, fragmented packets, truncated payloads.
  static func parse(_ raw: [UInt8]) -> IPv4Packet? {
    guard raw.count >= 20 else { return nil }
    let version = raw[0] >> 4
    guard version == 4 else { return nil }
    let ihl = Int(raw[0] & 0x0F)
    guard ihl >= 5, raw.count >= ihl * 4 else { return nil }
    let totalLen = Int(raw[2]) << 8 | Int(raw[3])
    guard totalLen >= ihl * 4, totalLen <= raw.count else { return nil }
    // Fragments (offset ≠ 0 or more-fragments) are dropped — the stack only
    // ever sees segments the OS sized to its MSS.
    let flagsFrag = UInt16(raw[6]) << 8 | UInt16(raw[7])
    guard flagsFrag & 0x3FFF == 0 else { return nil }

    let src = Array(raw[12..<16])
    let dst = Array(raw[16..<20])
    let proto = raw[9]
    let payload = Array(raw[(ihl * 4)..<totalLen])
    return IPv4Packet(src: src, dst: dst, protocol: proto, payload: payload)
  }

  /// Build an IPv4 packet (header checksum computed).
  static func build(src: [UInt8], dst: [UInt8], protocol: UInt8, payload: [UInt8]) -> [UInt8] {
    var out = [UInt8]()
    let totalLen = 20 + payload.count
    out.append(0x45)                       // IPv4, IHL 5
    out.append(0x00)                       // DSCP/ECN
    out.append(UInt8(totalLen >> 8))
    out.append(UInt8(totalLen & 0xFF))
    out.append(0x00)                       // identification
    out.append(0x00)
    out.append(0x40)                       // don't fragment
    out.append(0x00)
    out.append(64)                         // TTL
    out.append(protocol)
    out.append(0x00)                       // checksum (below)
    out.append(0x00)
    out.append(contentsOf: src)
    out.append(contentsOf: dst)
    let sum = Self.checksum(out)
    out[10] = UInt8(sum >> 8)
    out[11] = UInt8(sum & 0xFF)
    out.append(contentsOf: payload)
    return out
  }

  /// One's-complement Internet checksum over 16-bit words (RFC 1071).
  static func checksum(_ bytes: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var i = 0
    while i + 1 < bytes.count {
      sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
      i += 2
    }
    if i < bytes.count {
      sum += UInt32(bytes[i]) << 8
    }
    while sum >> 16 != 0 {
      sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return UInt16(~sum & 0xFFFF)
  }
}

struct TCPPacket {
  var srcPort: UInt16
  var dstPort: UInt16
  var seq: UInt32
  var ack: UInt32
  var flags: UInt8          // FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10
  var window: UInt16
  var payload: [UInt8]
  var mss: UInt16?          // parsed from SYN options
  var windowScale: UInt8?   // parsed from SYN options

  static let flagFIN: UInt8 = 0x01
  static let flagSYN: UInt8 = 0x02
  static let flagRST: UInt8 = 0x04
  static let flagPSH: UInt8 = 0x08
  static let flagACK: UInt8 = 0x10

  static func parse(_ bytes: [UInt8]) -> TCPPacket? {
    guard bytes.count >= 20 else { return nil }
    let srcPort = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
    let dstPort = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
    let seq = UInt32(bytes[4]) << 24 | UInt32(bytes[5]) << 16
      | UInt32(bytes[6]) << 8 | UInt32(bytes[7])
    let ack = UInt32(bytes[8]) << 24 | UInt32(bytes[9]) << 16
      | UInt32(bytes[10]) << 8 | UInt32(bytes[11])
    let dataOffset = Int(bytes[12] >> 4)
    guard dataOffset >= 5, bytes.count >= dataOffset * 4 else { return nil }
    let flags = bytes[13]
    let window = UInt16(bytes[14]) << 8 | UInt16(bytes[15])
    let headerLen = dataOffset * 4
    let payload = Array(bytes[headerLen...])

    var mss: UInt16? = nil
    var scale: UInt8? = nil
    if flags & flagSYN != 0, headerLen > 20 {
      var i = 20
      while i + 1 < headerLen {
        let kind = bytes[i]
        if kind == 0 { break }             // end of options
        if kind == 1 { i += 1; continue }  // NOP
        guard i + 1 < headerLen else { break }
        let len = Int(bytes[i + 1])
        guard len >= 2, i + len <= headerLen else { break }
        if kind == 2, len == 4, i + 4 <= headerLen {
          mss = UInt16(bytes[i + 2]) << 8 | UInt16(bytes[i + 3])
        } else if kind == 3, len == 3, i + 3 <= headerLen {
          scale = bytes[i + 2]
        }
        i += len
      }
    }

    return TCPPacket(
      srcPort: srcPort, dstPort: dstPort, seq: seq, ack: ack,
      flags: flags, window: window, payload: payload,
      mss: mss, windowScale: scale
    )
  }

  /// Build a TCP segment with the given pseudo-header endpoints.
  static func build(
    src: [UInt8], dst: [UInt8],
    srcPort: UInt16, dstPort: UInt16,
    seq: UInt32, ack: UInt32,
    flags: UInt8, window: UInt16,
    options: [UInt8] = [],
    payload: [UInt8]
  ) -> [UInt8] {
    let headerLen = 20 + options.count
    var seg = [UInt8]()
    seg.reserveCapacity(headerLen + payload.count)
    seg.append(UInt8(srcPort >> 8))
    seg.append(UInt8(srcPort & 0xFF))
    seg.append(UInt8(dstPort >> 8))
    seg.append(UInt8(dstPort & 0xFF))
    for shift in [24, 16, 8, 0] as [UInt32] {
      seg.append(UInt8((seq >> UInt32(shift)) & 0xFF))
    }
    for shift in [24, 16, 8, 0] as [UInt32] {
      seg.append(UInt8((ack >> UInt32(shift)) & 0xFF))
    }
    seg.append(UInt8((headerLen / 4) << 4))
    seg.append(flags)
    seg.append(UInt8(window >> 8))
    seg.append(UInt8(window & 0xFF))
    seg.append(0x00)   // checksum
    seg.append(0x00)
    seg.append(0x00)   // urgent
    seg.append(0x00)
    seg.append(contentsOf: options)
    seg.append(contentsOf: payload)

    // Checksum over the IPv4 pseudo-header + segment.
    var pseudo = [UInt8]()
    pseudo.append(contentsOf: src)
    pseudo.append(contentsOf: dst)
    pseudo.append(0)
    pseudo.append(IPProtocolNumber.tcp.rawValue)
    pseudo.append(UInt8(seg.count >> 8))
    pseudo.append(UInt8(seg.count & 0xFF))
    pseudo.append(contentsOf: seg)
    let sum = IPv4Packet.checksum(pseudo)
    seg[16] = UInt8(sum >> 8)
    seg[17] = UInt8(sum & 0xFF)
    return seg
  }
}

struct UDPPacket {
  var srcPort: UInt16
  var dstPort: UInt16
  var payload: [UInt8]

  static func parse(_ bytes: [UInt8]) -> UDPPacket? {
    guard bytes.count >= 8 else { return nil }
    let len = Int(bytes[4]) << 8 | Int(bytes[5])
    guard len >= 8, len <= bytes.count else { return nil }
    return UDPPacket(
      srcPort: UInt16(bytes[0]) << 8 | UInt16(bytes[1]),
      dstPort: UInt16(bytes[2]) << 8 | UInt16(bytes[3]),
      payload: Array(bytes[8..<len])
    )
  }

  static func build(src: [UInt8], dst: [UInt8],
                    srcPort: UInt16, dstPort: UInt16, payload: [UInt8]) -> [UInt8] {
    var seg = [UInt8]()
    let len = 8 + payload.count
    seg.append(UInt8(srcPort >> 8))
    seg.append(UInt8(srcPort & 0xFF))
    seg.append(UInt8(dstPort >> 8))
    seg.append(UInt8(dstPort & 0xFF))
    seg.append(UInt8(len >> 8))
    seg.append(UInt8(len & 0xFF))
    seg.append(0x00)
    seg.append(0x00)
    seg.append(contentsOf: payload)

    var pseudo = [UInt8]()
    pseudo.append(contentsOf: src)
    pseudo.append(contentsOf: dst)
    pseudo.append(0)
    pseudo.append(IPProtocolNumber.udp.rawValue)
    pseudo.append(UInt8(len >> 8))
    pseudo.append(UInt8(len & 0xFF))
    pseudo.append(contentsOf: seg)
    let sum = IPv4Packet.checksum(pseudo)
    if sum == 0 {
      seg[6] = 0xFF
      seg[7] = 0xFF
    } else {
      seg[6] = UInt8(sum >> 8)
      seg[7] = UInt8(sum & 0xFF)
    }
    return seg
  }
}
