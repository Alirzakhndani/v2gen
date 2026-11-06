import Foundation

// ════════════════════════════════════════════════════════════════════════════
// TCPStack — the userspace TCP implementation over NEPacketFlow.
//
// Per-flow state machine: SYN → SYN/ACK (MSS 1440, wscale 7) → ESTABLISHED
// (dial the proxy, flushing the app's early writes with the handshake) →
// data pumps with:
//   · receive window driven by the to-proxy buffer (zero-window backpressure)
//   · send window driven by the app's advertised window (go-back-N RTO)
//   · FIN/RST in both directions, 5-minute idle sweep, flow cap
//
// Sequence arithmetic uses RFC 793 circular comparison. All state is
// confined to ONE serial queue owned by the stack — no locks inside.
// ════════════════════════════════════════════════════════════════════════════

final class TCPStack {

  // MARK: - Types

  struct FlowKey: Hashable {
    let srcIP: UInt32
    let srcPort: UInt16
    let dstIP: UInt32
    let dstPort: UInt16
  }

  /// Provider hooks.
  var onSendPackets: ([Data]) -> Void = { _ in }
  var onDial: (
    _ key: FlowKey, _ targetIP: UInt32, _ targetPort: UInt16,
    _ onReady: @escaping (ProxyPipe) -> Void,
    _ onError: @escaping (String) -> Void
  ) -> Void = { _, _, _, _, _ in }
  /// Resolve a destination IP to a hostname (fake-IP table); nil = literal.
  var resolveHost: (UInt32) -> String? = { _ in nil }
  /// bytesUp = app→internet, bytesDown = internet→app.
  var onBytes: (Int, Int) -> Void = { _, _ in }
  /// UDP packets (DNS) are handed to the provider's fake resolver.
  var onDNSPacket: ((IPv4Packet) -> Void)?

  fileprivate var flows: [FlowKey: TCPFlow] = [:]
  private let queue: DispatchQueue
  private var sweepTimer: DispatchSourceTimer?

  fileprivate static let maxFlows = 512
  fileprivate static let idleTimeout: TimeInterval = 300
  fileprivate static let toProxyBufferLimit = 192 * 1024
  fileprivate static let ourWindowScale: UInt8 = 7
  fileprivate static let ourMSS: UInt16 = 1440

  init(queue: DispatchQueue) {
    self.queue = queue
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + 30, repeating: 30)
    timer.setEventHandler { [weak self] in self?.sweep() }
    timer.resume()
    self.sweepTimer = timer
  }

  // MARK: - Sequence helpers

  static func seqLT(_ a: UInt32, _ b: UInt32) -> Bool { Int32(a &- b) < 0 }
  static func seqLE(_ a: UInt32, _ b: UInt32) -> Bool { a == b || seqLT(a, b) }
  static func seqGT(_ a: UInt32, _ b: UInt32) -> Bool { seqLT(b, a) }
  static func seqGE(_ a: UInt32, _ b: UInt32) -> Bool { seqLE(b, a) }

  // MARK: - Inbound packets (from the device)

  func handlePacket(_ raw: [UInt8]) {
    guard let ip = IPv4Packet.parse(raw) else { return }
    switch ip.protocol {
    case IPProtocolNumber.tcp.rawValue:
      guard let tcp = TCPPacket.parse(ip.payload) else { return }
      handleTCP(ip: ip, tcp: tcp)
    case IPProtocolNumber.udp.rawValue:
      onDNSPacket?(ip)
    default:
      break
    }
  }

  private func handleTCP(ip: IPv4Packet, tcp: TCPPacket) {
    let key = FlowKey(
      srcIP: TCPStack.ip4(ip.src), srcPort: tcp.srcPort,
      dstIP: TCPStack.ip4(ip.dst), dstPort: tcp.dstPort
    )

    if tcp.flags & TCPPacket.flagRST != 0 {
      if let flow = flows[key] {
        flow.teardownProxy()
        flows[key] = nil
      }
      return
    }

    guard let flow = flows[key] else {
      guard tcp.flags & TCPPacket.flagSYN != 0, tcp.flags & TCPPacket.flagACK == 0,
            flows.count < Self.maxFlows
      else { return }
      let newFlow = TCPFlow(key: key, stack: self, tcp: tcp, ip: ip)
      flows[key] = newFlow
      newFlow.sendSYNACK()
      return
    }

    flow.handleSegment(tcp: tcp)
    if flow.isDead { flows[key] = nil }
  }

  // MARK: - Outbound (proxy → app)

  func proxyDelivered(key: FlowKey, data: Data) {
    queue.async { [weak self] in
      guard let self, let flow = self.flows[key], !flow.isDead else { return }
      flow.proxyDelivered(data)
    }
  }

  func proxyEnded(key: FlowKey) {
    queue.async { [weak self] in
      guard let self, let flow = self.flows[key], !flow.isDead else { return }
      flow.proxyEnded()
    }
  }

  func proxyFailed(key: FlowKey) {
    queue.async { [weak self] in
      guard let self, let flow = self.flows[key], !flow.isDead else { return }
      flow.proxyFailed()
      self.flows[key] = nil
    }
  }

  /// Tunnel going away — RST every flow.
  func resetAll() {
    queue.async { [weak self] in
      guard let self else { return }
      for (_, flow) in self.flows {
        flow.sendRST()
        flow.teardownProxy()
      }
      self.flows.removeAll()
    }
  }

  var flowCount: Int {
    queue.sync { flows.count }
  }

  // MARK: - Sweep

  private func sweep() {
    let now = Date()
    var expired: [FlowKey] = []
    for (key, flow) in flows where now.timeIntervalSince(flow.lastActivity) > Self.idleTimeout {
      expired.append(key)
      flow.sendRST()
      flow.teardownProxy()
    }
    for key in expired { flows[key] = nil }
  }

  // MARK: - Helpers

  static func ip4(_ bytes: [UInt8]) -> UInt32 {
    UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
  }

  static func ip4Bytes(_ v: UInt32) -> [UInt8] {
    [UInt8(v >> 24), UInt8(v >> 16), UInt8(v >> 8), UInt8(v)]
  }

  fileprivate func removeFlow(_ key: FlowKey) {
    flows[key] = nil
  }
}

// MARK: - Per-flow state

final class TCPFlow {
  fileprivate let key: TCPStack.FlowKey
  private unowned let stack: TCPStack

  // Endpoint addresses for packet building (remote = proxy target as seen
  // by the app; we answer as the "server" the app dialed).
  private let appIP: [UInt8]
  private let remoteIP: [UInt8]

  // Sequence state
  private let iss: UInt32
  private var sndUNA: UInt32        // oldest unacked (our side)
  private var sndNXT: UInt32        // next byte to send
  private var rcvNXT: UInt32        // next expected byte from the app
  private var theirWindow: UInt32   // scaled
  private var theirWindowScale: UInt8 = 0
  private var theirWindowScaled = false
  private let mss: Int

  // Buffers
  private var toProxy = [UInt8]()            // from app, toward proxy
  private var proxy: ProxyPipe?
  private var proxyReady = false
  private var proxyDialing = false
  private var toApp = [UInt8]()              // toward app; [0] tracks sndUNA
  private var toAppSentOffset = 0            // bytes already segmented

  // Lifecycle
  private enum Phase {
    case synReceived
    case established
    case finFromApp        // app sent FIN (we may still deliver data to it)
    case finToApp          // we sent FIN
    case dead
  }
  private var phase: Phase = .synReceived
  private var finFromProxy = false
  fileprivate var lastActivity = Date()
  private var rtoTimer: DispatchSourceTimer?
  private var rto: TimeInterval = 0.3

  var isDead: Bool { phase == .dead }

  init(key: TCPStack.FlowKey, stack: TCPStack, tcp: TCPPacket, ip: IPv4Packet) {
    self.key = key
    self.stack = stack
    self.appIP = ip.src
    self.remoteIP = ip.dst
    self.iss = UInt32.random(in: 1..<UInt32.max)
    self.sndUNA = iss
    self.sndNXT = iss &+ 1
    self.rcvNXT = tcp.seq &+ 1
    self.mss = Int(min(tcp.mss ?? TCPFlow.defaultMSS, TCPFlow.defaultMSS))
    if let scale = tcp.windowScale {
      self.theirWindowScale = scale
      self.theirWindowScaled = true
    }
    self.theirWindow = UInt32(tcp.window) << (theirWindowScaled ? UInt32(theirWindowScale) : 0)
  }

  private static let defaultMSS: UInt16 = 1460

  // MARK: - Handshake

  func sendSYNACK() {
    var options: [UInt8] = [
      0x02, 0x04, UInt8(TCPStack.ourMSS >> 8), UInt8(TCPStack.ourMSS & 0xFF),
      0x03, 0x03, TCPStack.ourWindowScale,
    ]
    options.append(contentsOf: [0x01, 0x01])
    sendSegment(seq: iss, flags: TCPPacket.flagSYN | TCPPacket.flagACK,
                window: advertisedWindowRaw(), options: options, payload: [])
  }

  func handleSegment(tcp: TCPPacket) {
    lastActivity = Date()

    if tcp.flags & TCPPacket.flagSYN != 0 {
      if phase == .synReceived {
        sendSYNACK()
      } else {
        // SYN on an established flow — respond with the current ACK.
        sendACK()
      }
      return
    }

    let seqEnd = tcp.seq &+ UInt32(tcp.payload.count)

    switch phase {
    case .synReceived:
      guard tcp.flags & TCPPacket.flagACK != 0,
            TCPStack.seqGE(tcp.ack, sndNXT)
      else { return }
      sndUNA = tcp.ack
      phase = .established
      updateTheirWindow(tcp)
      processAck(tcp)
      if !tcp.payload.isEmpty { acceptData(tcp) }
      if tcp.flags & TCPPacket.flagFIN != 0 { acceptFIN(seqEnd: seqEnd) }
      maybeDialProxy()
      pumpAll()
      if needsACK() { sendACK() }
      return

    case .established, .finFromApp, .finToApp:
      updateTheirWindow(tcp)
      processAck(tcp)
      if !tcp.payload.isEmpty { acceptData(tcp) }
      if tcp.flags & TCPPacket.flagFIN != 0 { acceptFIN(seqEnd: seqEnd) }
      pumpAll()
      if needsACK() { sendACK() }
      checkDone()
      return

    case .dead:
      return
    }
  }

  private func needsACK() -> Bool {
    // ACK when there is unacknowledged receive data. (Pure window updates
    // are also carried by the periodic ACK after proxy writes.)
    true
  }

  private func updateTheirWindow(_ tcp: TCPPacket) {
    guard tcp.flags & TCPPacket.flagACK != 0,
          TCPStack.seqLE(tcp.ack, sndNXT)
    else { return }
    let scale = theirWindowScaled ? UInt32(theirWindowScale) : 0
    theirWindow = UInt32(tcp.window) << scale
  }

  private func processAck(_ tcp: TCPPacket) {
    guard tcp.flags & TCPPacket.flagACK != 0 else { return }
    guard TCPStack.seqGT(tcp.ack, sndUNA), TCPStack.seqLE(tcp.ack, sndNXT) else {
      return
    }
    let acked = Int(tcp.ack &- sndUNA)
    sndUNA = tcp.ack
    if acked > 0, !toApp.isEmpty {
      let remove = min(acked, toAppSentOffset)
      if remove > 0 {
        toApp.removeFirst(remove)
        toAppSentOffset -= remove
      }
    }
    if sndUNA == sndNXT {
      rto = 0.3
      rtoTimer?.cancel()
      rtoTimer = nil
    }
  }

  private func acceptData(_ tcp: TCPPacket) {
    var payload = tcp.payload
    if TCPStack.seqLT(tcp.seq, rcvNXT) {
      let skip = Int(rcvNXT &- tcp.seq)
      guard skip < payload.count else { return }
      payload.removeFirst(skip)
    } else if TCPStack.seqGT(tcp.seq, rcvNXT) {
      return   // hole — wait for retransmission
    }
    guard !payload.isEmpty else { return }
    rcvNXT = rcvNXT &+ UInt32(payload.count)
    toProxy.append(contentsOf: payload)
    stack.onBytes(payload.count, 0)
    if phase == .established || phase == .finFromApp {
      maybeDialProxy()
    }
  }

  private func acceptFIN(seqEnd: UInt32) {
    guard phase == .established || phase == .finToApp else { return }
    guard TCPStack.seqGE(seqEnd &+ 1, rcvNXT) else {
      // FIN before the data arrives — ignore until the gap fills.
      return
    }
    rcvNXT = seqEnd &+ 1
    if phase == .finToApp {
      finishBoth()
    } else {
      phase = .finFromApp
    }
    // After the app's FIN, keep the proxy for the response until it ends.
    pumpAll()
    checkDone()
  }

  private func checkDone() {
    // Both directions finished and everything delivered + acked → done.
    if phase == .finFromApp, finFromProxy,
       toAppSentOffset >= toApp.count, sndUNA == sndNXT {
      finishBoth()
    }
  }

  // MARK: - Dial

  private func maybeDialProxy() {
    guard phase == .established || phase == .finFromApp else { return }
    guard proxy == nil, !proxyDialing else { return }
    proxyDialing = true
    // toProxy stays buffered here; it is flushed through the codec on
    // ready (the codec's first write builds the protocol request header).
    stack.onDial(
      key, key.dstIP, key.dstPort,
      { [weak self] pipe in
        guard let self else { return }
        self.stack.queue.async {
          self.proxyDialing = false
          guard self.phase != .dead else {
            pipe.close()
            return
          }
          self.proxy = pipe
          self.proxyReady = true
          self.attachProxy(pipe)
          self.pumpToProxy()
        }
      },
      { [weak self] _ in
        guard let self else { return }
        self.stack.queue.async {
          self.proxyDialing = false
          guard self.phase != .dead else { return }
          self.sendRST()
          self.phase = .dead
          self.stack.removeFlow(self.key)
        }
      }
    )
  }

  private func attachProxy(_ pipe: ProxyPipe) {
    pipe.read { [weak self] data, error in
      guard let self else { return }
      self.stack.queue.async {
        guard self.phase != .dead, self.proxy === pipe else { return }
        if let data, !data.isEmpty {
          self.proxyDelivered(data)
        } else {
          self.proxyEnded()
        }
      }
    }
  }

  // MARK: - Proxy side

  func proxyDelivered(_ data: Data) {
    guard phase != .dead else { return }
    lastActivity = Date()
    toApp.append(contentsOf: data)
    stack.onBytes(0, data.count)
    pumpToApp()
    if toApp.count - toAppSentOffset < TCPStack.toProxyBufferLimit {
      readMoreFromProxy()
    }
  }

  func proxyEnded() {
    guard phase != .dead else { return }
    lastActivity = Date()
    finFromProxy = true
    pumpToApp()
    // FIN once everything toward the app is SEGMENTED (the ACK follows).
    if toAppSentOffset >= toApp.count, phase != .finToApp {
      sendFIN()
    }
    checkDone()
  }

  func proxyFailed() {
    guard phase != .dead else { return }
    sendRST()
    teardownProxy()
    phase = .dead
  }

  private func readMoreFromProxy() {
    guard let pipe = proxy, phase != .dead else { return }
    pipe.read { [weak self] data, error in
      guard let self else { return }
      self.stack.queue.async {
        guard self.phase != .dead, self.proxy === pipe else { return }
        if let data, !data.isEmpty {
          self.proxyDelivered(data)
        } else {
          self.proxyEnded()
        }
      }
    }
  }

  // MARK: - Pumps

  private func pumpAll() {
    pumpToProxy()
    pumpToApp()
  }

  private func pumpToProxy() {
    guard let pipe = proxy, proxyReady, phase != .dead else { return }
    guard !toProxy.isEmpty else { return }
    let chunk = Data(toProxy)
    toProxy.removeAll()
    pipe.write(chunk) { [weak self] error in
      guard let self else { return }
      self.stack.queue.async {
        guard self.phase != .dead else { return }
        if error != nil {
          self.proxyFailed()
          return
        }
        // Window re-opens for the app — announce it.
        self.sendACK()
        if self.toApp.count - self.toAppSentOffset < TCPStack.toProxyBufferLimit {
          self.readMoreFromProxy()
        }
      }
    }
  }

  private func pumpToApp() {
    guard phase != .dead, phase != .finToApp else { return }
    let unsent = toApp.count - toAppSentOffset
    guard unsent > 0 else {
      if finFromProxy, toAppSentOffset >= toApp.count, phase != .finToApp {
        sendFIN()
      }
      return
    }
    let inflight = Int(sndNXT &- sndUNA)
    let windowSpace = Int(theirWindow) - inflight
    guard windowSpace > 0 else {
      scheduleRTO()
      return
    }
    let budget = min(unsent, windowSpace, mss * 4)
    var sent = 0
    while sent < budget {
      let start = toAppSentOffset
      let take = min(mss, budget - sent, toApp.count - start)
      guard take > 0 else { break }
      let slice = Array(toApp[start..<(start + take)])
      let seq = sndNXT &+ UInt32(sent)
      sendSegment(seq: seq, flags: TCPPacket.flagACK,
                  window: advertisedWindowRaw(), options: [], payload: slice)
      toAppSentOffset += take
      sent += take
    }
    sndNXT = sndNXT &+ UInt32(sent)
    scheduleRTO()
    if finFromProxy, toAppSentOffset >= toApp.count, phase != .finToApp {
      sendFIN()
    }
  }

  /// Go-back-N retransmission of every segmented-but-unacked byte. Also
  /// doubles as the zero-window persist probe.
  private func retransmitUnacked() {
    guard phase != .dead else { return }
    guard sndNXT != sndUNA else { return }
    // toApp[0] is the byte at sndUNA (acked prefix removed in processAck).
    var offset = 0
    while offset < toAppSentOffset {
      let take = min(mss, toAppSentOffset - offset)
      let slice = Array(toApp[offset..<(offset + take)])
      let seq = sndUNA &+ UInt32(offset)
      sendSegment(seq: seq, flags: TCPPacket.flagACK,
                  window: advertisedWindowRaw(), options: [], payload: slice)
      offset += take
    }
    rto = min(rto * 2, 4.0)
    scheduleRTO()
  }

  private func scheduleRTO() {
    guard phase != .dead, sndNXT != sndUNA, rtoTimer == nil else { return }
    let timer = DispatchSource.makeTimerSource(queue: stack.queue)
    timer.schedule(deadline: .now() + rto)
    timer.setEventHandler { [weak self] in
      guard let self, self.phase != .dead else { return }
      self.rtoTimer = nil
      self.retransmitUnacked()
      self.pumpToApp()
    }
    timer.resume()
    rtoTimer = timer
  }

  // MARK: - Segments out

  private func advertisedWindowRaw() -> UInt16 {
    let space = max(TCPStack.toProxyBufferLimit - toProxy.count, 0)
    let unscaled = space >> Int(TCPStack.ourWindowScale)
    return UInt16(min(unscaled, 0xFFFF))
  }

  private func sendSegment(seq: UInt32, flags: UInt8, window: UInt16,
                           options: [UInt8], payload: [UInt8]) {
    let seg = TCPPacket.build(
      src: remoteIP, dst: appIP,
      srcPort: key.dstPort, dstPort: key.srcPort,
      seq: seq, ack: rcvNXT,
      flags: flags, window: window, options: options, payload: payload
    )
    let packet = IPv4Packet.build(
      src: remoteIP, dst: appIP,
      protocol: IPProtocolNumber.tcp.rawValue, payload: seg
    )
    stack.onSendPackets([Data(packet)])
  }

  private func sendACK() {
    sendSegment(seq: sndNXT, flags: TCPPacket.flagACK,
                window: advertisedWindowRaw(), options: [], payload: [])
  }

  private func sendFIN() {
    guard phase != .finToApp, phase != .dead else { return }
    sendSegment(seq: sndNXT, flags: TCPPacket.flagFIN | TCPPacket.flagACK,
                window: advertisedWindowRaw(), options: [], payload: [])
    sndNXT = sndNXT &+ 1
    phase = (phase == .finFromApp) ? .dead : .finToApp
    if phase == .dead { finishBoth() }
  }

  func sendRST() {
    guard phase != .dead else { return }
    sendSegment(seq: sndUNA, flags: TCPPacket.flagRST | TCPPacket.flagACK,
                window: 0, options: [], payload: [])
  }

  func teardownProxy() {
    proxy?.close()
    proxy = nil
    proxyReady = false
    rtoTimer?.cancel()
    rtoTimer = nil
  }

  private func finishBoth() {
    teardownProxy()
    phase = .dead
    stack.removeFlow(key)
  }
}
