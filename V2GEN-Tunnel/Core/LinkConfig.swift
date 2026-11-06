import Foundation

// ════════════════════════════════════════════════════════════════════════════
// LinkConfig — the tunnel's decoder for raw subscription links.
//
// This is deliberately SEPARATE from the app's ConfigParser (which keeps the
// panel-accounting identity triples). Here every parameter the wire needs is
// extracted: protocol, transport (tcp/ws), TLS (sni/verify), and the
// per-protocol credentials.
//
// Unsupported shapes (reality, vision flow, grpc, http-obfs, legacy stream
// ciphers, plugins) parse to `nil` — the dialer rejects them up front, and
// the Lantern failover ladder simply never races them into the tunnel.
// ════════════════════════════════════════════════════════════════════════════

struct LinkConfig {
  var proto: Proto
  var tag: String
  var host: String            // connect address (endpoint of the transport)
  var port: UInt16
  var tls: Bool
  var sni: String             // TLS server name ("" → host)
  var verifyTLS: Bool
  var network: Network        // .tcp or .ws
  var wsPath: String
  var wsHost: String          // Host header for the WS upgrade ("" → sni/host)
  var wsEarlyData: Int        // max early-data bytes via Sec-WebSocket-Protocol (0 = off)
  var creds: Creds

  enum Proto: String {
    case vless, vmess, ss, trojan
  }

  enum Network: String {
    case tcp, ws
  }

  enum Creds {
    case vless(uuid: [UInt8])                       // 16 raw bytes
    case vmess(uuid: [UInt8], security: VMessSecurity)
    case ss(method: SSMethod, password: [UInt8])    // password = raw PSK (2022) or passphrase
    case trojan(password: String)
  }

  enum VMessSecurity: String {
    case aes128gcm, chacha20
  }

  enum SSMethod: String {
    case aes128gcm = "aes-128-gcm"
    case aes192gcm = "aes-192-gcm"
    case aes256gcm = "aes-256-gcm"
    case chacha20poly1305 = "chacha20-ietf-poly1305"
    case xchacha20poly1305 = "xchacha20-ietf-poly1305"
    case blake3aes128gcm = "2022-blake3-aes-128-gcm"
    case blake3aes256gcm = "2022-blake3-aes-256-gcm"
    case blake3chacha20 = "2022-blake3-chacha20-poly1305"

    /// Key length — also the classic-AEAD salt length (SIP004).
    var keyLength: Int {
      switch self {
      case .aes128gcm, .blake3aes128gcm: return 16
      case .aes192gcm: return 24
      case .aes256gcm, .chacha20poly1305, .xchacha20poly1305,
           .blake3aes256gcm, .blake3chacha20: return 32
      }
    }

    /// True for Shadowsocks-2022 (SIP022) — password is the base64 PSK,
    /// subkey derivation is BLAKE3, and the header carries a timestamp.
    var is2022: Bool {
      switch self {
      case .blake3aes128gcm, .blake3aes256gcm, .blake3chacha20: return true
      default: return false
      }
    }
  }

  // MARK: - Parsing

  static func parse(_ link: String) -> LinkConfig? {
    if link.hasPrefix("vless://") { return parseVLESS(link) }
    if link.hasPrefix("vmess://") { return parseVMess(link) }
    if link.hasPrefix("ss://") { return parseSS(link) }
    if link.hasPrefix("trojan://") { return parseTrojan(link) }
    return nil
  }

  // ── vless://uuid@host:port?params#tag ────────────────────────────────────

  private static func parseVLESS(_ link: String) -> LinkConfig? {
    guard let url = URL(string: link), let host = url.host, let port = url.port16,
          let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let user = comps.user,
          let uuid = uuidBytes(user)
    else { return nil }

    let q = queryDict(comps)
    let security = (q["security"] ?? "none").lowercased()
    guard security == "none" || security == "tls" else { return nil }   // reality → unsupported

    // Vision flow and mux change the wire format — only the plain
    // (flow-less) VLESS payload model is implemented.
    guard (q["flow"] ?? "").isEmpty else { return nil }

    let network = (q["type"] ?? "tcp").lowercased()
    var net = Network.tcp
    var wsPath = "/"
    var wsHost = ""
    var earlyData = 0
    if network == "ws" {
      net = .ws
      wsPath = q["path"] ?? "/"
      wsHost = q["host"] ?? ""
      // ?ed=2048 inside the path query → early data via Sec-WebSocket-Protocol
      if let edValue = pathQuery(wsPath)["ed"], let ed = Int(edValue), ed > 0 {
        earlyData = min(ed, 2048)
      }
    } else if network != "tcp" {
      return nil   // grpc / h2 / kcp → unsupported
    }

    let tls = security == "tls"
    let sni = firstNonEmpty(q["sni"], q["peer"], tls ? host : "")
    let allowInsecure = q["allowinsecure"] == "1" || q["insecure"] == "1"
    let tag = fragmentOf(link)

    return LinkConfig(
      proto: .vless, tag: tag.isEmpty ? host : tag, host: host, port: port,
      tls: tls, sni: sni, verifyTLS: !allowInsecure,
      network: net, wsPath: wsPath, wsHost: wsHost, wsEarlyData: earlyData,
      creds: .vless(uuid: uuid)
    )
  }

  // ── vmess://base64(json) ─────────────────────────────────────────────────

  private static func parseVMess(_ link: String) -> LinkConfig? {
    let b64 = String(link.dropFirst("vmess://".count))
    guard let json = String(validating: Data(base64Flexible: b64), as: UTF8.self),
          let obj = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
    else { return nil }

    guard let add = obj["add"] as? String, !add.isEmpty,
          let port = anyInt(obj["port"]), (1...65535).contains(port),
          let uuid = uuidBytes(obj["id"] as? String ?? "")
    else { return nil }

    // AEAD VMess only — alterId > 0 is the legacy (pre-4.28) protocol.
    guard (anyInt(obj["aid"]) ?? 0) == 0 else { return nil }

    // Security: auto / aes-128-gcm / chacha20-poly1305. "none" (plaintext
    // body) is rare in subs and unsupported.
    let scy = ((obj["scy"] as? String) ?? "auto").lowercased()
    let security: VMessSecurity
    switch scy {
    case "auto", "aes-128-gcm": security = .aes128gcm
    case "chacha20-poly1305": security = .chacha20
    default: return nil
    }

    let net = ((obj["net"] as? String) ?? "tcp").lowercased()
    let headerType = ((obj["type"] as? String) ?? "none").lowercased()
    guard headerType == "none" || headerType.isEmpty else { return nil }  // http obfs → no

    var network = Network.tcp
    var wsPath = "/"
    var wsHost = ""
    var earlyData = 0
    if net == "ws" {
      network = .ws
      wsPath = (obj["path"] as? String) ?? "/"
      wsHost = (obj["host"] as? String) ?? ""
      if let edValue = pathQuery(wsPath)["ed"], let ed = Int(edValue), ed > 0 {
        earlyData = min(ed, 2048)
      }
    } else if net != "tcp" {
      return nil   // grpc / h2 / kcp → unsupported
    }

    let tlsOn = ((obj["tls"] as? String) ?? "").lowercased() == "tls"
    let sniRaw = (obj["sni"] as? String) ?? ""
    let sni = sniRaw.isEmpty ? (tlsOn ? add : "") : sniRaw
    let tag = (obj["ps"] as? String) ?? add

    return LinkConfig(
      proto: .vmess, tag: tag, host: add, port: UInt16(port),
      tls: tlsOn, sni: sni, verifyTLS: true,
      network: network, wsPath: wsPath, wsHost: wsHost, wsEarlyData: earlyData,
      creds: .vmess(uuid: uuid, security: security)
    )
  }

  // ── ss:// (SIP002 + legacy full-base64) ──────────────────────────────────

  private static func parseSS(_ link: String) -> LinkConfig? {
    // Plugin-based links change the transport — unsupported.
    if link.contains("plugin=") { return nil }

    let body = upToFragment(link, after: "ss://")
    guard !body.isEmpty else { return nil }
    let tag = fragmentOf(link)

    var methodPass: String
    var hostPort: String

    if let at = body.lastIndex(of: "@") {
      methodPass = String(body[body.startIndex..<at])
      hostPort = String(body[body.index(after: at)...])
      if !methodPass.contains(":") {
        // ss://base64(method:pass)@host:port
        guard let dec = String(validating: Data(base64Flexible: methodPass), as: UTF8.self) else {
          return nil
        }
        methodPass = dec
      } else {
        methodPass = methodPass.removingPercentEncoding ?? methodPass
      }
    } else {
      // ss://base64(method:pass@host:port)
      guard let dec = String(validating: Data(base64Flexible: body), as: UTF8.self),
            let at = dec.lastIndex(of: "@")
      else { return nil }
      methodPass = String(dec[dec.startIndex..<at])
      hostPort = String(dec[dec.index(after: at)...])
    }

    guard let (host, port) = splitHostPort(hostPort) else { return nil }
    guard let colon = methodPass.firstIndex(of: ":") else { return nil }
    let method = String(methodPass[methodPass.startIndex..<colon])
    let pass = String(methodPass[methodPass.index(after: colon)...])
    guard let ssMethod = SSMethod(rawValue: method) else { return nil }
    guard (1...65535).contains(port) else { return nil }

    var password: [UInt8]
    if ssMethod.is2022 {
      // Shadowsocks-2022: the password IS the base64 PSK, length == key length.
      guard let psk = [UInt8](base64URLDecoded: pass), psk.count == ssMethod.keyLength else {
        return nil
      }
      password = psk
    } else {
      password = Array(pass.utf8)
    }

    return LinkConfig(
      proto: .ss, tag: tag.isEmpty ? host : tag, host: host, port: UInt16(port),
      tls: false, sni: "", verifyTLS: true,
      network: .tcp, wsPath: "/", wsHost: "", wsEarlyData: 0,
      creds: .ss(method: ssMethod, password: password)
    )
  }

  // ── trojan://password@host:port?params#tag ───────────────────────────────

  private static func parseTrojan(_ link: String) -> LinkConfig? {
    guard let url = URL(string: link), let host = url.host, let port = url.port16,
          let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let pass = comps.user?.removingPercentEncoding, !pass.isEmpty
    else { return nil }

    let q = queryDict(comps)
    let security = (q["security"] ?? "tls").lowercased()
    guard security == "tls" || security == "none" else { return nil }

    let network = (q["type"] ?? "tcp").lowercased()
    var net = Network.tcp
    var wsPath = "/"
    var wsHost = ""
    if network == "ws" {
      net = .ws
      wsPath = q["path"] ?? "/"
      wsHost = q["host"] ?? ""
    } else if network != "tcp" {
      return nil
    }

    let tls = security == "tls"
    let sni = firstNonEmpty(q["sni"], q["peer"], tls ? host : "")
    let allowInsecure = q["allowinsecure"] == "1" || q["insecure"] == "1"
    let tag = fragmentOf(link)

    return LinkConfig(
      proto: .trojan, tag: tag.isEmpty ? host : tag, host: host, port: port,
      tls: tls, sni: sni, verifyTLS: !allowInsecure,
      network: net, wsPath: wsPath, wsHost: wsHost, wsEarlyData: 0,
      creds: .trojan(password: pass)
    )
  }
}

// MARK: - Small parsing helpers

private func queryDict(_ comps: URLComponents) -> [String: String] {
  var out: [String: String] = [:]
  for item in comps.queryItems ?? [] {
    out[item.name.lowercased()] = item.value ?? ""
  }
  return out
}

private func firstNonEmpty(_ values: String...) -> String {
  for v in values where !v.trimmingCharacters(in: .whitespaces).isEmpty {
    return v.trimmingCharacters(in: .whitespaces)
  }
  return ""
}

private func pathQuery(_ path: String) -> [String: String] {
  guard let q = path.firstIndex(of: "?") else { return [:] }
  var out: [String: String] = [:]
  for pair in path[path.index(after: q)...].split(separator: "&") {
    let kv = pair.split(separator: "=", maxSplits: 1).map(String.init)
    guard !kv.isEmpty else { continue }
    out[kv[0]] = kv.count > 1 ? kv[1] : ""
  }
  return out
}

private func splitHostPort(_ s: String) -> (String, Int)? {
  guard let colon = s.lastIndex(of: ":") else { return nil }
  let host = String(s[s.startIndex..<colon])
    .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
  let port = Int(s[s.index(after: colon)...])
  guard !host.isEmpty, let port else { return nil }
  return (host, port)
}

private func upToFragment(_ link: String, after prefix: String) -> String {
  var body = String(link.dropFirst(prefix.count))
  if let hash = body.firstIndex(of: "#") {
    body = String(body[body.startIndex..<hash])
  }
  return body
}

private func fragmentOf(_ link: String) -> String {
  guard let hash = link.firstIndex(of: "#") else { return "" }
  return String(link[link.index(after: hash)...]).removingPercentEncoding ?? ""
}

private func anyInt(_ value: Any?) -> Int? {
  if let i = value as? Int { return i }
  if let s = value as? String { return Int(s) }
  if let d = value as? Double { return Int(d) }
  return nil
}

private func uuidBytes(_ s: String) -> [UInt8]? {
  let hex = s
    .replacingOccurrences(of: "-", with: "")
    .replacingOccurrences(of: "urn:uuid:", with: "")
  guard hex.count == 32, let bytes = [UInt8](hexEncoded: hex) else { return nil }
  return bytes
}

private extension URL {
  /// URL.port traps on out-of-range ports in some runtimes — the safe
  /// URLComponents path instead.
  var port16: UInt16? {
    guard let comps = URLComponents(url: self, resolvingAgainstBaseURL: false),
          let port = comps.port, (1...65535).contains(port) else { return nil }
    return UInt16(port)
  }
}

private extension Data {
  /// Standard + URL-safe base64, padding-tolerant.
  init(base64Flexible s: String) {
    var t = s.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    self = Data(base64Encoded: t) ?? Data()
  }
}

private extension [UInt8] {
  init?(base64URLDecoded s: String) {
    var t = s.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    guard let d = Data(base64Encoded: t) else { return nil }
    self = [UInt8](d)
  }

  init?(hexEncoded s: String) {
    let chars = Array(s)
    guard chars.count % 2 == 0, !chars.isEmpty else { return nil }
    var out: [UInt8] = []
    var i = 0
    while i < chars.count {
      guard let h = hexVal(chars[i]), let l = hexVal(chars[i + 1]) else { return nil }
      out.append(h << 4 | l)
      i += 2
    }
    self = out
  }
}

private func hexVal(_ c: Character) -> UInt8? {
  guard let a = c.asciiValue else { return nil }
  switch a {
  case 0x30...0x39: return a - 0x30
  case 0x61...0x66: return a - 0x61 + 10
  case 0x41...0x46: return a - 0x41 + 10
  default: return nil
  }
}
