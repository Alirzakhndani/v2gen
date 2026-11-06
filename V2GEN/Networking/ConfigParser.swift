import Foundation

// ── v2ray link parsing (vless / vmess / ss) ───────────────────────────────
// Direct port of the web app's parser — the same links must produce the
// same host/port/name triples so panel accounting matches across clients.

enum ConfigParser {
  static func parse(link: String) -> ParsedConfig? {
    if link.hasPrefix("vless://") {
      return parseVless(link)
    }
    if link.hasPrefix("vmess://") {
      return parseVmess(link)
    }
    if link.hasPrefix("ss://") {
      return parseSS(link)
    }
    guard !link.isEmpty else { return nil }
    return ParsedConfig(
      raw: link,
      proto: .other,
      name: String(link.prefix(24)),
      host: "",
      port: 0
    )
  }

  private static func parseVless(_ link: String) -> ParsedConfig? {
    guard let url = URL(string: link) else { return nil }
    let name = url.fragment.map { String($0.dropFirst()) }.flatMap(percentDecode) ?? ""
    let host = url.host ?? ""
    let port = url.port ?? 443
    guard !host.isEmpty else { return nil }

    // Transport security + SNI from the query (`security=tls|reality&sni=…`).
    // These drive the TLS-aware probe — name/host/port stay identical to
    // the web parser so panel accounting matches across clients.
    var isTLS = false
    var sni: String? = nil
    if let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) {
      let items = comps.queryItems ?? []
      let security = (items.first { $0.name == "security" }?.value ?? "").lowercased()
      isTLS = security == "tls" || security == "reality"
      for key in ["sni", "peer"] {
        if let v = items.first(where: { $0.name == key })?.value,
           !v.trimmingCharacters(in: .whitespaces).isEmpty {
          sni = v
          break
        }
      }
    }

    return ParsedConfig(
      raw: link, proto: .vless,
      name: name.isEmpty ? host : name,
      host: host, port: port,
      isTLS: isTLS, sni: sni
    )
  }

  private static func parseVmess(_ link: String) -> ParsedConfig? {
    guard let json = try? JSONSerialization.jsonObject(
      with: Data(base64Decoded: String(link.dropFirst("vmess://".count)))
    ) as? [String: Any] else { return nil }
    let host = json["add"] as? String ?? ""
    let port = (json["port"] as? Int) ?? Int(json["port"] as? String ?? "") ?? 443
    guard !host.isEmpty else { return nil }

    // `tls: "tls"` (some panels also emit "reality") + optional `sni`.
    let tlsRaw = (json["tls"] as? String ?? "").lowercased()
    let isTLS = tlsRaw == "tls" || tlsRaw == "reality"
    let sni = (json["sni"] as? String).flatMap(nonEmpty)

    return ParsedConfig(
      raw: link, proto: .vmess,
      name: (json["ps"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? host,
      host: host, port: port,
      isTLS: isTLS, sni: sni
    )
  }

  private static func parseSS(_ link: String) -> ParsedConfig? {
    let hashIdx = link.firstIndex(of: "#")
    var name = ""
    if let hashIdx {
      name = link[link.index(after: hashIdx)...].removingPercentEncoding ?? ""
    }
    let bodyStart = link.index(link.startIndex, offsetBy: 5)
    let bodyEnd = hashIdx ?? link.endIndex
    let body = String(link[bodyStart..<bodyEnd])

    // ss://base64(method:pass)@host:port — the host:port tail is plain.
    if let at = body.lastIndex(of: "@"),
       body[body.startIndex..<at].contains(":") {
      let hostPart = String(body[body.index(after: at)...])
      guard let lastColon = hostPart.lastIndex(of: ":") else { return nil }
      let host = hostPart[hostPart.startIndex..<lastColon].isEmpty
        ? hostPart
        : String(hostPart[hostPart.startIndex..<lastColon])
      let port = Int(hostPart[hostPart.index(after: lastColon)...]) ?? 443
      guard !host.isEmpty else { return nil }
      return ParsedConfig(
        raw: link, proto: .ss, name: name.isEmpty ? host : name,
        host: host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")),
        port: port
      )
    }

    // ss://base64(method:pass@host:port) — the whole body is encoded.
    guard let decoded = String(validating: Data(base64Decoded: body), as: UTF8.self),
          let at = decoded.range(of: "@", options: .backwards)
    else { return nil }
    let tail = String(decoded[at.upperBound...])
    guard let colon = tail.lastIndex(of: ":"),
          let port = Int(tail[tail.index(after: colon)...]) else { return nil }
    let host = String(tail[tail.startIndex..<colon])
      .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    guard !host.isEmpty else { return nil }
    return ParsedConfig(
      raw: link, proto: .ss, name: name.isEmpty ? host : name,
      host: host, port: port
    )
  }

  private static func percentDecode(_ s: String) -> String? {
    s.removingPercentEncoding
  }

  private static func nonEmpty(_ s: String) -> String? {
    let t = s.trimmingCharacters(in: .whitespaces)
    return t.isEmpty ? nil : t
  }
}

private extension Data {
  /// Standard + URL-safe base64, padding-tolerant.
  init(base64Decoded s: String) {
    var t = s.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    self = Data(base64Encoded: t) ?? Data()
  }
}
