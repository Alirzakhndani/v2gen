import Foundation
import UIKit

// ── Panel relay client ────────────────────────────────────────────────────
// The app talks to the panel over TWO paths, one per phase of the flow:
//   ENTRY (not connected — the VPS IP is filtered in Iran): login + sub
//   always go through the anti-filter Cloudflare worker (sub.v2gen.xyz →
//   panel). The worker learns from the VPS which sub link belongs to this
//   user; the app races exactly the configs that sub serves (the Lantern
//   mechanism lives in Racer/AutoSelect).
//   CONNECTED (a config from the sub is up — the VPS is reachable through
//   it): session logs (volume, remaining days, live heartbeat) go DIRECT
//   to the VPS (direct.v2gen.xyz:8443, DNS-only → 82.22.175.150). On
//   disconnect the exchange stops; the next connect re-enters via the
//   worker. Session contract (same endpoint on both legs — direct first,
//   worker fallback):
//   POST /api/app/login     { username, password }        → { ok, client }      (worker only)
//   GET  /api/sub/{token}                                → base64 links + headers (worker only)
//   POST /api/app/session   { subToken, action, … }       → { ok, sessionKey }   (direct → worker fallback)

enum PanelError: Error {
  /// The panel's own message — usually Persian, shown verbatim.
  case panel(String)
  /// The stored sub token is dead (unknown / subscription inactive) —
  /// the app drops it and returns to the login form.
  case inactive
  /// Transport-level failure reaching the worker.
  case network
}

/// Which leg of the flow a session request rides.
enum SessionPath: String, Sendable {
  /// Anti-filter Cloudflare worker — the ENTRY (login/sub) and the
  /// fallback for session logs while the tunnel is down.
  case worker
  /// Straight to the VPS — used for session logs while CONNECTED (the
  /// user's own tunnel makes the host reachable; nothing CF in between).
  case direct
}

struct PanelAPI: Sendable {
  /// Anti-filter entry — Cloudflare edge (always reachable in Iran).
  var baseURL = URL(string: "https://sub.v2gen.xyz")!
  /// Direct-to-VPS session logs (DNS-only host → 82.22.175.150). Only
  /// reachable while the user is connected through one of their configs —
  /// exactly when the app uses it.
  var directBaseURL = URL(string: "https://direct.v2gen.xyz:8443")!

  private let session: URLSession = {
    var cfg = URLSessionConfiguration.default
    cfg.timeoutIntervalForRequest = 15
    cfg.httpAdditionalHeaders = ["user-agent": "V2GEN-iOS/1.0"]
    return URLSession(configuration: cfg)
  }()

  /// Shorter leash on the direct leg: when the tunnel is down the host is
  /// simply filtered — fail fast so the beat can fall back to the worker
  /// inside the same interval. (AppModel benches direct after a failure.)
  private let directSession: URLSession = {
    var cfg = URLSessionConfiguration.default
    cfg.timeoutIntervalForRequest = 7
    cfg.httpAdditionalHeaders = ["user-agent": "V2GEN-iOS/1.0"]
    return URLSession(configuration: cfg)
  }()

  /// Fresh-connection session for tunnel verification: ephemeral (empty
  /// pool) + `Connection: close` — every request opens a NEW socket, so it
  /// follows the CURRENT routing table (through the tunnel once it's up)
  /// instead of reusing a pooled pre-tunnel connection that would bypass it.
  private let probeSession: URLSession = {
    var cfg = URLSessionConfiguration.ephemeral
    cfg.timeoutIntervalForRequest = 8
    cfg.httpAdditionalHeaders = [
      "user-agent": "V2GEN-iOS/1.0",
      "connection": "close",
    ]
    return URLSession(configuration: cfg)
  }()

  // MARK: - Tunnel verification

  /// Reach the worker's /healthz on a FRESH connection — the traffic this
  /// generates rides the tunnel when one is up (the engine's byte counter
  /// proves it), making it the end-to-end data-plane check for a candidate
  /// config: worker entry → CF edge → proxy config → … works.
  func healthCheck() async -> Bool {
    var req = URLRequest(url: baseURL.appending(path: "healthz"))
    req.timeoutInterval = 8
    do {
      let (_, response) = try await probeSession.data(for: req)
      return (response as? HTTPURLResponse)?.statusCode == 200
    } catch {
      return false
    }
  }

  // MARK: - Login

  struct LoginResponse: Decodable {
    let ok: Bool?
    let client: PanelClient?
    let error: String?

    /// Unparseable/empty bodies decode to this — the caller then surfaces
    /// the failure through the normal error path.
    static let empty = LoginResponse(ok: nil, client: nil, error: nil)
  }

  func login(username: String, password: String) async throws -> PanelClient {
    let body = try JSONSerialization.data(withJSONObject: [
      "username": username, "password": password,
    ])
    let (data, response) = try await request(
      "api/app/login", method: "POST", body: body
    )
    let decoded = (try? JSONDecoder.v2.decode(LoginResponse.self, from: data)) ?? .empty
    if httpOK(response), decoded.ok == true, let client = decoded.client {
      return client
    }
    throw PanelError.panel(decoded.error ?? "Login failed")
  }

  // MARK: - Subscription

  func subscription(token: String) async throws -> SubData {
    let (data, response) = try await request("api/sub/\(token)", method: "GET")
    let status = httpStatus(response)
    guard (200..<300).contains(status) else {
      // 404 = unknown token / subscription inactive — the stored auth is
      // dead; the app drops it and returns to the login form. (The worker
      // serves KV fallback configs when the PANEL is down, so a 404 here
      // really means the token is gone.)
      if status == 404 { throw PanelError.inactive }
      throw PanelError.panel("Subscription fetch failed (\(status))")
    }
    // The body is standard base64 of newline-separated v2ray links.
    let trimmed = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    let decodedBody = Self.base64Decode(trimmed)
    let links = decodedBody
      .split(whereSeparator: \.isNewline)
      .map { $0.trimmingCharacters(in: .whitespaces) }
      .filter { !$0.isEmpty }
    let configs = links.compactMap(ConfigParser.parse(link:))

    var userinfo = SubUserinfo()
    if let raw = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "subscription-userinfo"),
       !raw.isEmpty {
      for pair in raw.split(separator: ";") {
        let kv = pair.split(separator: "=", maxSplits: 1).map(String.init)
        guard kv.count == 2, let v = Int(kv[1]) else { continue }
        switch kv[0].trimmingCharacters(in: .whitespaces) {
        case "upload": userinfo.upload = v
        case "download": userinfo.download = v
        case "total": userinfo.total = v
        case "expire": userinfo.expire = v
        default: break
        }
      }
    }

    var title = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "profile-title") ?? ""
    if title.hasPrefix("base64:") {
      title = String(Self.base64Decode(String(title.dropFirst(7))))
    }

    return SubData(title: title, configs: configs, userinfo: userinfo)
  }

  // MARK: - Session lifecycle

  struct SessionResponse: Decodable {
    let ok: Bool?
    let sessionKey: String?
    let client: PanelClient?
    let error: String?

    static let empty = SessionResponse(ok: nil, sessionKey: nil, client: nil, error: nil)
  }

  func session(
    via path: SessionPath = .worker,
    token: String,
    action: SessionAction,
    sessionKey: String? = nil,
    device: String? = nil,
    config: ParsedConfig? = nil,
    bytesUp: Int? = nil,
    bytesDown: Int? = nil
  ) async throws -> SessionResponse {
    var payload: [String: Any] = ["subToken": token, "action": action.rawValue]
    if let sessionKey { payload["sessionKey"] = sessionKey }
    if let device { payload["device"] = device }
    if let config {
      payload["configTag"] = config.name
      payload["configHost"] = config.host
      payload["configPort"] = config.port
    }
    if let bytesUp { payload["bytesUp"] = bytesUp }
    if let bytesDown { payload["bytesDown"] = bytesDown }
    let body = try JSONSerialization.data(withJSONObject: payload)
    let (data, _) = try await request(
      "api/app/session", method: "POST", body: body, via: path
    )
    return (try? JSONDecoder.v2.decode(SessionResponse.self, from: data)) ?? .empty
  }

  // MARK: - Plumbing

  private func request(
    _ path: String,
    method: String,
    body: Data? = nil,
    via route: SessionPath = .worker
  ) async throws -> (Data, URLResponse) {
    let base = route == .direct ? directBaseURL : baseURL
    let sender = route == .direct ? directSession : session
    var req = URLRequest(url: base.appending(path: path))
    req.httpMethod = method
    req.httpBody = body
    if body != nil { req.setValue("application/json", forHTTPHeaderField: "content-type") }
    do {
      return try await sender.data(for: req)
    } catch {
      throw PanelError.network
    }
  }

  private func httpStatus(_ r: URLResponse) -> Int {
    (r as? HTTPURLResponse)?.statusCode ?? -1
  }

  private func httpOK(_ r: URLResponse) -> Bool {
    (200..<300).contains(httpStatus(r))
  }

  /// URL-safe base64 with padding fix.
  static func base64Decode(_ s: String) -> String {
    var t = s.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    guard let d = Data(base64Encoded: t) else { return s }
    return String(decoding: d, as: UTF8.self)
  }
}

extension JSONDecoder {
  /// `expireAt` arrives as ISO-8601 with fractional seconds
  /// ("2027-03-01T00:00:00.000Z").
  static let v2: JSONDecoder = {
    let d = JSONDecoder()
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let f2 = ISO8601DateFormatter()
    d.dateDecodingStrategy = .custom { decoder in
      let container = try decoder.singleValueContainer()
      let raw = try container.decode(String.self)
      if let date = f.date(from: raw) ?? f2.date(from: raw) { return date }
      throw DecodingError.dataCorruptedError(in: container, debugDescription: "bad date \(raw)")
    }
    return d
  }()
}

extension JSONEncoder {
  /// The matching writer — Keychain round-trips stay ISO-8601.
  static let v2: JSONEncoder = {
    let e = JSONEncoder()
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    e.dateEncodingStrategy = .custom { date, encoder in
      var container = encoder.singleValueContainer()
      try container.encode(f.string(from: date))
    }
    return e
  }()
}

/// The device label sent with session start (mirrors the web client).
var v2DeviceLabel: String {
  "V2GEN iOS · \(UIDevice.current.model)"
}
