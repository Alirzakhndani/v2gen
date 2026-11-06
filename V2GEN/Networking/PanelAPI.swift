import Foundation
import UIKit

// ── Panel relay client ────────────────────────────────────────────────────
// The app talks to the panel over TWO paths, one per phase of the flow:
//   ENTRY (not connected — the VPS IP is filtered in Iran): login + sub
//   always go through the anti-filter Cloudflare worker (sub.v2gen.xyz →
//   panel) — and each worker request RIDES EVERY FRONT AT ONCE (the DNS
//   path plus IP-pinned CF edges, see CFDirect): Iranian ISPs block
//   Cloudflare subnets non-uniformally, so a single-path login dies on
//   the wrong ISP while a raced one gets through. The worker learns from
//   the VPS which sub link belongs to this user; the app races exactly the configs that sub serves (the Lantern
//   mechanism lives in Racer/AutoSelect).
//   CONNECTED (a config from the sub is up — the VPS is reachable through
//   it): session logs (volume, remaining days, live heartbeat) go DIRECT
//   to the VPS (direct.v2gen.xyz:8443, DNS-only → 82.22.175.150). On
//   disconnect the exchange stops; the next connect re-enters via the
//   worker. Session contract (same endpoint on both legs — direct first,
//   worker fallback):
//   POST /api/app/login     { username, password }        → { ok, client }      (worker, raced)
//   GET  /api/sub/{token}                                → base64 links + headers (worker, raced)
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

/// A reached-the-worker HTTP response, whichever front delivered it.
struct PanelResponse: Sendable {
  let status: Int
  let body: Data
  /// Lowercased header map (both transport paths normalize into this).
  let headers: [String: String]

  func header(_ name: String) -> String? {
    headers[name.lowercased()]
  }
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
  /// config: worker entry → CF edge → proxy config → … works. (Plain
  /// URLSession only — this probe deliberately tests the CURRENT routing,
  /// not the anti-block fronts.)
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
    let res = try await request(
      "api/app/login", method: "POST", body: body
    )
    let decoded = (try? JSONDecoder.v2.decode(LoginResponse.self, from: res.body)) ?? .empty
    if (200..<300).contains(res.status), decoded.ok == true, let client = decoded.client {
      return client
    }
    throw PanelError.panel(decoded.error ?? "Login failed")
  }

  // MARK: - Subscription

  func subscription(token: String) async throws -> SubData {
    let res = try await request("api/sub/\(token)", method: "GET")
    let status = res.status
    guard (200..<300).contains(status) else {
      // 404 = unknown token / subscription inactive — the stored auth is
      // dead; the app drops it and returns to the login form. (The worker
      // serves KV fallback configs when the PANEL is down, so a 404 here
      // really means the token is gone.)
      if status == 404 { throw PanelError.inactive }
      throw PanelError.panel("Subscription fetch failed (\(status))")
    }
    // The body is standard base64 of newline-separated v2ray links.
    let trimmed = String(decoding: res.body, as: UTF8.self)
      .trimmingCharacters(in: .whitespacesAndNewlines)
    let decodedBody = Self.base64Decode(trimmed)
    let links = decodedBody
      .split(whereSeparator: \.isNewline)
      .map { $0.trimmingCharacters(in: .whitespaces) }
      .filter { !$0.isEmpty }
    let configs = links.compactMap(ConfigParser.parse(link:))

    var userinfo = SubUserinfo()
    if let raw = res.header("subscription-userinfo"), !raw.isEmpty {
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

    var title = res.header("profile-title") ?? ""
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
    let res = try await request(
      "api/app/session", method: "POST", body: body, via: path
    )
    return (try? JSONDecoder.v2.decode(SessionResponse.self, from: res.body)) ?? .empty
  }

  // MARK: - Plumbing

  private func request(
    _ path: String,
    method: String,
    body: Data? = nil,
    via route: SessionPath = .worker
  ) async throws -> PanelResponse {
    if route == .direct {
      return try await urlRequest(
        directBaseURL.appending(path: path), method: method, body: body,
        session: directSession
      )
    }
    return try await workerRequest(path, method: method, body: body)
  }

  // MARK: - Worker-front racing (Iranian anti-block)

  /// The CF edge IP that won the last race rides FIRST on the next
  /// request — sticky winner, so a working front keeps working.
  private static var stickyCFIP: String?

  private enum Front: Sendable {
    case url
    case cfIP(String)
  }

  private struct FrontOutcome: Sendable {
    let front: Front
    /// nil = this front failed to reach the worker at all (the failure
    /// reason is irrelevant — what matters is any-front-reached).
    let response: PanelResponse?
  }

  /// Fronts for this request: the DNS path always; the sticky CF winner
  /// and one rotating pool IP race alongside.
  private func pickFronts() -> [Front] {
    var fronts: [Front] = [.url]
    var candidates = CFDirect.pool
    if let sticky = PanelAPI.stickyCFIP {
      fronts.append(.cfIP(sticky))
      candidates.removeAll { $0 == sticky }
    }
    if let rotating = candidates.randomElement() {
      fronts.append(.cfIP(rotating))
    }
    return fronts
  }

  /// ENTRY-phase requests (login / sub / worker-fallback session logs)
  /// ride EVERY front at once — the DNS path plus IP-pinned Cloudflare
  /// edges that need no DNS at all. The first HTTP response wins (any
  /// status proves the front reaches the worker); every front failing is
  /// the only failure. Iranian ISPs block CF subnets non-uniformally —
  /// see CFDirect.
  private func workerRequest(
    _ path: String, method: String, body: Data?
  ) async throws -> PanelResponse {
    let fronts = pickFronts()
    let host = baseURL.host() ?? "sub.v2gen.xyz"
    return try await withThrowingTaskGroup(of: FrontOutcome.self) { group in
      for front in fronts {
        group.addTask {
          let res: PanelResponse?
          do {
            switch front {
            case .url:
              res = try await self.urlRequest(
                self.baseURL.appending(path: path), method: method,
                body: body, session: self.session
              )
            case .cfIP(let ip):
              let raw = try await CFDirect.request(
                ip: ip, host: host, path: path, method: method, body: body
              )
              res = PanelResponse(
                status: raw.status, body: raw.body, headers: raw.headers
              )
            }
          } catch {
            res = nil
          }
          return FrontOutcome(front: front, response: res)
        }
      }
      // Children NEVER throw (a failure rides as a nil response) — the
      // loop below only needs the first success.
      for try await outcome in group {
        if let res = outcome.response {
          if case .cfIP(let ip) = outcome.front {
            PanelAPI.stickyCFIP = ip
          }
          group.cancelAll()
          return res
        }
      }
      throw PanelError.network
    }
  }

  /// Plain URLSession transport — used directly by the direct (VPS)
  /// route and as the DNS front of the worker race.
  private func urlRequest(
    _ url: URL, method: String, body: Data?, session: URLSession
  ) async throws -> PanelResponse {
    var req = URLRequest(url: url)
    req.httpMethod = method
    req.httpBody = body
    if body != nil { req.setValue("application/json", forHTTPHeaderField: "content-type") }
    do {
      let (data, response) = try await session.data(for: req)
      let http = response as? HTTPURLResponse
      var headers: [String: String] = [:]
      for (k, v) in http?.allHeaderFields ?? [:] {
        if let ks = k as? String, let vs = v as? String {
          headers[ks.lowercased()] = vs
        }
      }
      return PanelResponse(
        status: http?.statusCode ?? -1, body: data, headers: headers
      )
    } catch {
      throw PanelError.network
    }
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
