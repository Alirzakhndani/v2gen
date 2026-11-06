import Foundation

// ── V2GEN models — value types throughout (write-swift skill) ────────────
// One enum for the mutually-exclusive connection lifecycle, instead of a
// pile of booleans: invalid combinations become unrepresentable.

/// The account record returned by the panel relay. Mirrors the web app's
/// `PanelClient`. Stored in the Keychain as JSON.
struct PanelClient: Codable, Equatable, Sendable {
  var name: String
  var subToken: String
  var status: String
  var usedBytes: Int
  var limitBytes: Int        // 0 = unlimited
  var expireAt: Date?
  var maxConnections: Int
}

/// One parsed v2ray link from the subscription body.
struct ParsedConfig: Codable, Identifiable, Equatable, Hashable, Sendable {
  var raw: String
  var protocol: ConfigProtocol
  var name: String
  var host: String
  var port: Int
  /// The link's own transport security claim (`security=tls|reality` on
  /// vless, `tls:"tls"` on vmess). When true the probe measures the TLS
  /// handshake, not just the TCP connect — Lantern's probe runs
  /// dial + handshake + request, and the handshake is the part Iranian
  /// censorship actually kills on a live connection.
  var isTLS: Bool = false
  /// SNI from the link (`sni` / `peer` on vless, `sni` on vmess) — what the
  /// TLS probe presents. Falls back to the host.
  var sni: String? = nil

  var id: String { "\(name)|\(host):\(port)" }

  enum ConfigProtocol: String, Codable, Sendable {
    case vless, vmess, ss, other
  }
}

/// Subscription payload (`/api/sub/{token}`).
struct SubData: Sendable {
  var title: String
  var configs: [ParsedConfig]
  var userinfo: SubUserinfo
}

struct SubUserinfo: Sendable {
  var upload: Int?
  var download: Int?
  var total: Int?
  var expire: Int?
}

/// A racer probe result. `rttMs == nil` means unreachable.
struct ProbeResult: Sendable {
  var config: ParsedConfig
  var rttMs: Int?
}

/// Connection lifecycle — the single source of truth the UI renders.
enum ConnState: Equatable, Sendable {
  case loading        // configs syncing after sign-in
  case ready          // slide to connect
  case connecting     // racing configs
  case connected
  case disconnecting
  case error

  /// Screen-reader announcements (state is never color alone).
  var announcement: String? {
    switch self {
    case .loading: nil
    case .ready: nil
    case .connecting: "Connecting"
    case .connected: "Connected"
    case .disconnecting: "Disconnecting"
    case .error: "Connection failed"
    }
  }
}

/// Session actions understood by the CF-worker relay.
enum SessionAction: String, Codable, Sendable {
  case start, beat, stop
}
