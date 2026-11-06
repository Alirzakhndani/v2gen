import Foundation

// ════════════════════════════════════════════════════════════════════════════
// V2GenIPC — the app ⇄ tunnel contract, compiled into BOTH targets.
//
//   App  → Tunnel : V2GenTunnelCommand   (file: tunnel-command.json)
//   Tunnel → App  : V2GenTunnelStats     (file: tunnel-stats.json)
//
// Transport: JSON files in the shared App Group container, written atomically.
// Signalling: Darwin notifications (zero-cost IPC on iOS) so the tunnel
// hot-swaps configs mid-session without tearing the TUN device down, and the
// app refreshes its live counters the moment they change.
// ════════════════════════════════════════════════════════════════════════════

/// App Group identifier shared by the app and the packet-tunnel extension.
///
/// ⚠️ Free signing rewrites it: Xcode personal teams register
/// `group.<TEAMID>.xyz.v2gen.app` and Sideloadly/AltStore do the same. The
/// identifier is therefore RESOLVED at runtime from the embedded
/// provisioning profile (whose `application-groups` always matches what the
/// signer actually provisioned), with the build-time name as fallback.
enum V2GenAppGroup {
  static let fallbackID = "group.xyz.v2gen.shared"

  static let resolvedID: String = {
    for candidate in profileGroupCandidates() {
      if FileManager.default
        .containerURL(forSecurityApplicationGroupIdentifier: candidate) != nil {
        return candidate
      }
    }
    return fallbackID
  }()

  /// `application-groups` from every embedded provisioning profile we can
  /// see — our own bundle (app process) and the containing .app (extension
  /// process, whose Bundle.main is the .appex).
  private static func profileGroupCandidates() -> [String] {
    var profileURLs: [URL] = []
    if let own = Bundle.main.url(
      forResource: "embedded", withExtension: "mobileprovision"
    ) {
      profileURLs.append(own)
    }
    if Bundle.main.bundleURL.pathExtension == "appex" {
      let appBundleURL = Bundle.main.bundleURL
        .deletingLastPathComponent()      // PlugIns/
        .deletingLastPathComponent()      // V2GEN.app/
      if let appProfile = Bundle(url: appBundleURL)?.url(
        forResource: "embedded", withExtension: "mobileprovision"
      ) {
        profileURLs.append(appProfile)
      }
    }

    var groups: [String] = []
    for url in profileURLs {
      groups.append(contentsOf: parseApplicationGroups(profileAt: url))
    }
    return groups
  }

  /// The .mobileprovision is a CMS wrapper around a plist — the XML lives
  /// between the first `<?xml` and the last `</plist>`.
  private static func parseApplicationGroups(profileAt url: URL) -> [String] {
    guard let data = try? Data(contentsOf: url) else { return [] }
    guard let xmlStart = data.range(of: Data("<?xml".utf8)),
          let xmlEnd = data.range(of: Data("</plist>".utf8),
                                  options: .backwards),
          xmlStart.lowerBound < xmlEnd.upperBound
    else { return [] }
    let plistData = data[xmlStart.lowerBound..<xmlEnd.upperBound]
    guard let plist = try? PropertyListSerialization.propertyList(
      from: Data(plistData), options: [], format: nil
    ) as? [String: Any],
      let entitlements = plist["Entitlements"] as? [String: Any],
      let groups = entitlements["com.apple.security.application-groups"] as? [String]
    else { return [] }
    return groups
  }
}

/// Darwin notification names.
let V2GenNotifyReload = "xyz.v2gen.tunnel.reload"     // app → tunnel: config rewritten
let V2GenNotifyStats  = "xyz.v2gen.tunnel.stats"      // tunnel → app: stats rewritten

/// Where the IPC files live (App Group container). Nil when the group is
/// unavailable (unit-test host, previews) — every accessor handles that.
enum V2GenIPC {
  static var containerURL: URL? {
    FileManager.default.containerURL(
      forSecurityApplicationGroupIdentifier: V2GenAppGroup.resolvedID
    )
  }

  static var commandURL: URL? { containerURL?.appendingPathComponent("tunnel-command.json") }
  static var statsURL: URL? { containerURL?.appendingPathComponent("tunnel-stats.json") }
}

// MARK: - App → Tunnel

/// What the app wants the tunnel to do. The whole payload rides one file so
/// a swap is atomic — the tunnel never sees a torn config.
struct V2GenTunnelCommand: Codable, Equatable {
  /// Monotonic id — the tunnel ignores stale reloads (an older file that
  /// lost a race with a newer write).
  var id: Int
  /// The RAW subscription link of the config to use, exactly as served by
  /// the panel (vless:// / vmess:// / ss:// / trojan://). The tunnel parses
  /// it itself so the wire format has exactly one decoder.
  var link: String
  /// The panel-accounting tag (config name) — echoed in stats so the app
  /// can show which member of the sub is live.
  var tag: String
}

// MARK: - Tunnel → App

struct V2GenTunnelStats: Codable, Equatable {
  /// Command id these stats belong to.
  var commandID: Int
  var tag: String
  /// Lifecycle of the data plane.
  var state: State
  /// Bytes tunnelled since the tunnel started (data plane only, not IPC).
  var bytesUp: Int
  var bytesDown: Int
  /// Live TCP flows right now (informational).
  var flows: Int
  /// Set when the active config keeps failing — grounds the app-side
  /// failover ladder in REAL dial outcomes from the user's traffic.
  var lastError: String?
  /// Wall clock of this snapshot (epoch seconds).
  var updatedAt: TimeInterval

  enum State: String, Codable {
    case starting      // TUN up, config dial pending
    case connected     // at least one outbound session established
    case failing       // dials keep failing
  }

  static func blank(commandID: Int, tag: String) -> V2GenTunnelStats {
    V2GenTunnelStats(
      commandID: commandID, tag: tag, state: .starting,
      bytesUp: 0, bytesDown: 0, flows: 0, lastError: nil,
      updatedAt: Date().timeIntervalSince1970
    )
  }
}

// MARK: - File helpers (both sides)

enum V2GenIPCFile {
  /// Atomically write a Codable to a URL. Returns false on any failure —
  /// callers treat IPC as best-effort and never crash the tunnel over it.
  @discardableResult
  static func write<T: Encodable>(_ value: T, to url: URL?) -> Bool {
    guard let url else { return false }
    guard let data = try? JSONEncoder().encode(value) else { return false }
    do {
      try data.write(to: url, options: .atomic)
      return true
    } catch {
      return false
    }
  }

  static func read<T: Decodable>(_ type: T.Type, from url: URL?) -> T? {
    guard let url, let data = try? Data(contentsOf: url) else { return nil }
    return try? JSONDecoder().decode(type, from: data)
  }
}

// MARK: - Darwin notifications (CFNotificationCenter, no dependencies)

enum V2GenDarwin {
  /// Post a Darwin notification. Safe from any thread/queue.
  static func post(_ name: String) {
    let center = CFNotificationCenterGetDarwinNotifyCenter()
    CFNotificationCenterPostNotification(
      center, CFNotificationName(name as CFString), nil, nil, true
    )
  }

  /// Observe a Darwin notification. `handler` fires on a CF internal queue —
  /// hop to your own queue from inside it. Keep the returned token alive to
  /// stay subscribed; drop it to unsubscribe.
  static func observe(
    _ name: String,
    handler: @escaping () -> Void
  ) -> DarwinObservationToken {
    DarwinObservationToken(name: name, handler: handler)
  }
}

/// One Darwin-notification subscription. `deinit` removes it.
final class DarwinObservationToken {
  private static let lock = NSLock()
  private static var registry: [UnsafeRawPointer: DarwinObservationToken] = [:]

  private let name: String
  private let handler: () -> Void

  fileprivate init(name: String, handler: @escaping () -> Void) {
    self.name = name
    self.handler = handler
    DarwinObservationToken.lock.lock()
    defer { DarwinObservationToken.lock.unlock() }
    DarwinObservationToken.registry[UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())] = self
    CFNotificationCenterAddObserver(
      CFNotificationCenterGetDarwinNotifyCenter(),
      Unmanaged.passUnretained(self).toOpaque(),
      { _, observer, _, _, _ in
        guard let observer else { return }
        let key = UnsafeRawPointer(observer)
        DarwinObservationToken.lock.lock()
        let token = DarwinObservationToken.registry[key]
        DarwinObservationToken.lock.unlock()
        token?.handler()
      },
      name as CFString,
      nil,
      .deliverImmediately
    )
  }

  deinit {
    DarwinObservationToken.lock.lock()
    DarwinObservationToken.registry[UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())] = nil
    DarwinObservationToken.lock.unlock()
    CFNotificationCenterRemoveObserver(
      CFNotificationCenterGetDarwinNotifyCenter(),
      Unmanaged.passUnretained(self).toOpaque(),
      CFNotificationName(name as CFString),
      nil
    )
  }
}
