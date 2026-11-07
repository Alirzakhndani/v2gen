import Foundation

// ── What did the side-loader actually grant THIS install? ─────────────────
// NEVPN error 5 ("permission denied") has THREE distinct cures, and the
// honest one depends on the signing ACCOUNT TYPE:
//   · the user dismissed the permission popup  → restart the app / reset
//   · a PAID team's profile simply lacks the network-extension entitlement
//     (Sideloadly without "Keep entitlements") → reinstall with it kept
//   · a FREE Apple ID — Apple NEVER grants the network-extension
//     entitlement to personal teams; no Sideloadly option can change it.
//     VPN on this install is IMPOSSIBLE, and the honest verdict says so.
// The ONLY reliable ground truth from inside the app is the embedded
// provisioning profile a side-loader (Sideloadly/AltStore/Xcode) always
// installs next to the binary: its Entitlements dictionary is what iOS
// actually granted, and its TimeToLive betrays the account type (free
// personal-team profiles live ≤ 7 days; paid development/ad-hoc/enterprise
// profiles ~ 1 year). App Store / TestFlight builds carry no profile —
// those are always entitled, so the caller falls back to save timing.

nonisolated enum SigningDiagnostics {

  // MARK: - Profile parsing

  /// The embedded provisioning profile's plist, or nil when this install
  /// carries no profile (store distribution) or it can't be parsed.
  static var profilePlist: [String: Any]? {
    guard
      let url = Bundle.main.url(
        forResource: "embedded", withExtension: "mobileprovision"
      ),
      let raw = try? Data(contentsOf: url)
    else { return nil }
    // The profile is a CMS envelope; the XML plist rides inside verbatim —
    // scan for it directly (the classic side-loader parsing trick).
    guard
      let start = raw.range(of: Data("<?xml".utf8)),
      let end = raw.range(
        of: Data("</plist>".utf8),
        options: .backwards,
        in: start.upperBound..<raw.endIndex
      )
    else { return nil }
    let plistData = raw[start.lowerBound..<end.upperBound]
    return try? PropertyListSerialization.propertyList(
      from: plistData, options: [], format: nil
    ) as? [String: Any]
  }

  /// Entitlements granted by the embedded provisioning profile of THIS
  /// install. nil when no profile exists (store distribution).
  static var profileEntitlements: [String: Any]? {
    profilePlist?["Entitlements"] as? [String: Any]
  }

  /// Does this install carry the packet-tunnel entitlement?
  ///   true  → granted (a save failure is then a user/permission problem)
  ///   false → NOT granted — free account or a stripped re-sign
  ///   nil   → no profile to read (store distribution) — timing decides
  static var networkExtensionGranted: Bool? {
    guard let ents = profileEntitlements else { return nil }
    guard let ne = ents["com.apple.developer.networking.network-extension"] else {
      return false
    }
    if let list = ne as? [String] {
      return list.contains("packet-tunnel-provider")
    }
    if let flag = ne as? Bool { return flag }
    return true
  }

  /// Days the provisioning profile stays valid. Free personal-team
  /// profiles are ≤ 7 days; paid development/ad-hoc/enterprise ~ 365.
  static var profileTimeToLive: Int? {
    guard let plist = profilePlist else { return nil }
    if let n = plist["TimeToLive"] as? NSNumber { return n.intValue }
    if let s = plist["TimeToLive"] as? String { return Int(s) }
    return nil
  }

  /// Is THIS install signed by a FREE personal team? Apple never grants
  /// the network-extension entitlement to free accounts — when this is
  /// true, no reinstall or Sideloadly option can ever make the VPN work;
  /// only signing with a paid team (or a certificate that carries the
  /// entitlement) can. nil when no profile is embedded (store
  /// distribution — those are always entitled).
  static var isFreePersonalTeam: Bool? {
    guard let ttl = profileTimeToLive else { return nil }
    return ttl <= 14
  }

  /// Human-readable dump for logs/debug rows.
  static var summary: String {
    guard let plist = profilePlist else { return "no embedded profile" }
    let keys = (plist["Entitlements"] as? [String: Any])?
      .keys.sorted().joined(separator: ", ") ?? "no entitlements"
    let ttl = profileTimeToLive.map { " · ttl \($0)d" } ?? ""
    return "granted: \(keys)\(ttl)"
  }
}
