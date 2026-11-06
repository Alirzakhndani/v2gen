import Foundation

// ── What did the side-loader actually grant THIS install? ─────────────────
// NEVPN error 5 ("permission denied") has two completely different cures:
//   · the user dismissed the permission popup  → restart the app / reset
//   · the re-signer stripped the network-extension entitlement (Sideloadly
//     without "Keep entitlements") → NO popup can ever appear; reinstall
// The ONLY reliable way to tell them apart from inside the app is the
// embedded provisioning profile a side-loader (Sideloadly/AltStore/Xcode)
// always installs next to the binary: its Entitlements dictionary is what
// iOS actually granted. App Store / TestFlight builds carry no profile —
// those are always entitled, so the caller falls back to save timing.

nonisolated enum SigningDiagnostics {

  /// Entitlements granted by the embedded provisioning profile of THIS
  /// install. nil when no profile exists (store distribution).
  static var profileEntitlements: [String: Any]? {
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
    guard
      let plist = try? PropertyListSerialization.propertyList(
        from: plistData, options: [], format: nil
      ) as? [String: Any]
    else { return nil }
    return plist["Entitlements"] as? [String: Any]
  }

  /// Does this install carry the packet-tunnel entitlement?
  ///   true  → granted (a save failure is then a user/permission problem)
  ///   false → STRIPPED by the re-signer — reinstall is the only fix
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

  /// Human-readable dump for logs/debug rows.
  static var summary: String {
    guard let ents = profileEntitlements else { return "no embedded profile" }
    let keys = ents.keys.sorted().joined(separator: ", ")
    return "granted: \(keys)"
  }
}
