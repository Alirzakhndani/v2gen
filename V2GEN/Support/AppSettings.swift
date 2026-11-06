import Foundation

// ── User connection preferences ───────────────────────────────────────────
// UserDefaults-backed toggles (Settings sheet). The tunnel reads them as
// flags on every V2GenTunnelCommand; the VPN profile's on-demand rules are
// refreshed through TunnelController whenever they change.

enum AppSettings {
  private static let stableKey = "v2gen.stableConnect"
  private static let killKey = "v2gen.killSwitch"

  /// Stable Connect: ranked failover links ride every command, the tunnel
  /// rotates configs by itself in the background, and the VPN profile gets
  /// always-connect on-demand rules (iOS re-starts the tunnel the instant
  /// any interface comes up — without the app).
  static var stableConnect: Bool {
    get { UserDefaults.standard.bool(forKey: stableKey) }
    set { UserDefaults.standard.set(newValue, forKey: stableKey) }
  }

  /// Kill Switch: fail-closed. The TUN stays up and blackholes ALL traffic
  /// while no config works (never falls back to the physical interface),
  /// plus the same always-reconnect on-demand rules as Stable Connect.
  static var killSwitch: Bool {
    get { UserDefaults.standard.bool(forKey: killKey) }
    set { UserDefaults.standard.set(newValue, forKey: killKey) }
  }
}
