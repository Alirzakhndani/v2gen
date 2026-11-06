import Foundation
import NetworkExtension

// ── Tunnel controller (app side) ──────────────────────────────────────────
// Owns the system VPN profile (NETunnelProviderManager) and the IPC files.
// The UI never touches NetworkExtension — AppModel drives this, keeping the
// frozen design completely untouched.
//
// Transport belt & braces: the command rides BOTH the App Group file (hot
// path, enables hot-swap + stats) AND the profile's providerConfiguration
// (cold path — survives signers that did not provision the App Group and
// on-demand restarts while the app is suspended). The tunnel reads the file
// first, the profile second.

@MainActor
enum TunnelController {

  enum TunnelError: Error, CustomStringConvertible {
    case ipcUnavailable
    case notEnabled
    case profileSaveFailed(String)

    var description: String {
      switch self {
      case .ipcUnavailable:
        return "App Group unavailable — reinstall the app profile"
      case .notEnabled:
        return "The VPN profile is not enabled in Settings"
      case .profileSaveFailed(let reason):
        return "VPN profile could not be saved — \(reason)"
      }
    }

    /// Honest, actionable Persian for the UI (each failure mode gets its
    /// own fix instead of one misleading generic message).
    var userMessage: String {
      switch self {
      case .ipcUnavailable:
        return "App Group در دسترس نیست — اپ را با Sideloadly (App Groups فعال) یا AltStore دوباره نصب کنید"
      case .notEnabled:
        return "پروفایل VPN در تنظیمات غیرفعال است — تنظیمات ← VPN ← V2GEN را روشن کنید"
      case .profileSaveFailed:
        return "اجازهٔ VPN داده نشد — پاپ‌آپ اجازه را Allow کنید یا از تنظیمات ← VPN فعال کنید"
      }
    }
  }

  /// Must match PRODUCT_BUNDLE_IDENTIFIER of the V2GEN-Tunnel target.
  /// Derived from the (possibly re-signed) main bundle id so free-signing
  /// tools (Sideloadly/AltStore/Xcode personal teams) that rename bundles
  /// keep the app→extension reference intact.
  static var tunnelBundleID: String {
    (Bundle.main.bundleIdentifier ?? "xyz.v2gen.app") + ".tunnel"
  }

  private static var manager: NETunnelProviderManager?
  private static var prepared = false

  // MARK: - Early profile preparation

  /// Create/refresh the VPN profile WITHOUT starting a tunnel. Called the
  /// moment the app has a signed-in user, so the iOS permission popup
  /// ("Would Like to Add VPN Configurations") and the Settings ← VPN row
  /// appear LONG before the first connect — a profile that exists early
  /// makes every later failure mode obvious instead of silent.
  static func prepare() async throws {
    _ = try await prepareManager()
  }

  /// Reflect the Stable Connect / Kill Switch toggles on the SAVED profile
  /// (on-demand rules) without touching a running tunnel.
  static func applyOnDemandRules(stableConnect: Bool, killSwitch: Bool) async {
    guard let m = try? await prepareManager() else { return }
    setOnDemand(on: m, stableConnect: stableConnect, killSwitch: killSwitch)
    try? await m.saveToPreferences()
    try? await m.loadFromPreferences()
  }

  // MARK: - Start / stop / swap

  /// Write the command file (best-effort — see providerConfiguration note
  /// above) and bring the tunnel up.
  static func start(command: V2GenTunnelCommand) async throws {
    // Best-effort IPC write: with a missing App Group the command still
    // reaches the tunnel through providerConfiguration (below). Stats and
    // hot-swap degrade gracefully instead of the connect dying here.
    V2GenIPCFile.write(command, to: V2GenIPC.commandURL)
    // Drop stale stats from a previous run so the app never adopts them.
    if let statsURL = V2GenIPC.statsURL {
      try? FileManager.default.removeItem(at: statsURL)
    }
    let m = try await prepareManager(command: command)
    try m.connection.startVPNTunnel()
  }

  /// Hot-swap the active config in a RUNNING tunnel (Darwin notification —
  /// the TUN stays up, live flows drain through their old connections).
  nonisolated static func swap(command: V2GenTunnelCommand) {
    guard V2GenIPCFile.write(command, to: V2GenIPC.commandURL) else { return }
    V2GenDarwin.post(V2GenNotifyReload)
  }

  static func stop() async {
    manager?.connection.stopVPNTunnel()
  }

  /// USER-initiated disconnect: with on-demand rules active (Stable
  /// Connect / Kill Switch), a plain stopVPNTunnel is overridden by iOS —
  /// the tunnel would come right back. Disable on-demand first, then stop.
  /// The next connect() re-enables the rules via prepareManager/apply.
  static func userStop() async {
    if prepared || manager != nil {
      if let m = try? await prepareManager() {
        m.isOnDemandEnabled = false
        m.onDemandRules = []
        try? await m.saveToPreferences()
        try? await m.loadFromPreferences()
      }
    }
    manager?.connection.stopVPNTunnel()
  }

  nonisolated static func readStats() -> V2GenTunnelStats? {
    V2GenIPCFile.read(V2GenTunnelStats.self, from: V2GenIPC.statsURL)
  }

  /// Is the TUN's fake gateway (198.18.0.1) on ANY interface right now?
  /// A dependency-free "routes are installed" signal — the honest
  /// verification fallback when the App Group (and with it the engine's
  /// byte counters) is unavailable.
  nonisolated static func tunAddressPresent() -> Bool {
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return false }
    defer { freeifaddrs(ifaddr) }
    var ptr: UnsafeMutablePointer<ifaddrs>? = first
    while let current = ptr {
      defer { ptr = current.pointee.ifa_next }
      guard let sa = current.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else {
        continue
      }
      var addr = sockaddr_in()
      memcpy(&addr, sa, MemoryLayout<sockaddr_in>.size)
      // Both sides are in network byte order — the comparison is exact.
      if addr.sin_addr.s_addr == inet_addr("198.18.0.1") { return true }
    }
    return false
  }

  // MARK: - Profile preparation

  private static func prepareManager(
    command: V2GenTunnelCommand? = nil
  ) async throws -> NETunnelProviderManager {
    var m: NETunnelProviderManager
    if prepared, let manager {
      // Re-load so a profile removed in Settings is detected honestly.
      try await manager.loadFromPreferences()
      m = manager
    } else {
      let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
      m = managers.first {
        ($0.protocolConfiguration as? NETunnelProviderProtocol)?
          .providerBundleIdentifier == tunnelBundleID
      } ?? NETunnelProviderManager()
    }

    m.localizedDescription = "V2GEN"
    let proto = (m.protocolConfiguration as? NETunnelProviderProtocol)
      ?? NETunnelProviderProtocol()
    proto.providerBundleIdentifier = tunnelBundleID
    proto.serverAddress = "V2GEN"
    // Always ride the LATEST command inside the profile — on-demand
    // restarts (app suspended) reload the tunnel from here, not from the
    // App Group file.
    if let command {
      proto.providerConfiguration = command.asProviderConfiguration
    } else if proto.providerConfiguration == nil {
      proto.providerConfiguration = ["group": V2GenAppGroup.resolvedID]
    }
    m.protocolConfiguration = proto
    if !m.isEnabled {
      m.isEnabled = true
    }

    do {
      try await m.saveToPreferences()
    } catch {
      // Entitlement/stripped-signing failures land here — surface them as
      // their own error instead of a misleading "permission not granted".
      throw TunnelError.profileSaveFailed(String(describing: error))
    }
    // Apple quirk: re-load after the save, or the tunnel may fail to
    // start with "no protocol found".
    try await m.loadFromPreferences()

    manager = m
    prepared = true
    return m
  }

  // MARK: - On-demand (Stable Connect / Kill Switch)

  /// On-demand is iOS's native always-reconnect: the system re-starts the
  /// tunnel the instant any interface comes up — in the background, without
  /// the app, faster than any app-level retry loop could. Kill Switch rides
  /// the same rules (it must never stay down) but the fail-closed half
  /// lives in TunnelProvider (TUN stays up, traffic blackholed).
  private static func setOnDemand(
    on m: NETunnelProviderManager,
    stableConnect: Bool,
    killSwitch: Bool
  ) {
    if stableConnect || killSwitch {
      let rule = NEOnDemandRuleConnect()
      rule.interfaceTypeMatch = .any
      m.onDemandRules = [rule]
      m.isOnDemandEnabled = true
      // (Sleep is covered too: the always-connect rule re-establishes the
      // tunnel on wake — on-demand rules apply across the lock screen.)
    } else {
      m.isOnDemandEnabled = false
      m.onDemandRules = []
    }
  }
}
