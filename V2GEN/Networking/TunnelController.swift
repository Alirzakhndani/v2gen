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
    /// NEVPN 5 with the permission popup shown and dismissed without Allow
    /// (Don't Allow / passcode canceled) — iOS then caches the denial.
    case popupDenied
    /// The install carries no network-extension entitlement (a paid
    /// team's re-sign stripped it) — the popup can NEVER appear; reinstall
    /// with the entitlement kept.
    case notEntitled
    /// The install is signed by a FREE Apple ID — Apple never grants the
    /// network-extension entitlement to personal teams, so the VPN profile
    /// can NEVER be saved on this install. Only a different signing fixes
    /// it (paid team / a certificate that carries the entitlement).
    case freeAccountNoVPN

    var description: String {
      switch self {
      case .ipcUnavailable:
        return "App Group unavailable — reinstall the app profile"
      case .notEnabled:
        return "The VPN profile is not enabled in Settings"
      case .profileSaveFailed(let reason):
        return "VPN profile could not be saved — \(reason)"
      case .popupDenied:
        return "VPN permission popup was denied"
      case .notEntitled:
        return "App is signed without the network-extension entitlement"
      case .freeAccountNoVPN:
        return "App is signed with a free Apple ID — VPN can never be granted"
      }
    }

    /// Can retry/reset actually change the outcome? A free-Apple-ID install
    /// can NEVER be fixed from inside the app (Apple does not grant the
    /// entitlement) — the recovery buttons are hidden for it so the user
    /// is not sent into a futile retry loop.
    var fixableByRetry: Bool {
      if case .freeAccountNoVPN = self { return false }
      return true
    }

    /// Honest, actionable Persian for the UI (each failure mode gets its
    /// own fix instead of one misleading generic message).
    var userMessage: String {
      switch self {
      case .ipcUnavailable:
        return "App Group در دسترس نیست — اپ را با Sideloadly (App Groups فعال) یا AltStore دوباره نصب کنید"
      case .notEnabled:
        return "پروفایل VPN در تنظیمات غیرفعال است — تنظیمات ← VPN ← V2GEN را روشن کنید"
      case .profileSaveFailed(let reason):
        // The raw iOS error rides along (clipped) — it is the ONLY way to
        // tell a denied popup from a missing network-extension entitlement
        // (a signing problem) from the app side.
        let clipped = reason.count > 110 ? String(reason.prefix(110)) + "…" : reason
        return "پروفایل VPN ذخیره نشد — پاپ‌آپ «Add VPN Configuration» را Allow کنید. "
          + "اگر پاپ‌آپ نیامد، اپ با دسترسی VPN امضا نشده است. (\(clipped))"
      case .popupDenied:
        return "اجازهٔ ساخت VPN رد شده است — اپ را کامل ببندید (App Switcher) و دوباره باز کنید؛ "
          + "این بار پاپ‌آپ «Add VPN Configuration» را Allow و رمز گوشی را بزنید. "
          + "اگر پاپ‌آپ دوباره نیامد: «بازنشانی پروفایل» را بزنید و در صورت نیاز موقتاً پاس‌کد گوشی را خاموش کنید"
      case .notEntitled:
        return "این نصب اپ، دسترسی VPN ندارد (هنگام امضا حذف شده) — اپ را کامل پاک کنید؛ "
          + "در Sideloadly بخش Advanced گزینه‌های «Keep entitlements» و «App Groups» را روشن کنید "
          + "و دوباره نصب کنید؛ هنگام اولین باز شدن اپ، پاپ‌آپ Allow را حتماً تأیید کنید"
      case .freeAccountNoVPN:
        return "این نصب با Apple ID رایگان امضا شده — اپل به اکانت رایگان هرگز اجازهٔ ساخت VPN "
          + "نمی‌دهد؛ پس پروفایل VPN روی این نصب ساخته نمی‌شود و مشکل از اپ هم نیست. "
          + "راه‌حل: با «اکانت توسعه‌دهندهٔ پولی Apple» (۹۹ دلار در سال، تا ۱۰۰ دستگاه) "
          + "یا «سرتیفیکیت امضاییِ دارای دسترسی VPN» دوباره نصب کنید — "
          + "آن‌وقت پاپ‌آپ «Add VPN Configuration» می‌آید و همه‌چیز کار می‌کند"
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

  /// Remove the saved profile entirely, then re-create it from scratch.
  /// Remove + re-add is the strongest re-prompt path iOS offers: a
  /// brand-new save presents the "Add VPN Configuration" permission prompt
  /// again even after an earlier "Don't Allow" (a plain re-save does not
  /// reliably), and it also clears a half-broken profile state.
  static func resetProfile() async throws {
    manager = nil
    prepared = false
    _ = try await rebuildFromScratch(command: nil)
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
    let m = try await loadOrReuseManager()
    let wasReused = m.localizedDescription != nil   // loaded from Preferences
    configure(m, command: command)

    // Idempotent prepare: a profile that already exists, is enabled and
    // carries a configuration needs NO save — every redundant save is
    // another chance to trip iOS's cached-denial (NEVPN 5) or surprise the
    // user with a permission popup at a random moment. Only create/change
    // paths touch saveToPreferences.
    if command == nil, m.isEnabled, profileLooksReady(m) {
      manager = m
      prepared = true
      return m
    }

    do {
      try await saveClassified(m)
    } catch {
      // Self-heal (one shot): a save on a REUSED profile failing is the
      // classic orphan — a leftover profile from a PREVIOUS install whose
      // signing no longer matches this one. Remove + a brand-new manager
      // re-presents the permission popup and clears the broken state.
      // (Never while connected — that would kill a live session for nothing.
      // When the heal ALSO fails, its fresh-manager verdict is the honest
      // error to surface.)
      if wasReused, m.connection.status != .connected {
        return try await rebuildFromScratch(command: command)
      }
      throw error
    }
    // Apple quirk: re-load after the save, or the tunnel may fail to
    // start with "no protocol found".
    try await m.loadFromPreferences()

    manager = m
    prepared = true
    return m
  }

  /// Load the saved profile (reusing the cached instance when prepared) or
  /// start a brand-new manager. `nil` localizedDescription marks a fresh one.
  private static func loadOrReuseManager() async throws -> NETunnelProviderManager {
    if prepared, let manager {
      // Re-load so a profile removed in Settings is detected honestly.
      try await manager.loadFromPreferences()
      return manager
    }
    let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
    if let existing = managers.first(where: {
      ($0.protocolConfiguration as? NETunnelProviderProtocol)?
        .providerBundleIdentifier == tunnelBundleID
    }) {
      return existing
    }
    return NETunnelProviderManager()
  }

  private static func configure(
    _ m: NETunnelProviderManager, command: V2GenTunnelCommand?
  ) {
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
  }

  /// Does the loaded profile already carry everything a cold start needs?
  private static func profileLooksReady(_ m: NETunnelProviderManager) -> Bool {
    guard let proto = m.protocolConfiguration as? NETunnelProviderProtocol else {
      return false
    }
    return proto.providerBundleIdentifier == tunnelBundleID
      && proto.providerConfiguration != nil
  }

  /// saveToPreferences with honest failure classification (NEVPN code 5):
  ///   · FREE personal team (profile TTL ≤ 14 days) → Apple never grants
  ///     the network-extension entitlement to free accounts — a reinstall
  ///     can NEVER fix it; only a different signing can. Say exactly that.
  ///   · entitlement missing from a paid team's embedded profile → the
  ///     popup can never come — a reinstall is the ONLY fix (Sideloadly:
  ///     Keep entitlements + App Groups).
  ///   · otherwise the popup WAS shown (or a previous denial is cached) →
  ///     restart the app / reset the profile; no reinstall needed.
  /// Timing is the tie-breaker when no profile is embedded (App Store
  /// builds): an instant code-5 means no popup was ever attempted.
  private static func saveClassified(_ m: NETunnelProviderManager) async throws {
    let t0 = Date()
    do {
      try await m.saveToPreferences()
    } catch {
      let raw = String(describing: error)
      let elapsed = Date().timeIntervalSince(t0)
      let isPermissionDenied = raw.contains("Code=5")
        || raw.contains("permission denied")
        || (error as? NSError)?.code == 5
      guard isPermissionDenied else {
        // Entitlement/stripped-signing failures land here — surface them
        // as their own error instead of a misleading "permission denied".
        throw TunnelError.profileSaveFailed(raw)
      }
      switch SigningDiagnostics.networkExtensionGranted {
      case .some(false):
        // Free personal team (profile TTL ≤ 14 days)? Apple NEVER grants
        // the network-extension entitlement to free accounts and no
        // Sideloadly option changes that — the honest verdict names the
        // real cure instead of a futile reinstall loop.
        if SigningDiagnostics.isFreePersonalTeam == true {
          throw TunnelError.freeAccountNoVPN
        }
        throw TunnelError.notEntitled
      case .some(true):
        // Entitlement IS in the profile → the popup was shown and answered
        // with Don't Allow (or an earlier denial is still cached).
        throw TunnelError.popupDenied
      case .none:
        // No embedded profile (store distribution) — timing decides:
        // a save that fails in under ~2 s never displayed a popup.
        throw elapsed < 2 ? TunnelError.notEntitled : TunnelError.popupDenied
      }
    }
  }

  /// Remove every profile of ours, then build a brand-new one. The fresh
  /// save's classified error propagates — the caller surfaces the verdict.
  private static func rebuildFromScratch(
    command: V2GenTunnelCommand?
  ) async throws -> NETunnelProviderManager {
    let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
    for m in managers
    where (m.protocolConfiguration as? NETunnelProviderProtocol)?
      .providerBundleIdentifier == tunnelBundleID {
      try? await m.removeFromPreferences()
    }
    manager = nil
    prepared = false
    let fresh = NETunnelProviderManager()
    configure(fresh, command: command)
    try await saveClassified(fresh)
    try? await fresh.loadFromPreferences()
    manager = fresh
    prepared = true
    return fresh
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
