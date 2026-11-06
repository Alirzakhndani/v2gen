import Foundation
import NetworkExtension

// ── Tunnel controller (app side) ──────────────────────────────────────────
// Owns the system VPN profile (NETunnelProviderManager) and the IPC files.
// The UI never touches NetworkExtension — AppModel drives this, keeping the
// frozen design completely untouched.

@MainActor
enum TunnelController {

  enum TunnelError: Error, CustomStringConvertible {
    case ipcUnavailable
    case notEnabled

    var description: String {
      switch self {
      case .ipcUnavailable:
        return "App Group unavailable — reinstall the app profile"
      case .notEnabled:
        return "The VPN profile is not enabled in Settings"
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

  // MARK: - Start / stop / swap

  /// Write the command file and bring the tunnel up.
  static func start(command: V2GenTunnelCommand) async throws {
    guard V2GenIPCFile.write(command, to: V2GenIPC.commandURL) else {
      throw TunnelError.ipcUnavailable
    }
    // Drop stale stats from a previous run so the app never adopts them.
    if let statsURL = V2GenIPC.statsURL {
      try? FileManager.default.removeItem(at: statsURL)
    }
    let m = try await prepareManager()
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

  nonisolated static func readStats() -> V2GenTunnelStats? {
    V2GenIPCFile.read(V2GenTunnelStats.self, from: V2GenIPC.statsURL)
  }

  // MARK: - Profile preparation

  private static func prepareManager() async throws -> NETunnelProviderManager {
    if prepared, let manager {
      // Re-load so a profile removed in Settings is detected honestly.
      try await manager.loadFromPreferences()
      if !manager.isEnabled {
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
      }
      return manager
    }

    let managers: [NETunnelProviderManager]
    do {
      managers = try await NETunnelProviderManager.loadAllFromPreferences()
    } catch {
      managers = []
    }
    let m = managers.first {
      ($0.protocolConfiguration as? NETunnelProviderProtocol)?
        .providerBundleIdentifier == tunnelBundleID
    } ?? NETunnelProviderManager()

    m.localizedDescription = "V2GEN"
    let proto = NETunnelProviderProtocol()
    proto.providerBundleIdentifier = tunnelBundleID
    proto.serverAddress = "V2GEN"
    proto.providerConfiguration = ["group": V2GenAppGroup.resolvedID]
    m.protocolConfiguration = proto
    m.isEnabled = true
    m.isOnDemandEnabled = false
    m.onDemandRules = []

    try await m.saveToPreferences()
    // Apple quirk: re-load after the first save, or the tunnel may fail to
    // start with "no protocol found".
    try await m.loadFromPreferences()

    manager = m
    prepared = true
    return m
  }
}
