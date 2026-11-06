import Foundation
import Security

// ── Keychain — credentials live in the iOS Keychain, not a file ───────────
// The web app kept its session in localStorage; the native equivalent is a
// generic-password item. No entitlements needed, wiped with the app.

enum KeychainStore {
  private static let service = "xyz.v2gen.app"
  private static let account = "panel-client"

  static func saveClient(_ client: PanelClient) {
    guard let data = try? JSONEncoder.v2.encode(client) else { return }
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
    let attributes: [String: Any] = [kSecValueData as String: data]
    let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    guard status == errSecItemNotFound else { return }
    var add = query
    add[kSecValueData as String] = data
    SecItemAdd(add as CFDictionary, nil)
  }

  static func loadClient() -> PanelClient? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: AnyObject?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
          let data = result as? Data,
          let client = try? JSONDecoder.v2.decode(PanelClient.self, from: data)
    else { return nil }
    return client
  }

  static func clearClient() {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
    SecItemDelete(query as CFDictionary)
  }
}
