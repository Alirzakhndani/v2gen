import Foundation

// ── Formatting helpers (iOS style, mirrors the web format.ts) ─────────────

enum ByteFormat {
  static func humanBytes(_ bytes: Int) -> String {
    guard bytes >= 1024 else { return "Zero KB" }
    let kb = Double(bytes) / 1024
    if kb < 1024 {
      return kb < 10 ? String(format: "%.1f KB", kb) : "\(Int(kb.rounded())) KB"
    }
    let mb = kb / 1024
    if mb < 1024 {
      return mb < 100
        ? String(format: "%.1f MB", mb)
        : "\(Int(mb.rounded())) MB"
    }
    let gb = mb / 1024
    return gb < 10 ? String(format: "%.1f GB", gb) : "\(Int(gb.rounded())) GB"
  }

  static func daysLeft(_ expireAt: Date?) -> Int? {
    guard let expireAt else { return nil }
    let days = Calendar.current.dateComponents(
      [.day], from: Date(), to: expireAt
    ).day ?? 0
    return max(0, days + 1)   // ceil, like the web app
  }

  static func remainingBytes(used: Int, limit: Int) -> Int? {
    limit == 0 ? nil : max(0, limit - used)   // 0 = unlimited
  }

  // ── Persian keyboard contamination — deterministic fix (code's job) ──
  // Typing a Latin username on a Persian keyboard yields Persian/Arabic
  // digits (user۱۲), Arabic yeh/kaf (ي/ك), and invisible marks (ZWNJ, bidi).
  // Exact-match auth then fails mysteriously. A char map fixes it — applied
  // to the USERNAME only: it is visible in the field, and panel usernames
  // are overwhelmingly Latin. Passwords are never rewritten.

  private static let charFixes: [Character: String] = {
    var map: [Character: String] = [:]
    let persianDigits = Array("۰۱۲۳۴۵۶۷۸۹")
    let arabicDigits = Array("٠١٢٣٤٥٦٧٨٩")
    let latin = Array("0123456789")
    for i in 0..<10 {
      map[persianDigits[i]] = String(latin[i])
      map[arabicDigits[i]] = String(latin[i])
    }
    map["ي"] = "ی"   // Arabic yeh → Persian yeh
    map["ك"] = "ک"   // Arabic kaf → Persian kaf
    map["\u{200C}"] = ""   // ZWNJ
    map["\u{200B}"] = ""   // ZWSP
    map["\u{200E}"] = ""   // LRM
    map["\u{200F}"] = ""   // RLM
    return map
  }()

  static func normalizePersianInput(_ s: String) -> String {
    String(s.map { charFixes[$0] ?? String($0) }.joined())
  }
}
