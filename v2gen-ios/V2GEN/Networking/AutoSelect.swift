import Foundation

// ── Lantern MutableAutoSelect — full port ──────────────────────────────────
// Source of truth: docs/worklog/lantern-analysis.md §6 (lantern-box fork:
// mutableautoselect.go, mutableautoselect_history.go, _probe.go). Parameter
// names and semantics follow the Go original; every divergence is called
// out at the decision point.
//
//   rankLocked      → ranked(at:)            tier → gated → delay
//   demoted()       → tier(_:at:)            soft/hard via windows + limits
//   applyStickiness → shouldSwitchCurrent    300 ms AND 30 % — both required
//   beatsOnDelay    →   (inside the above)
//   splitHealthy    → ranked(at:) ordering   gated members only as fallback
//   recovery gate   → gatedUntil/gateNeedsProbe   5 min + one success
//   switch penalty  → tier(_:at:)            alt > 3× slower → hard limit ×2
//   TagHistory      → Persisted / hydrate    15-min max age
//
// One honest divergence, documented in place: this build has no real data
// plane yet (traffic is simulated until the NetworkExtension milestone),
// so the current member's probe failure doubles as the user-path failure
// signal. Lantern's probe/user separation becomes meaningful the day real
// traffic flows through the winner.
//
// Pure value type: AppModel owns the single instance on the main actor;
// all network I/O happens in Racer (nonisolated). Nothing here touches
// the network or the clock directly — every mutation takes `now`.

struct AutoSelectState: Sendable {

  // ── Lantern parameters (mutableautoselect*.go defaults) ─────────────────
  static let switchToleranceMS = 300                    // absolute gain required
  static let switchToleranceRatio = 0.3                 // relative gain required
  static let consecutiveFailLimit = 3                   // probe failures → hard
  static let softFailLimit = 2                          // user failures in window → soft
  static let hardUserFailLimit = 3                      // user failures in window → hard
  static let userFailureWindow: TimeInterval = 300      // 5 min sliding window
  static let userFailureDedupeWindow: TimeInterval = 45 // 45 s dedupe
  static let switchPenaltyAltFactor = 3.0               // alt > 3× slower → hard limit ×2
  static let recoveryGateDuration: TimeInterval = 300   // 5 min + one success
  static let probeFreshnessWindow: TimeInterval = 30    // skip re-probing fresh results
  static let ladderCooldown: TimeInterval = 60
  static let ladderTotalBudget: TimeInterval = 10
  static let exhaustionRefetchGate: TimeInterval = 60
  static let confirmedSwitchCooldown: TimeInterval = 60
  static let maxPersistedAge: TimeInterval = 900        // 15 min

  // ── Model ────────────────────────────────────────────────────────────────

  enum Tier: Int, Comparable {
    case clean = 0, soft = 1, hard = 2
    static func < (lhs: Tier, rhs: Tier) -> Bool { lhs.rawValue < rhs.rawValue }
  }

  struct Member: Sendable {
    var config: ParsedConfig
    /// Last successful probe RTT. A probe failure NEVER clears this
    /// (Lantern keeps lastSuccessDelayMs across probe failures).
    var lastSuccessDelayMs: Int? = nil
    /// Whether the member's most recent probe succeeded. A stale delay
    /// from before a recent failure must not drive a switch decision —
    /// Lantern's sticky switching compares live probe data. Not
    /// persisted: a hydrated member starts "unproven" (conservative).
    var lastProbeSucceeded = false
    var consecutiveFailures = 0
    /// User-path failures inside the sliding window (Lantern userFailures).
    var userFailures: [Date] = []
    /// 45 s dedupe anchor for user failures.
    var lastUserFailureAt: Date? = nil
    /// Recovery gate: not selectable until the window passes AND one
    /// successful probe lands (gateNeedsProbe).
    var gatedUntil: Date? = nil
    var gateNeedsProbe = false
    var lastProbeAt: Date? = nil
  }

  private(set) var members: [Member] = []
  private(set) var currentTag: String?

  // ── Construction ─────────────────────────────────────────────────────────

  init(configs: [ParsedConfig]) {
    members = configs.map { Member(config: $0) }
  }

  /// Lantern hydrates TagHistory after a restart — but only history
  /// younger than maxPersistedAge (15 min); older state is discarded.
  init(restoring saved: Persisted, configs: [ParsedConfig], now: Date = .init()) {
    guard now.timeIntervalSince(saved.updatedAt) < Self.maxPersistedAge else {
      self.init(configs: configs)
      return
    }
    let byTag = Dictionary(saved.members.map { ($0.tag, $0) },
                           uniquingKeysWith: { first, _ in first })
    members = configs.map { cfg in
      var m = Member(config: cfg)
      if let p = byTag[cfg.id] {
        m.lastSuccessDelayMs = p.lastSuccessDelayMs
        m.consecutiveFailures = p.consecutiveFailures
        m.userFailures = p.userFailures
          .filter { now.timeIntervalSince($0) < Self.userFailureWindow }
        m.gatedUntil = p.gatedUntil
        m.gateNeedsProbe = p.gateNeedsProbe
      }
      return m
    }
  }

  /// Rebase onto a fresh pool after a sub refetch, carrying history over
  /// for surviving members (Lantern updateServers: list diff, evict gone,
  /// add new). New members start cold.
  init(configs: [ParsedConfig], carryingOver previous: AutoSelectState) {
    let byTag = Dictionary(previous.members.map { ($0.config.id, $0) },
                           uniquingKeysWith: { first, _ in first })
    members = configs.map { cfg in byTag[cfg.id] ?? Member(config: cfg) }
    currentTag = previous.currentTag
  }

  // ── Ingest (probe results) ───────────────────────────────────────────────

  /// Record a batch of probe results. Success resets the failure streak
  /// and (after the gate window) releases the recovery gate. Failure
  /// grows the streak but never clears lastSuccessDelayMs.
  mutating func ingest(_ results: [ProbeResult], at now: Date = .init()) {
    for r in results {
      guard let i = members.firstIndex(where: { $0.config.id == r.config.id }) else { continue }
      members[i].lastProbeAt = now
      members[i].lastProbeSucceeded = r.rttMs != nil
      if let ms = r.rttMs {
        members[i].lastSuccessDelayMs = ms
        members[i].consecutiveFailures = 0
        if members[i].gateNeedsProbe,
           let until = members[i].gatedUntil, now >= until {
          members[i].gatedUntil = nil
          members[i].gateNeedsProbe = false
        }
      } else {
        members[i].consecutiveFailures += 1
      }
    }
  }

  /// Lantern recordUserFailure — the user's traffic through the member
  /// failed (dial / stall / reset / no_response there). Here the signal
  /// source is the current member's failed probe (see header note); the
  /// 45 s dedupe keeps the accounting rate honest either way.
  mutating func recordUserFailure(tag: String, at now: Date = .init()) {
    guard let i = members.firstIndex(where: { $0.config.id == tag }) else { return }
    if let last = members[i].lastUserFailureAt,
       now.timeIntervalSince(last) < Self.userFailureDedupeWindow { return }
    members[i].lastUserFailureAt = now
    members[i].userFailures.append(now)
    members[i].userFailures.removeAll {
      now.timeIntervalSince($0) >= Self.userFailureWindow
    }
  }

  // ── Tiers (Lantern demoted()) ────────────────────────────────────────────

  func tier(_ member: Member, at now: Date = .init()) -> Tier {
    let userFails = member.userFailures
      .filter { now.timeIntervalSince($0) < Self.userFailureWindow }
      .count
    var hardLimit = Self.consecutiveFailLimit
    // Switch penalty: demoting the current member to a > 3× slower
    // alternative demands more evidence — its hard limit doubles.
    if let own = member.lastSuccessDelayMs,
       let alt = bestAlternativeDelay(excluding: member.config.id),
       Double(alt) > Self.switchPenaltyAltFactor * Double(own) {
      hardLimit *= 2
    }
    if member.consecutiveFailures >= hardLimit || userFails >= Self.hardUserFailLimit {
      return .hard
    }
    if userFails >= Self.softFailLimit { return .soft }
    return .clean
  }

  /// Recovery gate is active until the window has passed AND a successful
  /// probe has been recorded (splitHealthy uses this for ordering).
  func isGated(_ member: Member, at now: Date = .init()) -> Bool {
    if member.gateNeedsProbe { return true }
    if let until = member.gatedUntil { return now < until }
    return false
  }

  /// Lantern rankLocked: tier (clean < soft < hard) → ungated before gated
  /// → delay ascending. Never-probed members sort last within their tier;
  /// full ties break on pool position (the sub's own order) so ranking is
  /// deterministic — Swift's sort is not stable.
  func ranked(at now: Date = .init()) -> [Member] {
    members.enumerated()
      .sorted { a, b in
        rankKey(a.element, index: a.offset, at: now) < rankKey(b.element, index: b.offset, at: now)
      }
      .map { $0.element }
  }

  private func rankKey(_ m: Member, index: Int, at now: Date) -> (Int, Int, Int, Int) {
    (
      tier(m, at: now).rawValue,
      isGated(m, at: now) ? 1 : 0,
      m.lastSuccessDelayMs ?? .max,
      index
    )
  }

  // ── Selection ────────────────────────────────────────────────────────────

  /// Next candidate from the ranked pool, skipping `excluding` (the failed
  /// tag). Preference order mirrors Lantern's DialContext failover (walk
  /// the rank, dial to confirm): a member whose last probe succeeded wins
  /// over an unproven one; healthy tiers over hard; hard members serve
  /// only when nothing healthier exists.
  func selectNext(excluding excludedTag: String? = nil, at now: Date = .init()) -> ParsedConfig? {
    let pool = ranked(at: now).filter { $0.config.id != excludedTag }
    if let live = pool.first(where: { tier($0, at: now) != .hard && $0.lastProbeSucceeded }) {
      return live.config
    }
    if let healthy = pool.first(where: { tier($0, at: now) != .hard }) {
      return healthy.config
    }
    return pool.first?.config
  }

  /// First candidate in rank order whose tag is in `alive` — the tags a
  /// fresh race just measured successfully. Post-race selections (connect,
  /// ladder, refetch, network-change re-race) must never trust a stale
  /// persisted delay to bootstrap a doomed session.
  func selectAlive(
    from alive: Set<String>,
    excluding excludedTag: String? = nil,
    at now: Date = .init()
  ) -> ParsedConfig? {
    ranked(at: now).first {
      $0.config.id != excludedTag && alive.contains($0.config.id)
    }?.config
  }

  /// Best non-current candidate in rank order (the re-probe loop's
  /// challenger).
  func topChallenger(at now: Date = .init()) -> ParsedConfig? {
    ranked(at: now).first { $0.config.id != currentTag }?.config
  }

  func member(_ tag: String) -> Member? {
    members.first { $0.config.id == tag }
  }

  func currentMember(at now: Date = .init()) -> Member? {
    currentTag.flatMap { member($0) }
  }

  mutating func setCurrent(_ config: ParsedConfig?) {
    currentTag = config?.id
  }

  /// Lantern applyStickiness + beatsOnDelay: keep the current member
  /// unless it is hard-demoted, has never succeeded, or the challenger is
  /// decisively faster — by the absolute AND the relative margin (300 ms
  /// AND 30 %, both required).
  func shouldSwitchCurrent(to challenger: ParsedConfig, at now: Date = .init()) -> Bool {
    guard let cur = currentMember(at: now) else { return true }
    guard tier(cur, at: now) != .hard else { return true }
    guard let curDelay = cur.lastSuccessDelayMs else { return true }
    guard let chal = member(challenger.id),
          chal.lastProbeSucceeded,        // a challenger that just failed must not win on stale data
          let chalDelay = chal.lastSuccessDelayMs else { return false }
    return chalDelay < curDelay - Self.switchToleranceMS
        && Double(chalDelay) < Double(curDelay) * (1 - Self.switchToleranceRatio)
  }

  /// Lantern confirmSelectedFailure: after a switch confirmed by the old
  /// member failing again, the failed member enters the recovery gate
  /// (5 min + one successful probe before it can win again).
  mutating func applyConfirmedFailureSwitch(from failedTag: String?, at now: Date = .init()) {
    guard let failedTag,
          let i = members.firstIndex(where: { $0.config.id == failedTag }) else { return }
    members[i].gatedUntil = now.addingTimeInterval(Self.recoveryGateDuration)
    members[i].gateNeedsProbe = true
  }

  /// Lantern probeFreshnessWindow: results newer than 30 s are reused
  /// instead of re-probed (the 45 s loop probes most rounds anyway).
  func needsProbe(_ tag: String, at now: Date = .init()) -> Bool {
    guard let m = member(tag) else { return false }
    guard let last = m.lastProbeAt else { return true }
    return now.timeIntervalSince(last) >= Self.probeFreshnessWindow
  }

  private func bestAlternativeDelay(excluding tag: String) -> Int? {
    members
      .filter { $0.config.id != tag }
      .compactMap(\.lastSuccessDelayMs)
      .min()
  }

  // ── Persistence (Lantern: TagHistory → servers.json) ─────────────────────

  struct Persisted: Codable, Sendable {
    var updatedAt: Date
    var members: [PersistedMember]
  }

  struct PersistedMember: Codable, Sendable {
    var tag: String
    var lastSuccessDelayMs: Int?
    var consecutiveFailures: Int
    var userFailures: [Date]
    var gatedUntil: Date?
    var gateNeedsProbe: Bool
  }

  var persisted(now: Date = .init()) -> Persisted {
    Persisted(
      updatedAt: now,
      members: members.map { m in
        PersistedMember(
          tag: m.config.id,
          lastSuccessDelayMs: m.lastSuccessDelayMs,
          consecutiveFailures: m.consecutiveFailures,
          userFailures: m.userFailures,
          gatedUntil: m.gatedUntil,
          gateNeedsProbe: m.gateNeedsProbe
        )
      }
    )
  }
}

/// Lantern stores selection history in servers.json through the servers
/// manager; here it is a small JSON under Application Support. The file is
/// a few KB — writes happen on the main actor at selection events, same
/// pattern as KeychainStore.
enum SelectionHistoryStore {
  static func save(_ state: AutoSelectState) {
    guard let url = fileURL,
          let data = try? JSONEncoder().encode(state.persisted()) else { return }
    try? data.write(to: url, options: .atomic)
  }

  static func load() -> AutoSelectState.Persisted? {
    guard let url = fileURL,
          let data = try? Data(contentsOf: url) else { return nil }
    return try? JSONDecoder().decode(AutoSelectState.Persisted.self, from: data)
  }

  private static var fileURL: URL? {
    let fm = FileManager.default
    guard let dir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
      return nil
    }
    let appDir = dir.appendingPathComponent("V2GEN", isDirectory: true)
    try? fm.createDirectory(at: appDir, withIntermediateDirectories: true)
    return appDir.appendingPathComponent("autoselect-history.json")
  }
}
