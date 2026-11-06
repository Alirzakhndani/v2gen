import Foundation
import Network
import Observation
import SwiftUI

// ── V2GEN app model — the whole product in one state machine ──────────────
// Native port of the web app's V2GenApp root, upgraded to the FULL
// Lantern selection machine (docs/worklog/lantern-analysis.md §6):
//
//   sign-in → silent sub import → slide to connect → race on the user's
//   own internet (hydrated from persisted history) → live session with
//   the whole failover ladder underneath:
//
//   Transport follows the owner's two-path flow: ENTRY (login + sub)
//   always rides the anti-filter CF worker (sub.v2gen.xyz); once a config
//   is connected the session logs (volume / remaining days / live
//   heartbeat) go DIRECT to the VPS (direct.v2gen.xyz) through the user's
//   own tunnel — the worker carries them only while direct is benched
//   (tunnel down). On disconnect the exchange stops; every connect
//   restarts the whole process from the worker entry.
//
//   45 s health loop ─ probe current + top challenger (freshness-aware)
//     ├─ current alive, challenger decisively better → hysteresis switch
//     ├─ current dead → user-failure + fast failover to next in rank
//     │   └─ none healthy → LADDER: re-probe every member, 10 s budget,
//     │       60 s cooldown → still nobody → EXHAUSTION → refetch sub
//     │       (60 s gate) → rebase state, re-race → still nobody → die
//     └─ network changed (WiFi ⇄ cellular) → measurements are void →
//         immediate full re-race with stickiness
//
//   Every selection event persists to Application Support (15-min age,
//   Lantern TagHistory) so a recently-demoted server cannot win again
//   right after an app restart.
//
// MainActor by project default (DEFAULT_ACTOR_ISOLATION). Networking hops
// through URLSession/NWConnection off the main actor; everything the UI
// renders lives here.

@Observable
final class AppModel {
  // ── UI state ───────────────────────────────────────────────────────────
  var client: PanelClient?
  var connState: ConnState = .loading
  var configs: [ParsedConfig] = []
  var errorNote: String?
  /// VPN-profile setup failure (permission popup / entitlement). Kept
  /// SEPARATE from errorNote so the concurrent sub import (which resets
  /// connState and errorNote) can never erase it — a profile problem must
  /// stay on screen until the next successful prepare or connect.
  var profileNote: String?
  /// Transient message for the LOGIN form — set when a stored session is
  /// dropped (dead token / inactive subscription) so the bounce back to
  /// the form is EXPLAINED instead of reading as "login is broken".
  var loginNote: String?
  var settingsOpen = false
  var bytes = (up: 0, down: 0)

  /// Info-slab rows (live data) — same computation as the web app.
  var panelRows: PanelRows {
    let configBytes = (try? JSONEncoder().encode(configs))?.count ?? 0
    let clientBytes = (try? JSONEncoder().encode(client))?.count ?? 0
    let memory = ByteFormat.humanBytes(configBytes + clientBytes)
    let remain: String
    if let client, let left = ByteFormat.remainingBytes(used: client.usedBytes, limit: client.limitBytes) {
      remain = ByteFormat.humanBytes(left)
    } else {
      remain = "Unlimited"
    }
    let days: String
    if let client, let d = ByteFormat.daysLeft(client.expireAt) {
      days = String(d)
    } else {
      days = "∞"
    }
    return PanelRows(
      memory: memory,
      upload: ByteFormat.humanBytes(bytes.up),
      download: ByteFormat.humanBytes(bytes.down),
      remain: remain,
      days: days
    )
  }

  // ── Session internals (not for the UI) ─────────────────────────────────
  private let api = PanelAPI()
  private var sessionKey: String?
  private var currentConfig: ParsedConfig?

  /// The Lantern MutableAutoSelect state — tiers, demotion windows,
  /// recovery gates, history. Built at connect, rebased on sub refetch.
  private var select: AutoSelectState?

  // Ladder / exhaustion / switch gates (Lantern runLadder, refetchOnExhaustion,
  // confirmedFailureSwitchCooldown).
  private var ladderCooldownUntil = Date.distantPast
  private var exhaustionGateUntil = Date.distantPast
  private var confirmedSwitchCooldownUntil = Date.distantPast

  /// Direct-VPS leg health: a failed direct attempt (tunnel down / still
  /// filtered) benches the direct host for two minutes — session logs ride
  /// the worker meanwhile. A network change resets the bench (the fresh
  /// internet may reach the VPS even when the old one didn't).
  private var directBenchUntil = Date.distantPast
  private static let directBenchDuration: TimeInterval = 120

  /// One selection cycle at a time: the 45 s loop, network-change races
  /// and ladders all mutate the same state. A latecomer skips; the next
  /// 45 s tick re-runs the logic on fresh data.
  private var selectionBusy = false

  // The user's internet, watched live (NWPathMonitor) — a path change
  // voids every measurement and triggers an immediate re-race. Updates
  // cross from the monitor's queue into the main actor through a stream
  // of plain strings (AsyncStream.Continuation is Sendable — no
  // non-Sendable reference ever crosses isolation domains).
  private let pathMonitor = NWPathMonitor()
  private let pathQueue = DispatchQueue(label: "v2gen.path")
  private var lastPathKind: String?

  private var beatTask: Task<Void, Never>?
  private var reprobeTask: Task<Void, Never>?
  private var statsTask: Task<Void, Never>?

  /// IPC command id of the config the tunnel currently runs (or should run).
  private var commandID = 0

  // The panel's remain/days toggles (reference rows 4–5).
  var showRemain = false
  var showDays = false

  // ── Connection preferences (Settings sheet) ─────────────────────────
  var stableConnect: Bool {
    get { AppSettings.stableConnect }
    set { AppSettings.stableConnect = newValue }
  }
  var killSwitch: Bool {
    get { AppSettings.killSwitch }
    set { AppSettings.killSwitch = newValue }
  }

  /// Toggle handler: persist + refresh the profile's on-demand rules (no
  /// running-tunnel disruption). The next connect embeds the flags in the
  /// command itself.
  func setStableConnect(_ on: Bool) {
    stableConnect = on
    Task { await TunnelController.applyOnDemandRules(stableConnect: on, killSwitch: killSwitch) }
  }
  func setKillSwitch(_ on: Bool) {
    killSwitch = on
    Task { await TunnelController.applyOnDemandRules(stableConnect: stableConnect, killSwitch: on) }
  }

  // ── Timing ──────────────────────────────────────────────────────────────
  // Lantern's background probe runs every 180 s, but it also has a REAL
  // data plane whose dial/stall/reset failures drive switching. The real
  // tunnel IS that data plane: dial outcomes surface through the engine
  // stats (state flips to failing after consecutive dial failures), while
  // the probe loop still measures the raw internet (probes bind to the
  // physical interface while the tunnel is up).
  private static let beatInterval: Duration = .seconds(25)
  private static let reprobeInterval: Duration = .seconds(45)
  private static let statsPollInterval: Duration = .seconds(1)

  // MARK: - Boot

  func boot() {
    // VPN profile at FIRST APP OPEN, before any login — the permission is
    // bundle-level (entitlement), not account-level, so iOS can ask now.
    // This is the moment the user expects the "Add VPN Configuration"
    // popup, and an entitlement/signing problem surfaces on the very
    // first launch instead of as a silent connect failure later.
    Task { await prepareProfileQuietly() }
    if let stored = KeychainStore.loadClient() {
      client = stored
      Task { await loadSub() }
    } else {
      connState = .loading
    }
    startPathMonitor()
  }

  /// One prepare at a time: boot(), signIn() and scene-active re-checks
  /// all fire this; a save is already pending on the permission popup, so
  /// a second concurrent call would race the first. The busy guard makes
  /// them sequential-safe.
  private var profileBusy = false

  /// Profile health for the Settings status row (true after a successful
  /// prepare, false while a note is up).
  private(set) var profileOK = false

  /// Shared profile-task runner: one at a time; success clears the note
  /// and flags health, failure publishes the honest Persian message (raw
  /// iOS reason clipped along — the ONLY way to tell a denied popup from
  /// a missing network-extension entitlement).
  private func runProfileTask(_ work: () async throws -> Void) async {
    guard !profileBusy else { return }
    profileBusy = true
    defer { profileBusy = false }
    do {
      try await work()
      profileOK = true
      profileNote = nil
      await TunnelController.applyOnDemandRules(
        stableConnect: stableConnect, killSwitch: killSwitch
      )
    } catch let error as TunnelController.TunnelError {
      profileOK = false
      profileNote = error.userMessage
    } catch {
      profileOK = false
      profileNote = TunnelController.TunnelError
        .profileSaveFailed(String(describing: error)).userMessage
    }
  }

  /// Create/refresh the VPN profile; failures land in profileNote (honest,
  /// actionable Persian, always visible on Home) without blocking anything.
  private func prepareProfileQuietly() async {
    await runProfileTask { try await TunnelController.prepare() }
  }

  /// User-tapped retry (note bar / Settings row): a fresh save is the
  /// documented way to get the permission prompt back after a denial.
  func retryProfile() async {
    await prepareProfileQuietly()
  }

  /// User-tapped reset (note bar): remove + re-create the profile — the
  /// strongest re-prompt path (see TunnelController.resetProfile).
  func resetProfile() async {
    await runProfileTask { try await TunnelController.resetProfile() }
  }

  // MARK: - Sign-in / out

  @discardableResult
  func signIn(username: String, password: String) async -> String? {
    loginNote = nil
    let user = ByteFormat.normalizePersianInput(username.trimmingCharacters(in: .whitespaces))
    guard !user.isEmpty, !password.isEmpty else { return nil }
    do {
      let c = try await api.login(username: user, password: password)
      KeychainStore.saveClient(c)
      client = c
      configs = []
      Task { await loadSub() }
      // Fresh sign-in — the VPN profile popup belongs to THIS moment,
      // not buried in the first connect attempt.
      Task { await prepareProfileQuietly() }
      return nil
    } catch let PanelError.panel(message) {
      // The panel answers "wrong username or password" for inactive or
      // EXPIRED subscriptions too — a user typing the RIGHT password
      // otherwise reads this as "login is broken". The hint points at
      // the account state instead.
      if message.contains("نام کاربری") || message.contains("رمز") {
        return message + " — اگر رمز درست است، اشتراک شما منقضی یا غیرفعال شده است"
      }
      return message
    } catch let PanelError.networkReport(report) {
      // The raced fronts all failed — the compact per-front report rides
      // along: a screenshot of this line says exactly what the ISP blocks.
      return "اتصال به سرور برقرار نشد (\(report)) — اینترنت را عوض کنید "
        + "(Wi-Fi ⇄ دیتا) یا با فیلترشکن دوباره امتحان کنید"
    } catch {
      // No fronts were raced (transport setup failed outright) — usually
      // the device has no usable route at all. Actionable Persian.
      return "اتصال به سرور برقرار نشد — اینترنت را عوض کنید (Wi-Fi ⇄ دیتا) و دوباره امتحان کنید"
    }
  }

  func signOut() {
    if sessionKey != nil {
      Task { await disconnect() }
    }
    KeychainStore.clearClient()
    client = nil
    configs = []
    select = nil
    settingsOpen = false
  }

  // MARK: - Silent sub import

  func loadSub() async {
    guard let client else { return }
    // While a session is live (exhaustion refetch, mid-session Resync)
    // the import is silent — it must never tear down the connected UI.
    let silent = sessionKey != nil
    if !silent {
      connState = .loading
      errorNote = nil
    }
    do {
      let sub = try await api.subscription(token: client.subToken)
      configs = sub.configs

      // A live session rebases its selection state onto the new pool,
      // carrying history over for surviving members (Lantern
      // updateServers). Guarded: a mid-flight selection cycle commits its
      // own state next, and runLadder re-rebases onto `configs` anyway.
      if let state = select {
        guard beginSelection() else { return }
        defer { selectionBusy = false }
        var rebased = AutoSelectState(configs: sub.configs, carryingOver: state)
        if let cur = currentConfig {
          if sub.configs.contains(where: { $0.id == cur.id }) {
            rebased.setCurrent(cur)
          } else if let replacement = rebased.selectNext() {
            // The current config vanished from the sub — fail over now.
            rebased.applyConfirmedFailureSwitch(from: cur.id)
            await applySwitch(to: replacement, state: &rebased)
          } else {
            rebased.setCurrent(nil)
            currentConfig = nil   // dead weight until the next ladder finds someone
          }
        }
        select = rebased
        SelectionHistoryStore.save(rebased)
      }

      if !silent { connState = .ready }
    } catch PanelError.inactive {
      if silent {
        // The token died mid-session (expired / removed) — honest death.
        await die("اشتراک شما فعال نیست")
      } else {
        // Stored auth is dead — back to the login form; the next sign-in
        // re-enters through the worker. EXPLAIN the bounce (loginNote)
        // — an unexplained return to the form reads as "login is broken".
        loginNote = "ورود ذخیره‌شده باطل شد — اشتراک شما فعال نیست یا منقضی شده است"
        signOut()
      }
    } catch let PanelError.panel(message) {
      if !silent {
        errorNote = message
        connState = .error
      }
    } catch let PanelError.networkReport(report) {
      if !silent {
        // All raced fronts failed (DNS + CF edges) — the ISP is blocking
        // every Cloudflare route at once. The report says which.
        errorNote = "کانفیگ‌ها دریافت نشد (\(report)) — اینترنت را عوض کنید (Wi-Fi ⇄ دیتا) و دوباره امتحان کنید"
        connState = .error
      }
    } catch {
      if !silent {
        // No fronts were raced at all — the device has no usable route.
        errorNote = "کانفیگ‌ها دریافت نشد — اینترنت را عوض کنید (Wi-Fi ⇄ دیتا) و دوباره امتحان کنید"
        connState = .error
      }
    }
  }

  // MARK: - Connect (Lantern-style race on the user's internet)

  func connect() async {
    guard let client0 = client else { return }
    connState = .connecting
    errorNote = nil
    // Connecting re-attempts the profile save itself (TunnelController.start
    // → prepareManager) — a stale profile note would only mislead now.
    profileNote = nil

    // Every connect restarts from the anti-filter ENTRY (owner's flow):
    // the sub is silently re-fetched THROUGH THE WORKER, so the race list
    // is exactly what the user's sub link serves right now. If the worker
    // is unreachable the cached list races — Lantern caches its config on
    // disk the same way.
    do {
      let fresh = try await api.subscription(token: client0.subToken)
      configs = fresh.configs
    } catch PanelError.inactive {
      loginNote = "ورود ذخیره‌شده باطل شد — اشتراک شما فعال نیست یا منقضی شده است"
      signOut()   // stored token is dead — back to the login form
      return
    } catch {
      // worker unreachable — race the cached list below
    }
    if configs.isEmpty {
      errorNote = "هیچ کانفیگی در اشتراک شما یافت نشد"
      connState = .error
      return
    }

    // Hydrate persisted history (< 15 min old) so a recently-demoted or
    // gated server does not win again right after a restart (Lantern
    // TagHistory hydrate).
    var state: AutoSelectState
    if let saved = SelectionHistoryStore.load() {
      state = AutoSelectState(restoring: saved, configs: configs)
    } else {
      state = AutoSelectState(configs: configs)
    }

    let results = await Racer.race(configs)
    state.ingest(results)

    // The winner must have a FRESH success from this race on the user's
    // current internet — a stale persisted delay must not bootstrap a
    // doomed session.
    let alive = Set(results.map { $0.config.id })
    guard var candidate = state.selectAlive(from: alive) else {
      SelectionHistoryStore.save(state)
      errorNote = "هیچ کانفیگی از اینترنت شما پاسخ نداد"
      connState = .error
      return
    }

    // ── Real tunnel bring-up (connect-time ladder) ─────────────────────
    // Each candidate gets the tunnel started with ITS link, then the app
    // pulls the worker's /healthz on a FRESH connection — which rides the
    // tunnel — so the dial it forces is the real end-to-end proof that
    // this config carries the user's traffic. A candidate that cannot is
    // an honest user-failure; the next in rank takes its place.
    //
    // Hot-swap fast path: while the tunnel is already up (candidate ≥ 2)
    // and the App Group works, rotation is a swap() — no stop/start cycle,
    // no on-demand race, Lantern-fast member switch.
    let canHotSwap = V2GenIPC.commandURL != nil
    var tunnelRunning = false
    var winner: ParsedConfig?
    var tried = Set<String>()
    while tried.count < 3 {
      tried.insert(candidate.id)
      do {
        if tunnelRunning && canHotSwap {
          commandID += 1
          TunnelController.swap(command: makeCommand(candidate))
          try? await Task.sleep(for: .milliseconds(500))  // engine reload lands
        } else {
          try await startTunnel(with: candidate)
          tunnelRunning = true
        }
      } catch {
        await TunnelController.stop()
        tunnelRunning = false
        errorNote = (error as? TunnelController.TunnelError)?.userMessage
          ?? "اتصال تونل ناموفق بود — دوباره تلاش کنید"
        connState = .error
        return
      }
      if await verifyTunnel() {
        winner = candidate
        break
      }
      state.recordUserFailure(tag: candidate.id)
      guard let next = state.ranked().map(\.config)
        .first(where: { alive.contains($0.id) && !tried.contains($0.id) })
      else {
        // Kill Switch: leave the failing tunnel UP — traffic dies INSIDE
        // the TUN (fail-closed) and on-demand keeps retrying it while the
        // app looks for a better config. Without it: honest teardown.
        if !killSwitch {
          await TunnelController.stop()
          tunnelRunning = false
        }
        break
      }
      if !canHotSwap {
        await TunnelController.stop()
        tunnelRunning = false
      }
      candidate = next
      try? await Task.sleep(for: .milliseconds(600))
    }

    guard let best = winner else {
      state.setCurrent(nil)
      SelectionHistoryStore.save(state)
      // No winner: tear the trial tunnel down — EXCEPT under the Kill
      // Switch, where a failing TUN still beats a leak (traffic dies
      // inside it; on-demand keeps retrying while the app looks for a
      // better moment).
      if !killSwitch, tunnelRunning {
        await TunnelController.stop()
      }
      errorNote = "هیچ کانفیگی از اینترنت شما پاسخ نداد"
      connState = .error
      return
    }
    state.setCurrent(best)
    select = state
    SelectionHistoryStore.save(state)

    currentConfig = best
    bytes = (0, 0)

    // START rides the connected-phase router: DIRECT to the VPS first —
    // the winning config is up, so the panel is one tunnel-hop away —
    // with the worker as fallback (see sendSession).
    guard let res = await sendSession(action: .start, config: best) else {
      errorNote = "Network error while starting the session"
      connState = .error
      return
    }
    guard res.ok == true, let key = res.sessionKey else {
      errorNote = res.error ?? "Session could not start"
      connState = .error
      return
    }
    if let updated = res.client {
      client = updated
    }
    sessionKey = key
    connState = .connected
    startSessionLoops()
  }

  // MARK: - Tunnel plumbing (real data plane)

  /// The full command for a config: RAW link + every flag + the ranked
  /// failover list (Stable Connect rotates through it on its own when the
  /// app is suspended).
  private func makeCommand(_ config: ParsedConfig) -> V2GenTunnelCommand {
    let ranked = (select?.ranked() ?? [])
      .map(\.config)
      .filter { $0.id != config.id }
    return V2GenTunnelCommand(
      id: commandID,
      link: config.raw,
      tag: config.name,
      failoverLinks: ranked.map(\.raw),
      failoverTags: ranked.map(\.name),
      stableConnect: stableConnect,
      killSwitch: killSwitch
    )
  }

  /// Start (or restart) the tunnel with a config's raw link.
  private func startTunnel(with config: ParsedConfig) async throws {
    commandID += 1
    try await TunnelController.start(command: makeCommand(config))
  }

  /// Prove the candidate's data plane: the /healthz check opens a FRESH
  /// connection (so it follows the new routing table), and the engine's
  /// byte counter must move — the request really went through the tunnel.
  private func verifyTunnel() async -> Bool {
    try? await Task.sleep(for: .milliseconds(700))   // routes settle

    // Degraded mode — no App Group → the engine's stats never appear. The
    // TUN's fake gateway (198.18.0.1) proves the routes installed, and the
    // fresh-socket healthCheck then proves the proxy plane carries traffic
    // (a dead proxy kills that connection INSIDE the TUN — no bypass).
    if TunnelController.readStats() == nil {
      for _ in 0..<10 {
        if TunnelController.tunAddressPresent(), await api.healthCheck() {
          return true
        }
        try? await Task.sleep(for: .milliseconds(600))
      }
      return false
    }

    let baseline = TunnelController.readStats()?.bytesUp ?? 0
    for _ in 0..<3 {
      if await api.healthCheck() {
        if let stats = TunnelController.readStats(), stats.bytesUp > baseline {
          return true
        }
        // Rode a pooled/direct connection — the next round forces fresh.
        try? await Task.sleep(for: .milliseconds(400))
        continue
      }
      if let stats = TunnelController.readStats(), stats.state == .failing {
        return false
      }
      try? await Task.sleep(for: .milliseconds(500))
    }
    // Last chance: other system traffic may have established the plane.
    for _ in 0..<6 {
      if let stats = TunnelController.readStats() {
        if stats.state == .connected { return true }
        if stats.state == .failing { return false }
      }
      try? await Task.sleep(for: .milliseconds(500))
    }
    return false
  }

  // MARK: - Disconnect (final usage credit)

  func disconnect() async {
    guard client != nil, sessionKey != nil else {
      await TunnelController.userStop()
      connState = .ready
      return
    }
    connState = .disconnecting
    stopSessionLoops()
    await sendBeat(.stop)          // ride the tunnel one last time — direct leg
    await TunnelController.userStop()
    sessionKey = nil
    currentConfig = nil
    select = nil   // history stays persisted on disk
    connState = .ready
  }

  // MARK: - Session loops

  private func startSessionLoops() {
    stopSessionLoops()

    // Heartbeat — keeps the session live on the panel homepage.
    beatTask = Task { [weak self] in
      while !Task.isCancelled {
        try? await Task.sleep(for: Self.beatInterval)
        guard let self, !Task.isCancelled else { return }
        await self.sendBeat(.beat)
      }
    }

    // Real data-plane accounting — the engine's counters (bytesUp/Down
    // counted at the TCP stack) land in the UI every second, and a
    // sustained dial-failure state feeds the failover ladder exactly like
    // a dead probe: user-failure + confirmed switch.
    statsTask = Task { [weak self] in
      var failingSince: Date?
      while !Task.isCancelled {
        try? await Task.sleep(for: Self.statsPollInterval)
        guard let self, !Task.isCancelled else { return }
        guard let stats = TunnelController.readStats(),
              stats.commandID == self.commandID
        else { continue }
        self.bytes = (stats.bytesUp, stats.bytesDown)
        if stats.state == .failing {
          let since = failingSince ?? Date()
          failingSince = since
          if Date().timeIntervalSince(since) > 8 {
            failingSince = nil
            await self.tunnelFailedCurrent()
          }
        } else {
          failingSince = nil
        }
      }
    }

    // Health loop — probes current + top challenger, drives the whole
    // failover ladder (Lantern activeInterval + DialContext failover).
    reprobeTask = Task { [weak self] in
      while !Task.isCancelled {
        try? await Task.sleep(for: Self.reprobeInterval)
        guard let self, !Task.isCancelled else { return }
        await self.reprobe()
      }
    }
  }

  private func stopSessionLoops() {
    beatTask?.cancel()
    reprobeTask?.cancel()
    statsTask?.cancel()
    beatTask = nil
    reprobeTask = nil
    statsTask = nil
  }

  // MARK: - Data-plane failure (the engine reports the current config dead)

  /// The tunnel's dial outcomes say the current config keeps failing while
  /// the session is live — the real-world equivalent of Lantern's
  /// dial-failure path: record the user failure and switch (or ladder).
  private func tunnelFailedCurrent() async {
    guard sessionKey != nil, var state = select, let current = currentConfig
    else { return }
    guard beginSelection() else { return }
    defer { selectionBusy = false }

    state.recordUserFailure(tag: current.id)
    if let replacement = state.selectNext(excluding: current.id) {
      state.applyConfirmedFailureSwitch(from: current.id)
      confirmedSwitchCooldownUntil = Date()
        .addingTimeInterval(AutoSelectState.confirmedSwitchCooldown)
      await applySwitch(to: replacement, state: &state)
    } else {
      await runLadder(&state)
    }

    guard sessionKey != nil else {
      select = nil
      return
    }
    select = state
    SelectionHistoryStore.save(state)
  }

  // MARK: - The health loop (Lantern MutableAutoSelect, live)

  private func reprobe() async {
    guard sessionKey != nil,
          var state = select,
          let current = currentConfig else { return }
    guard beginSelection() else { return }
    defer { selectionBusy = false }

    // Probe the current member and the top challenger (freshness-aware —
    // a challenger probed < 30 s ago is not re-probed, Lantern
    // probeFreshnessWindow).
    let curResult = await Racer.probe(current)
    state.ingest([curResult])
    if let challenger = state.topChallenger(), state.needsProbe(challenger.id) {
      state.ingest([await Racer.probe(challenger)])
    }

    if curResult.rttMs != nil {
      // Alive — improvement switch only, and never during the confirmed-
      // switch cooldown (Lantern applyStickiness + switch cooldown).
      if Date() >= confirmedSwitchCooldownUntil,
         let challenger = state.topChallenger(),
         state.shouldSwitchCurrent(to: challenger) {
        await applySwitch(to: challenger, state: &state)
      }
    } else {
      // Dead — the user's traffic through this member failed (Lantern
      // recordUserFailure; see AutoSelect header for the probe/user note).
      state.recordUserFailure(tag: current.id)
      if let replacement = state.selectNext(excluding: current.id) {
        state.applyConfirmedFailureSwitch(from: current.id)
        confirmedSwitchCooldownUntil = Date()
          .addingTimeInterval(AutoSelectState.confirmedSwitchCooldown)
        await applySwitch(to: replacement, state: &state)
      } else {
        // No healthy replacement in the current state → ladder.
        await runLadder(&state)
      }
    }

    // The session may have died mid-cycle (die() / user disconnect) —
    // never resurrect stale selection state over it.
    guard sessionKey != nil else {
      select = nil
      return
    }
    select = state
    SelectionHistoryStore.save(state)
  }

  // MARK: - Ladder + exhaustion (Lantern runLadder / ExhaustionSignal)

  /// When no healthy replacement exists, re-probe EVERY member in
  /// parallel under a total budget (10 s), cooled down for 60 s. An empty
  /// ladder is Exhaustion → the sub is refetched immediately (gated
  /// against spam) and the pool re-raced.
  private func runLadder(_ state: inout AutoSelectState) async {
    let now = Date()
    guard now >= ladderCooldownUntil else { return }
    ladderCooldownUntil = now.addingTimeInterval(AutoSelectState.ladderCooldown)

    // Always ladder over the CURRENT pool — a Resync or refetch may have
    // changed `configs` since the caller's state was built.
    state = AutoSelectState(configs: configs, carryingOver: state)

    let results = await Racer.race(configs, budget: AutoSelectState.ladderTotalBudget)
    state.ingest(results)

    let alive = Set(results.map { $0.config.id })
    if let replacement = state.selectAlive(from: alive, excluding: currentConfig?.id) {
      state.applyConfirmedFailureSwitch(from: currentConfig?.id)
      confirmedSwitchCooldownUntil = Date()
        .addingTimeInterval(AutoSelectState.confirmedSwitchCooldown)
      await applySwitch(to: replacement, state: &state)
    } else {
      await refetchAfterExhaustion(&state)
    }
  }

  /// Lantern ExhaustionSignal → LocalBackend.refetchOnExhaustion. The
  /// session stays up; the next ladder round retries after its cooldown.
  private func refetchAfterExhaustion(_ state: inout AutoSelectState) async {
    let now = Date()
    guard now >= exhaustionGateUntil else { return }
    exhaustionGateUntil = now.addingTimeInterval(AutoSelectState.exhaustionRefetchGate)

    await loadSub()   // silent — never tears down the live session
    guard !configs.isEmpty else {
      await die("هیچ کانفیگی از اینترنت شما پاسخ نداد")
      return
    }

    // Rebase onto the fresh pool (history carries over), then re-race it.
    var rebased = AutoSelectState(configs: configs, carryingOver: state)
    let results = await Racer.race(configs)
    rebased.ingest(results)

    let alive = Set(results.map { $0.config.id })
    if let replacement = rebased.selectAlive(from: alive, excluding: currentConfig?.id) {
      rebased.applyConfirmedFailureSwitch(from: currentConfig?.id)
      confirmedSwitchCooldownUntil = Date()
        .addingTimeInterval(AutoSelectState.confirmedSwitchCooldown)
      state = rebased
      await applySwitch(to: replacement, state: &state)
    } else if currentConfig == nil {
      // Nobody anywhere, on any pool — honest death.
      await die("هیچ کانفیگی از اینترنت شما پاسخ نداد")
    }
    // else: keep the (dead) current as last resort — the next ladder
    // round retries after its cooldown (Lantern keeps the tunnel up
    // through exhaustion while refetching).
  }

  // MARK: - Live re-race when the user's internet changes

  /// A path change (WiFi ⇄ cellular) voids every measurement — Lantern
  /// re-probes after network changes. Full fresh race, then stickiness
  /// decides whether the winner actually changes: a network change alone
  /// is not a reason to switch servers.
  private func reraceOnNetworkChange(retry: Bool = true) async {
    guard sessionKey != nil, !configs.isEmpty, select != nil else { return }
    guard beginSelection() else {
      if retry {
        try? await Task.sleep(for: .seconds(3))
        await reraceOnNetworkChange(retry: false)
      }
      return
    }
    defer { selectionBusy = false }
    guard var state = select else { return }

    let results = await Racer.race(configs)
    state.ingest(results)
    let alive = Set(results.map { $0.config.id })

    if let current = currentConfig,
       alive.contains(current.id) {
      // Current still alive on the new internet — stickiness applies.
      if Date() >= confirmedSwitchCooldownUntil,
         let challenger = state.selectAlive(from: alive, excluding: current.id),
         state.shouldSwitchCurrent(to: challenger) {
        await applySwitch(to: challenger, state: &state)
      }
    } else if let replacement = state.selectAlive(from: alive, excluding: currentConfig?.id) {
      // Current died with the network change — confirmed-failure switch.
      state.applyConfirmedFailureSwitch(from: currentConfig?.id)
      confirmedSwitchCooldownUntil = Date()
        .addingTimeInterval(AutoSelectState.confirmedSwitchCooldown)
      await applySwitch(to: replacement, state: &state)
    } else {
      await runLadder(&state)
    }

    // The session may have died mid-cycle — never resurrect stale state.
    guard sessionKey != nil else {
      select = nil
      return
    }
    select = state
    SelectionHistoryStore.save(state)
  }

  private func startPathMonitor() {
    let (stream, continuation) = AsyncStream<String>.makeStream()
    // The handler runs on the monitor's queue and yields only a Sendable
    // string; the main-actor task below consumes it.
    pathMonitor.pathUpdateHandler = { @Sendable path in
      // While the tunnel is up, probes must bind to the RAW internet —
      // keep the Racer's binding in sync with every path update.
      Racer.setPhysicalInterface(Self.physicalInterfaceName(path))
      _ = continuation.yield(Self.pathKind(path))
    }
    pathMonitor.start(queue: pathQueue)
    Task { [weak self] in
      for await kind in stream {
        self?.pathChanged(kind)
      }
    }
  }

  /// The interface name of the user's current physical path (WiFi/cellular/
  /// wired) — what outbound sockets bind to when the VPN's default routes
  /// must be bypassed.
  private nonisolated static func physicalInterfaceName(_ path: NWPath) -> String? {
    for interface in path.availableInterfaces {
      switch interface.type {
      case .wifi, .cellular, .wiredEthernet:
        return interface.name
      default:
        continue
      }
    }
    return nil
  }

  /// Interface class of a path — the dedupe key for "the user's internet
  /// changed". `none` = unsatisfied.
  private nonisolated static func pathKind(_ path: NWPath) -> String {
    guard path.status == .satisfied else { return "none" }
    if path.usesInterfaceType(.wifi) { return "wifi" }
    if path.usesInterfaceType(.cellular) { return "cellular" }
    if path.usesInterfaceType(.wiredEthernet) { return "wired" }
    return "other"
  }

  private func pathChanged(_ kind: String) {
    defer { lastPathKind = kind }
    guard let last = lastPathKind,
          last != kind,
          kind != "none" else { return }
    // A new internet voids the direct-leg bench — the fresh path may
    // reach the VPS even when the old one didn't.
    directBenchUntil = .distantPast
    guard sessionKey != nil, connState == .connected, select != nil else { return }
    Task { await reraceOnNetworkChange() }
  }

  // MARK: - Switching + gates

  /// One selection cycle at a time (returns false when one is mid-flight).
  private func beginSelection() -> Bool {
    if selectionBusy { return false }
    selectionBusy = true
    return true
  }

  /// Move the session to `config`: update state + current, hot-swap the
  /// RUNNING tunnel to the new link (no TUN teardown — live flows drain
  /// through their old connections), then tell the panel (the beat carries
  /// the new config — live accounting).
  private func applySwitch(to config: ParsedConfig, state: inout AutoSelectState) async {
    guard config.id != currentConfig?.id else { return }
    currentConfig = config
    state.setCurrent(config)
    commandID += 1
    TunnelController.swap(
      command: V2GenTunnelCommand(id: commandID, link: config.raw, tag: config.name)
    )
    await sendBeat(.beat)
  }

  /// Total death — stop the session with the usage credited and surface
  /// the failure honestly.
  private func die(_ note: String) async {
    errorNote = note
    await disconnect()
    connState = .error
  }

  // MARK: - Session transport (two-path, per the owner's flow)

  /// Send a session request on the right leg: DIRECT to the VPS while
  /// connected (the user's own tunnel carries the logs — volume, remaining
  /// days, live heartbeat), the anti-filter worker when direct is benched
  /// (tunnel down) or as fallback. Both legs failing → nil — best effort,
  /// the panel lazily ends stale sessions and the next beat catches up.
  private func sendSession(
    action: SessionAction,
    sessionKey: String? = nil,
    config: ParsedConfig? = nil
  ) async -> PanelAPI.SessionResponse? {
    guard let client else { return nil }
    let device = action == .start ? v2DeviceLabel : nil
    let cfg = config ?? currentConfig
    if Date() >= directBenchUntil {
      do {
        return try await api.session(
          via: .direct,
          token: client.subToken,
          action: action,
          sessionKey: sessionKey,
          device: device,
          config: cfg,
          bytesUp: bytes.up,
          bytesDown: bytes.down
        )
      } catch {
        directBenchUntil = Date().addingTimeInterval(Self.directBenchDuration)
      }
    }
    return try? await api.session(
      via: .worker,
      token: client.subToken,
      action: action,
      sessionKey: sessionKey,
      device: device,
      config: cfg,
      bytesUp: bytes.up,
      bytesDown: bytes.down
    )
  }

  // MARK: - Heartbeat

  private func sendBeat(_ action: SessionAction) async {
    guard sessionKey != nil else { return }
    guard let res = await sendSession(action: action, sessionKey: sessionKey) else { return }
    if action == .beat, let updated = res.client {
      // Usage credited server-side — adopt the panel's number.
      self.client = updated
    }
  }

  // MARK: - Scene lifecycle

  /// The real tunnel keeps running while the app is backgrounded (that's
  /// the point of a NetworkExtension) — no disconnect. On return to the
  /// foreground the heartbeat catches up immediately (the panel lazily
  /// ends stale sessions, so a beat right after resume keeps it live).
  func scenePhaseChanged(_ phase: ScenePhase) {
    if phase == .active, sessionKey == nil {
      // Back in the app with no live session — re-check the profile: the
      // user may have just allowed/removed it in Settings, and a fresh
      // save is also the path to a re-appeared permission prompt after a
      // denial. (While a session runs, the profile is obviously fine.)
      Task { await prepareProfileQuietly() }
    }
    if phase == .active, sessionKey != nil {
      Task { await sendBeat(.beat) }
    }
    // Stable Connect: returning to the app while the session is live but
    // the tunnel is failing → re-enter the ladder RIGHT NOW (it re-fetches
    // the sub and re-races) instead of waiting for the 45 s loop.
    if phase == .active, stableConnect, sessionKey != nil,
       connState == .connected,
       let stats = TunnelController.readStats(), stats.state == .failing {
      Task { await tunnelFailedCurrent() }
    }
  }
}

/// Info-slab row values.
struct PanelRows: Equatable, Sendable {
  var memory: String
  var upload: String
  var download: String
  var remain: String
  var days: String
}
