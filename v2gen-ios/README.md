# V2GEN — Native iOS (SwiftUI + Liquid Glass)

The V2GEN VPN app as a **native iPhone app**: real Apple **Liquid Glass** on
iOS 26 — not glassmorphism. Same product flow as the web simulator:
sign-in → silent sub import → slide to connect → Lantern-style race on the
user's own internet → live session with panel heartbeats → usage credited
on stop. The transport follows the owner's **two-path flow**: the ENTRY
(login + sub) always rides the anti-filter Cloudflare worker
(`sub.v2gen.xyz`) — the Iran-blocked VPS IP is never contacted while
disconnected; once a config is up, the session logs (volume /
remaining days / live heartbeat) go **direct to the VPS**
(`direct.v2gen.xyz:8443`, DNS-only) through the user's own tunnel, with
the worker as fallback while the tunnel is down. On disconnect the
exchange stops; every connect restarts from the worker entry.

The config selection is the **full Lantern MutableAutoSelect machine** —
demoted tiers (Clean/Soft/Hard), 5-minute user-failure windows, the
recovery gate, 300 ms/30 % hysteresis, the failover ladder
(fast-failover → 10 s re-probe budget → exhaustion → sub refetch), a
live re-race the moment the user's internet changes (WiFi ⇄ cellular),
and 15-minute persisted selection history. The full port notes live in
`docs/worklog/autoselect-port.md`.

## Requirements

| | |
|---|---|
| Xcode | 26+ (iOS 26 SDK — `glassEffect` and friends) |
| Swift | 6 (Default Actor Isolation = MainActor, Approachable Concurrency) |
| Deployment target | **iOS 26.0** (iPhone 11 / SE 2nd gen and newer) |
| Generator | [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`) |

## Build

```bash
cd ios
xcodegen generate     # writes V2GEN.xcodeproj from project.yml
open V2GEN.xcodeproj  # select the V2GEN scheme, ⌘R
```

Shipping an installable IPA (ad-hoc signed, entitlements embedded for
free side-loaders):

```bash
cd ios
./build-ipa.sh        # → build/V2GEN.ipa   (needs xcodegen + Xcode 26)
```

Free install on a personal iPhone (Apple ID, 7-day renewal): **INSTALL-fa.md**.

Signing: the project builds unsigned (`CODE_SIGNING_ALLOWED = NO`) so the
free side-load flow works — sign at export with a free/development
identity, then side-load or package the IPA.

## Why iOS 26.0 with no fallback path

The owner's requirement is **native Liquid Glass**. `Material`
(`.ultraThinMaterial`…) is an approximation, never an equivalent — a
pre-26 fallback would ship fake glass to iPhone XR/XS/X-class devices
(stuck on iOS 18) and double every code path. If reach matters more than
purity later, the `liquid-glass` skill's `fallback-and-migration.md`
describes the Material-fallback adoption path.

## Architecture

```
V2GEN/
  V2GENApp.swift          App entry · root crossfade · scene-phase resume beat
  Theme/
    Motion.swift          Named spring presets (v2Tap/v2Reveal/v2Momentum/
                          v2Glide/v2Settle) + Reduce-Motion substitutes +
                          Apple momentum projection (exponential decay)
    V2GenTheme.swift      Ink palette, measured metrics, glass/fill presets
    Wallpaper.swift       The unedited glacier wallpaper, edge-to-edge
  Models/Models.swift     PanelClient, ParsedConfig (+isTLS/sni from the
                          link), ConnState, SubData, ProbeResult
  Networking/
    PanelAPI.swift        two-path client: ENTRY (login/sub) via the
                          anti-filter CF worker; session logs DIRECT to
                          the VPS (direct.v2gen.xyz) with worker fallback;
                          + fresh-connection /healthz (tunnel verification)
    ConfigParser.swift    vless / vmess / ss parsing (web-parity triples)
                          + security/sni extraction for the TLS probe
    TunnelController.swift  NETunnelProviderManager profile + IPC files +
                          hot-swap (Darwin notify) + stop
    Racer.swift           Probe layer: 6 workers, per-protocol timeouts
                          (Lantern behaviorFor classes), TLS-handshake
                          probing, budget races; binds to the PHYSICAL
                          interface while the tunnel is up (raw-internet
                          measurement, no loop through our own VPN)
    AutoSelect.swift      ⭐ Full MutableAutoSelect port: Clean/Soft/Hard
                          tiers, 5-min user-failure windows, switch
                          penalty, recovery gates, 300ms/30% hysteresis,
                          rank determinism, 15-min persisted history
  ViewModels/AppModel.swift  @Observable state machine: sign-in → import →
                          hydrated race → REAL tunnel bring-up ladder
                          (each candidate: start tunnel → /healthz rides
                          it → engine bytes must move = end-to-end proof)
                          → session loops (25 s beat, 45 s health loop,
                          1 s stats poll feeding the ladder with real
                          dial failures) → stop with usage; NWPathMonitor
                          re-races live when the user's internet changes
  Views/
    LoginView.swift       Glass card sign-in · Persian panel errors ·
                          Persian-keyboard username normalization
    HomeView.swift        Wallpaper · title · glass gear · announcements ·
                          sensory feedback
    InfoPanelView.swift   The fixed-design glass slab (5 rows, native
                          Toggles, hairline separators)
    ConnectSliderView.swift  THE hero: interactive glass capsule, pearl
                          knob, emerald trail/halo, drag-to-connect with
                          rubber-band + momentum commit, glide-home release
    SettingsSheetView.swift  Native system sheet: quota, Copy subscription
                          link (→ V2Box / Streisand), Resync, Sign out
  Support/
    KeychainStore.swift   Credentials in the iOS Keychain (not a file)
    ByteFormat.swift      humanBytes / daysLeft / Persian char normalization

V2GEN-Tunnel/             ⭐ the real VPN (NEPacketTunnelProvider, Swift 5)
  Shared/V2GenIPC.swift   app ⇄ tunnel contract (compiled into BOTH targets):
                          App Group resolved at runtime from the embedded
                          provisioning profile (free-signing-proof), atomic
                          JSON command/stats files, Darwin notifications
  Core/
    ByteStream.swift      the one transport abstraction (read/write/close)
    BLAKE3.swift          SS-2022 subkey derivation (verified vs reference)
    SHA224.swift          Trojan password hashing
    V2GenCrypto.swift     AES-GCM/ChaCha/ECB, HKDF-SHA1, EVP_BytesToKey,
                          FNV1a/CRC32, and the VMess AEAD KDF (closed form
                          derived from Go and verified against xray's
                          official test vector)
    LinkConfig.swift      full link decoder: vless/vmess/ss/trojan + all
                          transport params (ws path/host/ed, tls/sni,
                          allowInsecure); unsupported shapes → nil
  Transport/
    NWTransport.swift     NWByteStream — TCP/TLS over Network.framework
    WebSocket.swift       RFC 6455 client + v2ray early-data conventions
  Proxy/
    VLESS.swift           VLESS + Trojan codecs (SOCKS-style addressing)
    VMess.swift           VMess AEAD (auth id, sealed header, AEAD chunks)
    Shadowsocks.swift     classic AEAD + Shadowsocks-2022 (SIP022, the
                          exact sing-shadowsocks wire format)
    ProxyDialer.swift     dial pipeline + ProxyEngine (hot-swap config,
                          dial health, byte counters)
  TUN/
    IPStack.swift         IPv4/TCP/UDP parse+build+checksum
    TCPStack.swift        userspace TCP: handshake, windows, go-back-N
                          RTO, FIN/RST, backpressure, idle sweep
    FakeDNS.swift         fake-IP DNS authority (no leaks; remote
                          resolution through the proxy)
  TunnelProvider.swift    the NEPacketTunnelProvider: TUN settings,
                          packet loop, IPC reload, 1 s stats publishing
```

### Liquid Glass decisions (and the one judgment call)

- **System components first**: the settings sheet is a native `.sheet`
  (system glass + drag-to-dismiss for free), the gear is
  `.buttonStyle(.glass)`, rows use native `Toggle`, copy/primary actions
  use `.glassProminent`.
- **Custom glass only where the design earns it**: the login card, the
  info slab, and the connect capsule — each a lone glass surface floating
  over the fixed wallpaper (never stacked, never nested).
- **Nested controls get fills, never a second lens**: input backgrounds,
  icon chips, the pearl knob, the white capsule button — all fills
  (glass cannot sample glass).
- **The always-on info slab** is the deliberate exception: a large static
  glass surface in the content zone. It is the fixed reference design; the
  wallpaper beneath is varied content, so refraction has real input.
- **No `GlassEffectContainer`**: the glass surfaces never sit near each
  other, never merge, never morph — the container exists for glass that
  shares sampling or blends (verified with the apple-liquid-glass audit
  script; findings reviewed in context).
- `interactive()` only on the connect capsule — the one surface that takes
  drag and tap input.

### System-settings synchronization

| Setting | Behavior |
|---|---|
| Liquid Glass appearance (Clear/Tinted on 26.1, intensity slider on 27) | All glass uses the default `.regular` variant and system components, so the user's choice renders automatically. **No public API reads this setting** — by design, it is not yours to assert. |
| Light / Dark | The scene is dark-preferred: every screen is wallpaper-immersive (the Camera-app pattern — Apple's own immersive apps stay dark). Sheet content uses semantic colors (`.primary`/`.secondary`) and adapts to the scheme it renders in. |
| Reduce Transparency / Increase Contrast | The system frosts/contrasts the material itself — never overridden, never swapped to `.identity`. |
| Reduce Motion | Every app-authored animation branches at the call site: springs → 0.15 s crossfades; the halo breathing loop is skipped (not retimed); the drag still tracks 1:1 (only the release spring is tamed); `glassEffectTransition` would use `.materialize`. |
| Dynamic Type | Rows/fields use `minHeight` and grow; measured reference geometry approximates at the standard size. (Fixed: the capsule lane height and knob ⌀ — see limitations.) |
| VoiceOver | Every state change is announced (`AccessibilityNotification.Announcement`); symbol-only buttons carry labels; the slider exposes an explicit connect/disconnect action (a drag is not a VoiceOver gesture); haptics pair every state change (`.sensoryFeedback`). |

## Test matrix (Phase 7) — run on device/simulator

Built in a Linux sandbox with **no Xcode, no Swift toolchain, no iOS
simulator**: the code was verified by the apple-liquid-glass audit script
(clean), skill-checklist review, and two Jev design-QA judgments — but it
has **not been compiled or rendered**. Everything below is untested here
and must be run in Xcode:

| Test | Expected |
|---|---|
| Build (⌘B) | Compiles clean against the iOS 26 SDK |
| Light / Dark mode | Immersive screens identical (fixed dark wallpaper); sheet follows its scheme |
| Liquid Glass appearance presets | Glass renders per the user's Clear/Tinted choice automatically |
| Reduce Transparency | Slab / capsule / sheet frost, still legible |
| Increase Contrast | Borders appear; inks keep ≥4.5:1 |
| Reduce Motion | Springs become 0.15 s fades; halo loop gone; drag still 1:1 |
| Dynamic Type (largest size) | Rows grow; slab content not clipped; lane label may truncate (known) |
| VoiceOver | Announcements on connect/disconnect; gear/slider actions reachable |
| Drag-to-connect | 1:1 tracking, rubber-band past the end, latch at ~90 %, settle home on early release |
| Tap while connected | Glide home + session stop with usage credited |
| Login → connect → background app | Backgrounding stops the session and credits usage |
| Selection machine (see `docs/worklog/autoselect-port.md` §4) | Winner = lowest live RTT; dead winner fails over within ~2 min; total death → ladder → refetch → honest error; WiFi⇄cellular re-races immediately; restart < 15 min keeps demotions |
| Simulator ≠ device | Glass renders differently on simulator — accept appearance only on hardware |

## Known limitations

1. **No real tunnel** — same as the web app: the "session" is a
   simulation with live accounting on the panel; real device tunneling
   happens via *Copy subscription link* → V2Box/Streisand. A native
   NetworkExtension provider (vless) would need the tunnel-provider
   entitlement and is the next milestone. The selection machine is
   already tunnel-ready: the probe/user-failure split in
   `AutoSelectState` becomes meaningful the day real traffic flows
   through the winner.
2. **Fixed capsule metrics** (80.5 pt lane, ⌀69 knob) — reference design;
   at accessibility text sizes the lane label may truncate.
3. **Sheet-glass buttons on the 27 SDK**: `controlSize`/`ButtonBorderShape`
   reset inside sheets when built against the iOS 27 SDK (version-pinned
   bug in the skill corpus) — verify if you bump the SDK.
4. **Scene-phase stop** is immediate on leaving the foreground (the web
   app's `pagehide` equivalent); no grace period.
