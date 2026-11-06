import SwiftUI

// ── V2GEN connect control — the hero floating glass capsule ─────────────────
// The lane material is v2LaneGlass (V2GenTheme): an .ultraThinMaterial
// lens — the lightest REAL system blur, the glacier wallpaper stays
// clearly visible through it — with layered glass optics on top (top
// sheen, bottom bounce, hairline bright rim, float shadow): the
// Instagram-floating-bar look, not the flat dark matte the adaptive
// .regular glassEffect rendered over this dark backdrop. The knob is a
// PEARL fill, not glass (a sampling lens nested over the lane reads as
// mud — fills read as depth; the knob shadow ON the clear lane is what
// makes the glass feel thick). Reference-measured (mockup 58F4AA58
// @2.168 px/pt): ~80.5 pt lane, ⌀68–69 pt knob concentric with the left
// cap, 6 pt inset, chevron ~13.8 × 21.7 pt @4.4 stroke, 21 pt lane
// label, commit at ~90 % of the lane.
//
// Interaction — iPhone answer-call DNA, ported from the web app:
//   · drag right → emerald halo + light trail grow behind the knob (1:1
//     finger tracking; the user is the animation)
//   · reach ~90 % → the knob LATCHES (momentum spring — bounce earned by
//     the throw) and the app connects
//   · release early → light settle home, carrying the release velocity
//   · tap while ready → connect directly; tap while connected → buttery
//     glide home and the session drops
//
// All app-authored motion branches on Reduce Motion (gesture tracking
// stays 1:1 — only the release spring is tamed).

struct ConnectSliderView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.accessibilityReduceMotion) private var reduceMotion

  @State private var knobX: CGFloat = 0
  @State private var laneWidth: CGFloat = 0
  @State private var dragActive = false
  @State private var dragStartX: CGFloat = 0
  @State private var releaseGliding = false

  // ── Derived geometry ───────────────────────────────────────────────────
  private var maxDrag: CGFloat {
    max(laneWidth - V2Metrics.knob - V2Metrics.knobInset * 2, 0)
  }

  /// Where the knob centers while configs sync (the loading state).
  private var knobCentered: CGFloat {
    max((laneWidth - V2Metrics.knob) / 2 - V2Metrics.knobInset, 0)
  }

  private var state: ConnState { model.connState }
  private var canDrag: Bool { state == .ready || state == .error }
  private var progress: Double {
    maxDrag > 0 ? Double(min(knobX / maxDrag, 1)) : 0
  }

  // ── Body ───────────────────────────────────────────────────────────────

  var body: some View {
    ZStack(alignment: .leading) {
      trail
      halo
      laneLabel
      knob
    }
    .frame(height: V2Metrics.capsuleHeight)
    .v2LaneGlass()
    .contentShape(.capsule)
    .onGeometryChange(for: CGFloat.self, of: { proxy in
      proxy.size.width
    }, action: { _, new in
      laneWidth = new
      if state == .loading { knobX = knobCentered(for: new) }
    })
    .onTapGesture {
      switch state {
      case .connected:
        release()
      case .ready, .error:
        Task { await model.connect() }
      default:
        break
      }
    }
    .onChange(of: state) { _, newState in
      choreograph(newState)
    }
    .onAppear {
      // Initial placement (onChange only fires on change).
      if state == .loading {
        withAnimation(Animation.v2(.v2Settle, reduceMotion: reduceMotion)) {
          knobX = knobCentered
        }
      }
    }
    // VoiceOver — the drag is not a gesture VoiceOver users can make;
    // an explicit action replaces it.
    .accessibilityElement(children: .ignore)
    .accessibilityLabel("VPN connection")
    .accessibilityValue(accessibilityState)
    .accessibilityHint(state == .connected ? "Double-tap to disconnect." : "Double-tap to connect.")
    .accessibilityAction {
      switch state {
      case .connected:
        Task { await model.disconnect() }
      case .ready, .error:
        Task { await model.connect() }
      default:
        break
      }
    }
  }

  // MARK: - Lane content

  /// Emerald trail — a FILL on the glass lane, scaled on X from the
  /// leading edge (transform-first: no per-frame relayout).
  private var trail: some View {
    Capsule()
      .fill(
        LinearGradient(
          colors: [
            Color(red: 0.243, green: 0.812, blue: 0.353),
            Color(red: 0.184, green: 0.722, blue: 0.306),
          ],
          startPoint: .leading, endPoint: .trailing
        )
      )
      .frame(width: max(laneWidth - 14, 0), height: V2Metrics.capsuleHeight - 14)
      .scaleEffect(x: max(progress, 0.001), anchor: .leading)
      .opacity(knobX > 2 ? 1 : 0)
      .offset(x: 7)
      .frame(maxHeight: .infinity, alignment: .center)
      .allowsHitTesting(false)
      .accessibilityHidden(true)
  }

  /// Emerald halo breathing behind the knob — decorative; the loop is
  /// SKIPPED (not slowed) under Reduce Motion.
  private var halo: some View {
    Circle()
      .fill(
        RadialGradient(
          colors: [
            Color(red: 0.243, green: 0.812, blue: 0.353).opacity(0.55),
            .clear,
          ],
          center: .center, startRadius: 10, endRadius: 55
        )
      )
      .frame(width: V2Metrics.knob + 42, height: V2Metrics.knob + 42)
      .scaleEffect(0.55 + 0.63 * progress)
      .opacity(
        state == .connected
          ? 1
          : 0.95 * smoothstep(progress, from: 0.015, to: 0.5)
      )
      .modifier(HaloBreath(active: state == .connected && !reduceMotion))
      .offset(x: V2Metrics.knobInset + knobX - 21)
      .frame(maxHeight: .infinity, alignment: .center)
      .allowsHitTesting(false)
      .accessibilityHidden(true)
  }

  /// Lane label — centered right of the resting knob; fades as the knob
  /// slides under it.
  private var laneLabel: some View {
    Group {
      switch state {
      case .ready:
        Text("Slide to Connect")
          .font(.system(size: 21, weight: .regular))
          .foregroundStyle(Ink.lane)
      case .loading:
        EmptyView()
      case .connecting:
        Text("Connecting…")
          .font(.system(size: 21, weight: .medium))
          .foregroundStyle(Ink.primary.opacity(0.9))
      case .connected:
        Text("Connected")
          .font(.system(size: 21, weight: .semibold))
          .foregroundStyle(Ink.connected)
      case .disconnecting:
        Text("Disconnecting…")
          .font(.system(size: 21, weight: .medium))
          .foregroundStyle(Ink.primary.opacity(0.9))
      case .error:
        Text("Couldn't connect — try again")
          .font(.system(size: 21, weight: .medium))
          .foregroundStyle(Ink.error)
      }
    }
    .lineLimit(1)
    .minimumScaleFactor(0.82)
    .shadow(color: Color(black: 0.036, opacity: 0.6), radius: 2, y: 1)
    .frame(maxWidth: .infinity)
    .padding(.leading, V2Metrics.knob / 2 + V2Metrics.knobInset)
    .padding(.trailing, 36)
    .opacity(state == .ready ? max(1 - progress / 0.45, 0) : 1)
    .animation(.easeOut(duration: 0.2), value: state)
    .allowsHitTesting(false)
    .accessibilityHidden(true)
  }

  // MARK: - Knob (pearl fill, not glass)

  private var knob: some View {
    ZStack {
      Circle()
        .fill(
          LinearGradient(
            stops: [
              .init(color: Color(red: 1.0, green: 1.0, blue: 1.0), location: 0),
              .init(color: Color(red: 0.86, green: 0.88, blue: 0.91), location: 0.62),
              .init(color: Color(red: 0.78, green: 0.80, blue: 0.83), location: 1),
            ],
            startPoint: .topLeading, endPoint: .bottomTrailing
          )
        )
        .overlay(
          Circle().strokeBorder(
            LinearGradient(
              colors: [Color(red: 0.86, green: 0.87, blue: 0.89), .white.opacity(0.6)],
              startPoint: .top, endPoint: .bottom
            ),
            lineWidth: 1.2
          )
        )
        .shadow(color: Color(black: 0.02, opacity: 0.35), radius: 8, y: 3)
      knobGlyph
    }
    .frame(width: V2Metrics.knob, height: V2Metrics.knob)
    .scaleEffect(dragActive ? 0.97 : 1)
    .offset(x: V2Metrics.knobInset + knobX)
    .frame(maxHeight: .infinity, alignment: .center)
    .contentShape(.circle)
    .gesture(dragGesture)
    .animation(Animation.v2(.v2Tap, reduceMotion: reduceMotion), value: dragActive)
  }

  @ViewBuilder
  private var knobGlyph: some View {
    ZStack {
      switch state {
      case .loading, .connecting:
        ProgressView()
          .controlSize(.large)
          .tint(Color(red: 0.169, green: 0.184, blue: 0.227))
      case .connected, .disconnecting:
        Image(systemName: "power")
          .font(.system(size: 26, weight: .semibold))
          .foregroundStyle(Color(red: 0.122, green: 0.659, blue: 0.310))
          .opacity(state == .disconnecting ? 0.5 : 1)
      case .ready, .error:
        ChevronGlyph()
          .stroke(
            Color(red: 0.11, green: 0.137, blue: 0.20),
            style: StrokeStyle(lineWidth: 4.4, lineCap: .round, lineJoin: .round)
          )
          .frame(width: 19, height: 22.5)
      }
    }
    .animation(.easeOut(duration: 0.25), value: state)
  }

  // MARK: - Drag (1:1 tracking, rubber band, momentum decision)

  private var dragGesture: some Gesture {
    DragGesture(minimumDistance: 4)
      .onChanged { value in
        guard canDrag else { return }
        if !dragActive {
          dragActive = true
          dragStartX = knobX
        }
        let raw = dragStartX + value.translation.width
        knobX = rubberBand(raw)
      }
      .onEnded { value in
        guard dragActive else { return }
        dragActive = false
        if knobX >= maxDrag * V2Metrics.commitFraction {
          withAnimation(Animation.v2(.v2Momentum, reduceMotion: reduceMotion)) {
            knobX = maxDrag
          }
          Task { await model.connect() }
        } else {
          withAnimation(Animation.v2(.v2Settle, reduceMotion: reduceMotion)) {
            knobX = 0
          }
        }
      }
  }

  /// Progressive resistance past the edges (never a hard stop).
  private func rubberBand(_ raw: CGFloat) -> CGFloat {
    if raw > maxDrag {
      maxDrag + (raw - maxDrag) * 0.05
    } else if raw < 0 {
      raw * 0.05
    } else {
      raw
    }
  }

  // MARK: - State choreography (state-driven knob placement)

  private func choreograph(_ newState: ConnState) {
    switch newState {
    case .connecting, .connected:
      releaseGliding = false
      if knobX < maxDrag - 0.5 {
        withAnimation(Animation.v2(.v2Momentum, reduceMotion: reduceMotion)) {
          knobX = maxDrag
        }
      }
    case .loading:
      releaseGliding = false
      withAnimation(Animation.v2(.v2Settle, reduceMotion: reduceMotion)) {
        knobX = knobCentered
      }
    case .ready, .error, .disconnecting:
      // A user-triggered release already owns the glide home.
      guard !releaseGliding else {
        if newState == .ready { releaseGliding = false }
        return
      }
      if knobX > 0.75 {
        withAnimation(Animation.v2(.v2Glide, reduceMotion: reduceMotion)) {
          knobX = 0
        }
      }
    }
  }

  /// Tap while connected → glide home, drop the session.
  private func release() {
    guard state == .connected else { return }
    releaseGliding = true
    withAnimation(Animation.v2(.v2Glide, reduceMotion: reduceMotion)) {
      knobX = 0
    }
    Task { await model.disconnect() }
  }

  private func knobCentered(for width: CGFloat) -> CGFloat {
    max((width - V2Metrics.knob) / 2 - V2Metrics.knobInset, 0)
  }

  private var accessibilityState: String {
    switch state {
    case .loading: "Loading configs"
    case .ready: "Ready"
    case .connecting: "Connecting"
    case .connected: "Connected"
    case .disconnecting: "Disconnecting"
    case .error: "Connection failed"
    }
  }
}

/// Reference chevron — two rounded strokes, vertex at the right.
private struct ChevronGlyph: Shape {
  func path(in rect: CGRect) -> Path {
    var p = Path()
    p.move(to: CGPoint(x: rect.minX + rect.width * 0.30, y: rect.minY + rect.height * 0.12))
    p.addLine(to: CGPoint(x: rect.maxX - rect.width * 0.20, y: rect.midY + rect.height * 0.01))
    p.addLine(to: CGPoint(x: rect.minX + rect.width * 0.30, y: rect.maxY - rect.height * 0.12))
    return p
  }
}

private func smoothstep(_ x: Double, from: Double, to: Double) -> Double {
  let t = min(max((x - from) / (to - from), 0), 1)
  return t * t * (3 - 2 * t)
}

/// Connected-state halo breathing — an ambient loop, so it must be
/// SKIPPED (not retimed) under Reduce Motion; hence the view-level branch.
private struct HaloBreath: ViewModifier {
  let active: Bool

  func body(content: Content) -> some View {
    if active {
      content.phaseAnimator([false, true]) { view, phase in
        view.scaleEffect(phase ? 1.10 : 0.94)
      } animation: { _ in
        .easeInOut(duration: 1.6)
      }
    } else {
      content
    }
  }
}
