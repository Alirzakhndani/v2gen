import SwiftUI
import UIKit

// ── V2GEN home — wallpaper → V2GEN title + gear → info slab → connect ────
// The wallpaper is the fixed reference backdrop; the glass slab and capsule
// float over it as Liquid Glass with light ink. State is announced to
// VoiceOver (state ≠ color alone) and paired with sensory feedback.
//
// Vertical rhythm — reference-measured (mockup 58F4AA58, iPhone 16 Pro
// canvas): title center ≈ 14.9 %H, card top ≈ 19.9 %H, pill center
// ≈ 78.4 %H, pill bottom ≈ 131 pt above the home indicator. The paddings
// below land on those anchors on 59/47 pt-safe-area devices (empirically
// calibrated against the v1.1 screenshot: title cap top = 63.7 + padding).

struct HomeView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.accessibilityReduceMotion) private var reduceMotion
  @State private var appeared = false

  var body: some View {
    Wallpaper { EmptyView() }
    VStack(spacing: 0) {
      header
      InfoPanelView()
        .padding(.horizontal, 18.5)
        .padding(.top, 19)
      Spacer(minLength: 20)
      errorNote
      ConnectSliderView()
        .padding(.horizontal, 23)
        .padding(.bottom, 110)
    }
    .sheet(isPresented: Binding(
      get: { model.settingsOpen },
      set: { model.settingsOpen = $0 }
    )) {
      SettingsSheetView()
    }
    // Animated state changes are announced, not just shown.
    .onChange(of: model.connState) { _, state in
      if let message = state.announcement {
        AccessibilityNotification.Announcement(message).post()
      }
    }
    // Haptics — native sensory feedback, staged like the web app.
    .sensoryFeedback(.success, trigger: model.connState == .connected)
    .sensoryFeedback(.warning, trigger: model.connState == .disconnecting)
    .sensoryFeedback(.error, trigger: model.connState == .error)
    .sensoryFeedback(.impact(weight: .light), trigger: model.connState == .ready)
    .sensoryFeedback(.impact(weight: .heavy), trigger: model.connState == .connecting)
    .sensoryFeedback(.selection, trigger: model.settingsOpen)
  }

  // MARK: - Header (title + gear)

  private var header: some View {
    ZStack {
      HStack {
        Text("V2GEN")
          .font(.system(size: 38, weight: .black))
          .tracking(-0.84)
          .foregroundStyle(Ink.primary)
          .shadow(color: Color(black: 0.08, opacity: 0.5), radius: 2, y: 1)
          .shadow(color: .white.opacity(0.3), radius: 11)
        Spacer()
      }
      HStack {
        Spacer()
        // Gear — system glass button (buttonStyle(.glass) carries the
        // interactive material; never a raw glassEffect behind a button).
        Button {
          model.settingsOpen = true
        } label: {
          Image(systemName: "gearshape.fill")
            .font(.system(size: 18.5, weight: .medium))
            .foregroundStyle(Ink.primary)
            .frame(width: 40, height: 40)
            .contentShape(.rect)
        }
        .buttonStyle(.glass)
        .buttonBorderShape(.capsule)
        .accessibilityLabel("Settings")
      }
    }
    .padding(.horizontal, 20)
    .padding(.top, 49)
    // Entrance — the glass gear enters on SCALE only (transform-only
    // entrance for backdrop surfaces); the title ink fades.
    .opacity(appeared ? 1 : 0)
    .offset(y: appeared ? 0 : 8)
    .scaleEffect(appeared ? 1 : 0.9)
    .animation(Animation.v2(.v2Reveal, reduceMotion: reduceMotion), value: appeared)
    .onAppear { appeared = true }
    .accessibilityElement(children: .contain)
  }

  // MARK: - Error note (Persian-first, floats in the open wallpaper)

  @ViewBuilder
  private var errorNote: some View {
    // The ZStack survives the conditional so the removal animates; the
    // animation context lives OUTSIDE the `if` (motion-skill rule).
    ZStack {
      if model.connState == .error, let note = model.errorNote {
        Text(note)
          .font(.system(size: 13.5, weight: .medium))
          .foregroundStyle(Ink.error)
          .multilineTextAlignment(.center)
          .v2InkShadow()
          .padding(.horizontal, 30)
          .padding(.bottom, 14)
          .transition(reduceMotion ? .opacity : .opacity.combined(with: .offset(y: 6)))
      }
    }
    .animation(reduceMotion ? .v2Reduced : .easeOut(duration: 0.28), value: model.connState)
  }
}
