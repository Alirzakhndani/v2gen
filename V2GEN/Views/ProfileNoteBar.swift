import SwiftUI

// ── VPN profile failure bar — the note plus in-place recovery actions ──────
// Rendered on BOTH Login and Home. (Login was the v1.2.1 blind spot: on a
// fresh install the user sits on the LOGIN screen while boot() prepares the
// VPN profile — a failed prepare (denied popup / stripped entitlement)
// landed in profileNote, which only HomeView rendered. The user saw
// nothing at all: no popup AND no error.)
//
// Two actions, weakest first:
//   · retry — a fresh saveToPreferences; iOS re-presents the permission
//     prompt after a denial on most versions
//   · reset — remove + re-create the profile; a brand-new save asks for
//     permission again even where a plain re-save does not
//
// The bar collapses to zero height when there is no note (ZStack survives
// the conditional so removal animates; the animation context lives
// OUTSIDE the `if` — motion-skill rule).

struct ProfileNoteBar: View {
  @Environment(AppModel.self) private var model
  @Environment(\.accessibilityReduceMotion) private var reduceMotion

  var body: some View {
    ZStack {
      if let note = model.profileNote {
        VStack(spacing: 10) {
          Text(note)
            .font(.system(size: 13.5, weight: .medium))
            .foregroundStyle(Ink.error)
            .multilineTextAlignment(.center)
            .v2InkShadow()
          HStack(spacing: 14) {
            action(
              "تلاش دوباره", icon: "arrow.clockwise",
              run: { Task { await model.retryProfile() } }
            )
            action(
              "بازنشانی پروفایل", icon: "arrow.triangle.2.circlepath",
              run: { Task { await model.resetProfile() } }
            )
          }
        }
        .padding(.horizontal, 30)
        .padding(.bottom, 14)
        .environment(\.layoutDirection, .rightToLeft)
        .transition(
          reduceMotion ? .opacity : .opacity.combined(with: .offset(y: 6))
        )
      }
    }
    .animation(
      reduceMotion ? .v2Reduced : .easeOut(duration: 0.28),
      value: model.profileNote
    )
  }

  // Chip-style action button — a FILL on the wallpaper (nested-control
  // glass rule: no second lens), 40 pt tall with a generous shape for the
  // 44 pt touch target law.
  private func action(
    _ title: String, icon: String, run: @escaping () -> Void
  ) -> some View {
    Button(action: run) {
      Label(title, systemImage: icon)
        .font(.system(size: 13, weight: .semibold))
        .foregroundStyle(Ink.primary)
        .padding(.horizontal, 16)
        .frame(height: 40)
        .v2ChipFill(radius: 20)
        .contentShape(.capsule)
    }
    .buttonStyle(.plain)
    .accessibilityLabel(title)
  }
}
