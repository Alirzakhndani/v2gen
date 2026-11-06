import SwiftUI

// ── V2GEN theme — ink, glass, and measured geometry ───────────────────────
// The reference design is fixed: the owner's dark abstract wallpaper
// renders byte-for-byte as the backdrop, and the app's ink sits on it as
// light chrome — the same deliberate exception Apple's own immersive apps
// (Camera, Photos full-screen) make: over fixed dark CONTENT, ink stays
// light regardless of system scheme. Every surface that is NOT wallpaper-
// immersive (the settings sheet, system controls, alerts) uses semantic
// colors and follows the system's Light/Dark setting normally.

enum Ink {
  /// Primary ink over the wallpaper — reference-measured #FDFDFE.
  static let primary = Color(red: 0.992, green: 0.992, blue: 0.996)

  /// Muted labels on glass — reference rgba(218,227,241,0.78), held
  /// ≥4.5:1 against the smoked glass over the dark wallpaper.
  static let secondary = Color(red: 0.855, green: 0.890, blue: 0.945, opacity: 0.78)

  /// Slider lane label — reference #BFC6D7.
  static let lane = Color(red: 0.749, green: 0.776, blue: 0.843)

  /// Error ink — reference #FF9A96 (never the only signal; text + symbol).
  static let error = Color(red: 1.0, green: 0.604, blue: 0.588)

  /// Connected green — reference #5ADF8B.
  static let connected = Color(red: 0.353, green: 0.875, blue: 0.545)
}

enum V2Metrics {
  // Reference-measured @2.168 px/pt — see the web reference implementation.
  static let slabCorner: CGFloat = 25
  static let sheetCorner: CGFloat = 30
  static let inputCorner: CGFloat = 14

  /// Info-slab rows (Memory / Upload / Download / Remain / Days).
  static let rowSpacing: CGFloat = 0      // hairline-separated, measured
  /// Icon chip — reference-measured ⌀ ~72.7 px @2.168 = 33.5 pt.
  static let iconChip: CGFloat = 33.5

  /// The connect capsule (352.5 × 80.5 pt lane, ⌀69 pt pearl knob).
  static let capsuleHeight: CGFloat = 80.5
  static let knob: CGFloat = 69
  static let knobInset: CGFloat = 6
  /// Commit when the knob reaches ~90 % of the lane.
  static let commitFraction: CGFloat = 0.9
}

// ── Glass presets ─────────────────────────────────────────────────────────
// glassEffect is applied AFTER layout/appearance modifiers, and shapes are
// passed through `in:` — never clipShape on glass, never opacity < 1 on a
// glass ancestor, never glass stacked on glass. Nested controls inside a
// glass surface get FILLS (below), not a second lens.

extension View {
  /// The always-visible info slab — the one large custom glass surface the
  /// fixed reference design mandates. Regular glass (the adaptive variant),
  /// rectangular 25 pt radius per the reference geometry.
  func v2SlabGlass() -> some View {
    glassEffect(.regular, in: .rect(cornerRadius: V2Metrics.slabCorner))
  }

  /// The connect lane — the hero FLOATING BAR glass (the Instagram-style
  /// reference: very clear, bright, hairline-rimmed). NOT the adaptive
  /// `.regular` glassEffect — over this app's fixed dark glacier wallpaper
  /// that variant renders a flat dark matte slab (adaptive darkening +
  /// heavy blur weight; `tint(_:)` only adds color, it cannot thin the
  /// material). Instead the lens is a REAL system material —
  /// `.ultraThinMaterial`, the lightest blur iOS ships — so the wallpaper
  /// stays clearly visible through the lane, and the glass look comes from
  /// deterministic layered optics ON the lens:
  ///   · body wash — white, brighter at the top (sheen), faint bounce at
  ///     the bottom (light reflecting inside the glass)
  ///   · hairline rim — 1 pt stroke, brightest at the top edge where the
  ///     light catches, dimmer at the sides, a soft bounce at the bottom
  ///   · float shadow — detaches the bar from the wallpaper
  /// Every alpha is fixed (the backdrop is the fixed dark wallpaper, so
  /// the optics can be), and Reduce Transparency is honored natively by
  /// the material. Interaction lives on the content above the lens.
  func v2LaneGlass() -> some View {
    background(
      Capsule()
        .fill(.ultraThinMaterial)
        .overlay(
          Capsule().fill(
            LinearGradient(
              stops: [
                .init(color: .white.opacity(0.26), location: 0.00),
                .init(color: .white.opacity(0.10), location: 0.18),
                .init(color: .white.opacity(0.06), location: 0.55),
                .init(color: .white.opacity(0.13), location: 1.00),
              ],
              startPoint: .top, endPoint: .bottom
            )
          )
        )
        .overlay(
          Capsule().strokeBorder(
            LinearGradient(
              stops: [
                .init(color: .white.opacity(0.85), location: 0.00),
                .init(color: .white.opacity(0.22), location: 0.45),
                .init(color: .white.opacity(0.50), location: 1.00),
              ],
              startPoint: .top, endPoint: .bottom
            ),
            lineWidth: 1
          )
        )
        .shadow(color: .black.opacity(0.42), radius: 18, y: 10)
    )
  }

  /// Fill for icon chips and small controls that live INSIDE a glass
  /// surface (glass-on-glass rule: a second sampling lens there reads as
  /// mud — nested controls get a light frost fill instead).
  func v2ChipFill(radius: CGFloat) -> some View {
    background(
      RoundedRectangle(cornerRadius: radius, style: .continuous)
        .fill(.white.opacity(0.14))
        .overlay(
          RoundedRectangle(cornerRadius: radius, style: .continuous)
            .strokeBorder(.white.opacity(0.18), lineWidth: 1)
        )
    )
  }

  /// Soft shadow that seats light ink on glass over the dark wallpaper.
  func v2InkShadow() -> some View {
    shadow(color: Color(black: 0.10, opacity: 0.40), radius: 1, y: 1)
  }
}

extension Color {
  init(black: Double, opacity: Double) {
    self.init(.sRGB, white: black, opacity: opacity)
  }
}
