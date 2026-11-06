import SwiftUI

// ── V2GEN motion system ───────────────────────────────────────────────────
// Named presets, one per interaction class — the SwiftUI translation of the
// web app's motion.ts. Source: apple-motion-feel + WWDC23 "Animate with
// springs". The two designer parameters:
//   · bounce — 0.0 for tap-driven UI (nothing threw it), 0.1–0.2 only where
//     a drag/flick earned the overshoot.
//   · duration — 0.3–0.4 s unless a line of reasoning exists.
// Rule (consistency beats correctness): the same interaction animates the
// same way everywhere, from this one file.

extension Animation {
  /// Tap-driven feedback (buttons, toggles, chips) — critically damped.
  /// (web: SPRING_TAP 340/34 → ζ≈0.92)
  static let v2Tap = Animation.smooth(duration: 0.32)

  /// Entrance of surfaces the user summoned — smooth, no overshoot.
  /// (web: SPRING_REVEAL 210/26 → ζ≈0.90)
  static let v2Reveal = Animation.smooth(duration: 0.45)

  /// Momentum commits — the slider latch after a thrown drag. Bounce is
  /// earned by the throw. (web: SPRING_MOMENTUM 320/30 → ζ≈0.84)
  static let v2Momentum = Animation.snappy(duration: 0.38, extraBounce: 0.12)

  /// Long buttery glide home (disconnect) — near-critical, heavier.
  /// (web: SPRING_GLIDE 168/26/1.05 → ζ≈0.98)
  static let v2Glide = Animation.smooth(duration: 0.55)

  /// Light settle after an abandoned drag — brisk, tiny overshoot.
  /// (web: SPRING_SETTLE 210/26)
  static let v2Settle = Animation.snappy(duration: 0.35, extraBounce: 0.06)
}

// ── Reduce Motion ─────────────────────────────────────────────────────────
// The system tones down ITS glass motion, never ours. Every app-authored
// animation branches at the point of use (reduce-motion.md): substitute,
// don't remove — a crossfade (0.15 s, no bounce) still reads, an abrupt
// cut does not. Gesture tracking itself always stays 1:1.

extension Animation {
  /// Substitute ladder rung 1–2 for Reduce Motion: same change, crossfade
  /// speed, zero bounce.
  static let v2Reduced = Animation.easeInOut(duration: 0.15)

  /// The adaptive form used at call sites:
  ///   withAnimation(Animation.v2(.v2Tap)) { … }
  static func v2(_ base: Animation, reduceMotion: Bool) -> Animation {
    reduceMotion ? .v2Reduced : base
  }
}

/// Apple's momentum projection (exponential decay, NOT v²/2a): where a
/// flick will rest, so the release snaps to the target nearest the
/// projection and hands the velocity to the spring.
func v2ProjectMomentum(
  _ current: Double,
  velocity: Double,
  decelerationRate: Double = 0.998
) -> Double {
  current + (velocity / 1000) * decelerationRate / (1 - decelerationRate)
}
