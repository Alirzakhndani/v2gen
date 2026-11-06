import SwiftUI

@main
struct V2GENApp: App {
  @State private var model = AppModel()
  @Environment(\.scenePhase) private var scenePhase

  var body: some Scene {
    WindowGroup {
      RootView()
        .environment(model)
        .onChange(of: scenePhase) { _, phase in
          model.scenePhaseChanged(phase)
        }
        .task { model.boot() }
    }
  }
}

// ── Root — login ⇄ home crossfade ─────────────────────────────────────────
// Wallpaper-immersive app: every screen renders over the fixed dark glacier
// wallpaper, so the scene is deliberately dark-preferred (the Camera-app
// pattern — Apple's own immersive apps stay dark regardless of system
// Light/Dark). Text and controls use semantic or explicit design inks; the
// system's own adaptations (glass material, vibrancy, Reduce Transparency
// frosting) are never overridden.
struct RootView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.accessibilityReduceMotion) private var reduceMotion

  var body: some View {
    ZStack {
      if model.client == nil {
        LoginView()
          .transition(.opacity)
      } else {
        HomeView()
          .transition(.opacity)
      }
    }
    .animation(Animation.v2(.v2Reveal, reduceMotion: reduceMotion), value: model.client == nil)
    .preferredColorScheme(.dark)
  }
}
