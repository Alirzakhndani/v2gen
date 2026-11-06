import SwiftUI

// ── The user's dark glacier wallpaper — byte-for-byte unedited ────────────
// The fixed reference backdrop every glass surface refracts. Never edited,
// never tinted. Full-bleed edge-to-edge (the system status bar renders
// over it; the scene is dark-preferred so its ink stays white).

struct Wallpaper<Overlay: View>: View {
  @ViewBuilder var overlay: () -> Overlay

  var body: some View {
    ZStack {
      GeometryReader { geo in
        Image("Wallpaper")
          .resizable()
          .scaledToFill()
          .frame(width: geo.size.width, height: geo.size.height)
      }
      .ignoresSafeArea()
      overlay()
        .ignoresSafeArea()
    }
    .allowsHitTesting(false)
  }
}
