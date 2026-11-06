import SwiftUI

// ── The owner's wallpaper — byte-for-byte unedited ────────────────────────
// The fixed backdrop every glass surface refracts (the owner's own dark
// abstract — flowing near-black curves with silver rim highlights; swapped
// in at the owner's request, still dark so the light-ink theme holds).
// Never edited, never tinted. Full-bleed edge-to-edge (the system status
// bar renders over it; the scene is dark-preferred so its ink stays white).

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
