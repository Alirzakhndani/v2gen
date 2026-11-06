import SwiftUI

// ── V2GEN sign-in — glass card over the unedited wallpaper ────────────────
// The card is a real Liquid Glass surface (.glassEffect) floating over the
// wallpaper; nested controls (inputs, button) get FILLS, never a second
// lens (glass-on-glass reads as mud). Persian panel errors render RTL.
//
// GLASS RULES (same physics as the web implementation):
//   · the card enters on TRANSFORM ONLY — opacity < 1 on a backdrop
//     surface collapses its refraction; the ink inside carries the fade.
//   · the scrim is a PLAIN dim, never a blur (a blurred layer under glass
//     is glass-under-glass).

struct LoginView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.accessibilityReduceMotion) private var reduceMotion

  @State private var username = ""
  @State private var password = ""
  @State private var showPass = false
  @State private var busy = false
  @State private var error: String?
  @State private var notice: String?
  @State private var cardShown = false

  var body: some View {
    ZStack {
      Wallpaper { scrim }
      VStack(spacing: 0) {
        wordmark
        glassCard
        // VPN-profile failures surface HERE too (fresh installs sit on
        // Login before any session — v1.2.1's blind spot).
        ProfileNoteBar()
          .padding(.top, 16)
        Spacer(minLength: 0)
        footer
      }
    }
  }

  /// Scrim — plain focus dim, brightest around the card zone (never a
  /// blur: glass must sample the wallpaper itself).
  private var scrim: some View {
    LinearGradient(
      stops: [
        .init(color: Color(black: 0.03, opacity: 0.18), location: 0.0),
        .init(color: Color(black: 0.03, opacity: 0.44), location: 0.58),
        .init(color: Color(black: 0.03, opacity: 0.60), location: 1.0),
      ],
      startPoint: .top, endPoint: .bottom
    )
  }

  // MARK: - Wordmark

  private var wordmark: some View {
    VStack(spacing: 6) {
      Text("V2GEN")
        .font(.system(size: 38, weight: .black))
        .tracking(-0.84)
        .foregroundStyle(Ink.primary)
        .shadow(color: Color(black: 0.08, opacity: 0.5), radius: 2, y: 1)
        .shadow(color: .white.opacity(0.3), radius: 11)
      Text("SECURE VPN")
        .font(.system(size: 12, weight: .semibold))
        .tracking(3.8)
        .foregroundStyle(Ink.primary.opacity(0.8))
        .v2InkShadow()
    }
    .padding(.top, 96)
    .accessibilityElement(children: .combine)
  }

  // MARK: - Glass card

  private var glassCard: some View {
    VStack(alignment: .leading, spacing: 0) {
      Text("Sign in")
        .font(.system(size: 21, weight: .semibold))
        .foregroundStyle(Ink.primary)
      Text("Use your V2GEN subscription account")
        .font(.system(size: 13))
        .foregroundStyle(Ink.secondary)
        .padding(.top, 3)

      fields
        .padding(.top, 20)

      if notice != nil || error != nil {
        noticeAndError
          .padding(.top, 14)
      }

      signInButton
        .padding(.top, 22)
    }
    .padding(24)
    .frame(maxWidth: 321)
    .glassEffect(.regular, in: .rect(cornerRadius: 30))
    .padding(.top, 46)
    // Entrance — transform only (glass rule): the card springs up; the
    // offset never touches the material's opacity. Under Reduce Motion the
    // same change rides a fast ease.
    .offset(y: cardShown ? 0 : 26)
    .animation(
      Animation.v2(.v2Reveal, reduceMotion: reduceMotion).delay(0.12),
      value: cardShown
    )
    .onAppear { cardShown = true }
  }

  // MARK: - Fields

  private var fields: some View {
    VStack(spacing: 12) {
      fieldInput {
        TextField("Username", text: $username)
          .textInputAutocapitalization(.never)
          .autocorrectionDisabled()
          .textContentType(.username)
          .onChange(of: username) { _, _ in notice = nil }
      }
      fieldInput {
        HStack(spacing: 8) {
          Group {
            if showPass {
              TextField("Password", text: $password)
                .textContentType(.password)
            } else {
              SecureField("Password", text: $password)
                .textContentType(.password)
            }
          }
          .accessibilityElement(children: .combine)
          // eye toggle — 44 pt hit zone (visible glyph stays 18 pt)
          Button {
            showPass.toggle()
          } label: {
            Image(systemName: showPass ? "eye.slash" : "eye")
              .font(.system(size: 18, weight: .medium))
              .foregroundStyle(Ink.secondary)
              .frame(width: 46, height: 46)
              .contentShape(.rect)
          }
          .accessibilityLabel(showPass ? "Hide password" : "Show password")
          .buttonStyle(.plain)
        }
      }
    }
  }

  private func fieldInput<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
    content()
      .font(.system(size: 16))
      .foregroundStyle(Ink.primary)
      .padding(.horizontal, 16)
      .frame(height: 48)
      .v2ChipFill(radius: V2Metrics.inputCorner)
  }

  // MARK: - Notice / error (RTL Persian)

  private var noticeAndError: some View {
    VStack(spacing: 5) {
      if let notice {
        Text(notice)
          .font(.system(size: 12))
          .foregroundStyle(Ink.primary.opacity(0.75))
      }
      if let error {
        Text(error)
          .font(.system(size: 13))
          .foregroundStyle(Ink.error)
      }
    }
    .multilineTextAlignment(.center)
    .frame(maxWidth: .infinity)
    .environment(\.layoutDirection, .rightToLeft)
    .accessibilityElement(children: .combine)
    .accessibilityLabel([notice, error].compactMap { $0 }.joined(separator: ". "))
  }

  // MARK: - Submit

  private var canSubmit: Bool {
    !busy && !username.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty
  }

  private var signInButton: some View {
    Button {
      guard canSubmit else { return }
      Task { await submit() }
    } label: {
      Group {
        if busy {
          ProgressView()
            .tint(Color(red: 0.137, green: 0.165, blue: 0.239))
        } else {
          Text("Sign In")
            .font(.system(size: 17, weight: .semibold))
            .foregroundStyle(Color(red: 0.137, green: 0.165, blue: 0.239))
        }
      }
      .frame(maxWidth: .infinity)
      .frame(height: 52)
    }
    .buttonStyle(WhiteCapsuleButtonStyle())
    .disabled(!canSubmit)
    .opacity(canSubmit ? 1 : 0.45)
  }

  private func submit() async {
    busy = true
    error = nil
    notice = nil
    // Persian keyboard contamination — deterministic char-map fix, applied
    // to the username only (visible in the field; passwords never touched).
    let user = ByteFormat.normalizePersianInput(username.trimmingCharacters(in: .whitespaces))
    if user != username.trimmingCharacters(in: .whitespaces) {
      username = user
      notice = "نام کاربری دارای حروف یا اعداد فارسی بود — به‌صورت خودکار اصلاح شد"
    }
    if let message = await model.signIn(username: user, password: password) {
      error = message
    }
    busy = false
  }

  private var footer: some View {
    Text("Your data travels only through the Cloudflare anti-filter relay")
      .font(.system(size: 11.5, weight: .medium))
      .tracking(0.7)
      .foregroundStyle(Ink.primary.opacity(0.78))
      .v2InkShadow()
      .padding(.top, 34)
      .padding(.bottom, 30)
  }
}

// ── White capsule button — reference primary action ───────────────────────
// A FILL on the glass card (nested controls get fills, not lenses): the
// reference's white capsule with dark ink, soft drop shadow, springy press.
struct WhiteCapsuleButtonStyle: ButtonStyle {
  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .background {
        Capsule(style: .continuous)
          .fill(.white)
          .shadow(color: Color(black: 0.02, opacity: 0.55), radius: 14, y: 10)
          .shadow(color: .white.opacity(0.35), radius: 1)
      }
      .scaleEffect(configuration.isPressed ? 0.97 : 1)
      .animation(Animation.v2(.v2Tap, reduceMotion: UIAccessibility.isReduceMotionEnabled), value: configuration.isPressed)
  }
}
