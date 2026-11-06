import SwiftUI
import UIKit

// ── V2GEN settings — native sheet ─────────────────────────────────────────
// A system .sheet: iOS 26 gives it the Liquid Glass treatment and the
// drag-to-dismiss gesture natively (no hand-rolled sheet physics). Content
// uses SEMANTIC colors (.primary/.secondary) so it follows the system
// scheme. The "Copy subscription link" action hands the CF-relayed sub URL
// to native clients (V2Box / Streisand) — the link only ever touches the
// Cloudflare worker, never the VPS directly.

struct SettingsSheetView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  @State private var copied = false

  private var client: PanelClient? { model.client }

  var body: some View {
    NavigationStack {
      content
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
    }
    .presentationDetents([.medium, .large])
    .presentationDragIndicator(.visible)
  }

  @ViewBuilder
  private var content: some View {
    if let client {
      List {
        Section {
          VStack(alignment: .leading, spacing: 2) {
            Text(client.name)
              .font(.title3.weight(.semibold))
              .foregroundStyle(.primary)
            Text("sub · \(client.subToken.prefix(8))…")
              .font(.system(size: 11.5, design: .monospaced))
              .foregroundStyle(.secondary)
          }
          .padding(.vertical, 4)
          .accessibilityElement(children: .combine)
        }

        quotaSection(client)

        // ── System VPN profile health ───────────────────────────────────
        Section {
          Button {
            Task { await model.retryProfile() }
          } label: {
            HStack {
              Label(
                "VPN profile",
                systemImage: model.profileOK
                  ? "checkmark.shield" : "exclamationmark.shield"
              )
              .foregroundStyle(.primary)
              Spacer()
              Text(model.profileOK ? "Ready" : "Needs attention")
                .foregroundStyle(model.profileOK ? Color.secondary : Color.red)
                .font(.subheadline.weight(.medium))
            }
          }
          .accessibilityHint("Re-checks the system VPN profile")
          .accessibilityValue(model.profileOK ? "Ready" : "Needs attention")
        } footer: {
          Text("Tapping re-checks the system VPN profile. If a permission popup appears, tap Allow; if a red note appears on the main screen, follow its retry/reset buttons. No popup after a previous Allow is normal — the profile already exists in Settings ← VPN.")
        }

        // ── Connection behavior (Stable Connect / Kill Switch) ──────────
        Section {
          Toggle(isOn: Binding(
            get: { model.stableConnect },
            set: { model.setStableConnect($0) }
          )) {
            Label("Stable Connect", systemImage: "bolt.badge.clock")
          }
          .accessibilityHint("Keep the connection alive in the background")

          Toggle(isOn: Binding(
            get: { model.killSwitch },
            set: { model.setKillSwitch($0) }
          )) {
            Label("Kill Switch", systemImage: "shield.lefthalf.filled")
          }
          .accessibilityHint("Block all traffic when the VPN is down")
        } header: {
          Text("Connection")
        } footer: {
          Text("Stable Connect: the VPN reconnects by itself the moment the network is back, instantly rotates to the next working config if the current one dies, and refreshes your subscription automatically when every config fails — all in the background.\n\nKill Switch: if the VPN cannot protect the traffic, nothing leaves the phone — no site opens outside the tunnel while a connection is failing.")
        }

        Section {
          Button {
            copySub(client)
          } label: {
            Label(
              copied ? "Copied — paste into V2Box / Streisand" : "Copy subscription link",
              systemImage: copied ? "checkmark" : "link"
            )
          }
          .buttonStyle(.glassProminent)
          .buttonBorderShape(.capsule)
          .sensoryFeedback(.success, trigger: copied)
        } footer: {
          Text("Hands the Cloudflare-relayed subscription link to a native client (V2Box / Streisand) for a real device tunnel.")
        }

        Section {
          Button {
            Task {
              dismiss()
              await model.loadSub()
            }
          } label: {
            Label("Resync configs", systemImage: "arrow.triangle.2.circlepath")
              .foregroundStyle(.primary)
          }
          Button(role: .destructive) {
            model.signOut()
          } label: {
            Label("Sign out", systemImage: "rectangle.portrait.and.arrow.right")
          }
        }
      }
    } else {
      ContentUnavailableView("Signed out", systemImage: "person.slash")
    }
  }

  // MARK: - Quota

  @ViewBuilder
  private func quotaSection(_ client: PanelClient) -> some View {
    let remain = client.limitBytes > 0
      ? max(0, client.limitBytes - client.usedBytes)
      : nil
    let fraction = client.limitBytes > 0
      ? min(1, Double(client.usedBytes) / Double(client.limitBytes))
      : 0

    Section("Volume") {
      VStack(alignment: .leading, spacing: 10) {
        HStack {
          Text(ByteFormat.humanBytes(client.usedBytes))
            .font(.body.weight(.semibold))
            .monospacedDigit()
            .foregroundStyle(.primary)
          Spacer()
          Text(remain != nil ? "of \(ByteFormat.humanBytes(client.limitBytes))" : "Unlimited")
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
        if remain != nil {
          ProgressView(value: fraction)
            .tint(Color(red: 0.184, green: 0.722, blue: 0.306))
            .accessibilityLabel("Data volume used")
            .accessibilityValue("\(Int((fraction * 100).rounded())) percent")
        }
      }
      .padding(.vertical, 4)
    }
  }

  // MARK: - Copy

  private func copySub(_ client: PanelClient) {
    UIPasteboard.general.string = "https://sub.v2gen.xyz/api/sub/\(client.subToken)"
    withAnimation(.easeOut(duration: 0.2)) { copied = true }
    Task {
      try? await Task.sleep(for: .seconds(2))
      withAnimation(.easeOut(duration: 0.2)) { copied = false }
    }
  }
}
