import SwiftUI

// ── V2GEN info panel — the fixed reference glass slab ─────────────────────
// Five live rows (Memory / Upload / Download / Remain / Days) on one real
// Liquid Glass surface (.glassEffect, 25 pt radius per the reference).
// Icon chips and switches are FILLS on the glass (never a second lens —
// glass cannot sample glass). Native Toggle switches get iOS 26 glass
// automatically and follow the system scheme.
//
// Row geometry approximates the reference at the standard type size and
// GROWS with Dynamic Type (accessibility requirement — a fixed-height
// slab would clip larger text).

private struct RowDef: Identifiable {
  let key: String
  let label: String
  let icon: String
  let chipRadius: CGFloat
  let hasSwitch: Bool

  var id: String { key }
}

private let rows: [RowDef] = [
  .init(key: "memory", label: "Memory Usage:", icon: "cpu", chipRadius: 10.5, hasSwitch: false),
  .init(key: "upload", label: "Upload:", icon: "arrow.up", chipRadius: 16, hasSwitch: false),
  .init(key: "download", label: "Download:", icon: "arrow.down", chipRadius: 16, hasSwitch: false),
  .init(key: "remain", label: "Remain:", icon: "calendar.badge.clock", chipRadius: 10.5, hasSwitch: true),
  .init(key: "days", label: "Days:", icon: "calendar", chipRadius: 10.5, hasSwitch: true),
]

struct InfoPanelView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.accessibilityReduceMotion) private var reduceMotion
  @State private var appeared = false

  var body: some View {
    VStack(spacing: 0) {
      ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
        if index > 0 { separator }
        rowView(row)
      }
    }
    .padding(.vertical, 4)
    .v2SlabGlass()
    .offset(y: appeared ? 0 : 18)
    .animation(Animation.v2(.v2Reveal, reduceMotion: reduceMotion), value: appeared)
    .onAppear { appeared = true }
    .accessibilityElement(children: .contain)
    .accessibilityLabel("Connection details")
  }

  // MARK: - Row

  @ViewBuilder
  private func rowView(_ row: RowDef) -> some View {
    let value = value(for: row.key)
    HStack(spacing: 13) {
      // icon chip — 32 pt light frost fill, white SF Symbol
      Image(systemName: row.icon)
        .font(.system(size: 15, weight: .medium))
        .foregroundStyle(.white)
        .frame(width: V2Metrics.iconChip, height: V2Metrics.iconChip)
        .v2ChipFill(radius: row.chipRadius)

      Text(row.label)
        .font(.system(size: 14, weight: .medium))
        .foregroundStyle(Ink.secondary)
        .fixedSize()

      Spacer(minLength: 10)

      Text(value)
        .font(.system(size: 14.5, weight: .semibold))
        .monospacedDigit()
        .foregroundStyle(Ink.primary)

      if row.hasSwitch {
        toggle(for: row)
      }
    }
    .padding(.horizontal, 21.5)
    .frame(minHeight: 59)
    .accessibilityElement(children: .combine)
  }

  @ViewBuilder
  private func toggle(for row: RowDef) -> some View {
    // Native Toggle — iOS 26 renders the glass switch; follows the system.
    Group {
      switch row.key {
      case "remain":
        Toggle("", isOn: Binding(
          get: { model.showRemain },
          set: { model.showRemain = $0 }
        ))
      default:
        Toggle("", isOn: Binding(
          get: { model.showDays },
          set: { model.showDays = $0 }
        ))
      }
    }
    .labelsHidden()
    .accessibilityLabel(row.label)
  }

  /// Separator — faint white hairline, brighter toward the right.
  private var separator: some View {
    LinearGradient(
      stops: [
        .init(color: .white.opacity(0.10), location: 0),
        .init(color: .white.opacity(0.18), location: 1),
      ],
      startPoint: .leading, endPoint: .trailing
    )
    .frame(height: 0.5)
    .padding(.horizontal, 20)
  }

  private func value(for key: String) -> String {
    let panel = model.panelRows
    switch key {
    case "memory": panel.memory
    case "upload": panel.upload
    case "download": panel.download
    case "remain": panel.remain
    case "days": panel.days
    default: ""
    }
  }
}
