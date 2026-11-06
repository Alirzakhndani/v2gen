import SwiftUI

// ── V2GEN info panel — the fixed reference glass slab ─────────────────────
// Five live rows (Memory / Upload / Download / Remain / Days) on one real
// Liquid Glass surface (.glassEffect, 25 pt radius per the reference).
// Icon chips and switches are FILLS on the glass (never a second lens —
// glass cannot sample glass). Native Toggle switches get iOS 26 glass
// automatically and follow the system scheme.
//
// Row geometry is reference-measured @2.168 px/pt (mockup 58F4AA58):
// ⌀33.5 pt chips, value follows the label (+10 pt gap), 59 pt rows on
// hairlines; the slab grows with its content (accessibility requirement —
// a fixed-height slab would clip larger text).

private struct RowDef: Identifiable {
  let key: String
  let label: String
  let icon: String
  let chipRadius: CGFloat
  let hasSwitch: Bool

  var id: String { key }
}

private let rows: [RowDef] = [
  .init(key: "memory", label: "Memory Usage:", icon: "desktopcomputer", chipRadius: 12, hasSwitch: false),
  .init(key: "upload", label: "Upload:", icon: "arrow.up", chipRadius: 16.75, hasSwitch: false),
  .init(key: "download", label: "Download:", icon: "arrow.down", chipRadius: 16.75, hasSwitch: false),
  .init(key: "remain", label: "Remain:", icon: "calendar.badge.clock", chipRadius: 12, hasSwitch: true),
  .init(key: "days", label: "Days:", icon: "calendar", chipRadius: 12, hasSwitch: true),
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
    .padding(.vertical, 10)
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
    HStack(spacing: 6) {
      // icon chip — 33.5 pt light frost fill, white SF Symbol
      Image(systemName: row.icon)
        .font(.system(size: 17, weight: .medium))
        .foregroundStyle(.white)
        .frame(width: V2Metrics.iconChip, height: V2Metrics.iconChip)
        .v2ChipFill(radius: row.chipRadius)

      Text(row.label)
        .font(.system(size: 14, weight: .medium))
        .foregroundStyle(Ink.secondary)
        .fixedSize()

      // Value follows the label (reference layout): 6 spacing + 4 = 10 pt gap.
      Text(value)
        .font(.system(size: 14.5, weight: .semibold))
        .monospacedDigit()
        .foregroundStyle(Ink.primary)
        .padding(.leading, 4)

      Spacer(minLength: 10)

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
    return switch key {
    case "memory": panel.memory
    case "upload": panel.upload
    case "download": panel.download
    case "remain": panel.remain
    case "days": panel.days
    default: ""
    }
  }
}
