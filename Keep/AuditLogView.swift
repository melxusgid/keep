import SwiftUI

struct AuditLogView: View {
    @EnvironmentObject var model: VaultModel
    @State private var entries: [AuditEntry] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Audit Log")
                    .font(.title2.bold())
                Spacer()
                Button("Refresh", systemImage: "arrow.clockwise") {
                    Task { await refresh() }
                }
                .buttonStyle(.bordered)
            }
            .padding(.horizontal)

            if entries.isEmpty {
                Spacer()
                ContentUnavailableView(
                    "No audit entries",
                    systemImage: "clock.badge.checkmark",
                    description: Text("Vault activity will appear here")
                )
                Spacer()
            } else {
                List(entries) { entry in
                    HStack {
                        // Action icon
                        Image(systemName: icon(for: entry.action))
                            .foregroundColor(color(for: entry.action))
                            .font(.caption)

                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.action.capitalized)
                                .font(.body)
                            if let name = entry.secretName, name != "_all" && name != "_vault" {
                                Text(name)
                                    .font(.caption.monospaced())
                                    .foregroundColor(.secondary)
                            }
                        }

                        Spacer()

                        Text(entry.timestamp, style: .relative)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(.inset)
            }
        }
        .task { await refresh() }
    }

    private func refresh() async {
        await model.refreshAuditLog()
        entries = model.auditEntries
    }

    private func icon(for action: String) -> String {
        switch action {
        case "init": return "lock.shield"
        case "unlock": return "lock.open"
        case "lock": return "lock"
        case "set": return "plus.circle"
        case "get": return "eye"
        case "list": return "list.bullet"
        case "delete": return "trash"
        case "rotate": return "arrow.triangle.2.circlepath"
        case "export": return "square.and.arrow.up"
        default: return "circle"
        }
    }

    private func color(for action: String) -> Color {
        switch action {
        case "init", "unlock": return .green
        case "lock": return .orange
        case "set": return .blue
        case "get": return .secondary
        case "delete": return .red
        case "rotate": return .purple
        default: return .secondary
        }
    }
}
