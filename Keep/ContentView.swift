import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: VaultModel
    @State private var selectedTab: Tab = .secrets
    @State private var vaultStats: VaultStats?

    enum Tab: String, CaseIterable {
        case secrets = "Secrets"
        case audit = "Audit"
        case settings = "Settings"

        var icon: String {
            switch self {
            case .secrets: return "key.fill"
            case .audit: return "clock.arrow.circlepath"
            case .settings: return "gearshape"
            }
        }
    }

    var body: some View {
        Group {
            if model.isUnlocked {
                unlockedView
            } else {
                LockScreenView()
                    .environmentObject(model)
            }
        }
        .alert("Keep", isPresented: $model.showError) {
            Button("OK") { model.showError = false }
        } message: {
            Text(model.errorMessage ?? "Unknown error")
        }
    }

    // MARK: - Unlocked View

    var unlockedView: some View {
        VStack(spacing: 0) {
            // Header bar
            HStack {
                Image(systemName: "lock.shield.fill")
                    .foregroundStyle(.tint)
                Text("Keep")
                    .font(.headline)
                Spacer()
                if let stats = vaultStats {
                    Text("\(stats.secretCount) secret\(stats.secretCount == 1 ? "" : "s")")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Button("Lock", systemImage: "lock") {
                    model.lock()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)

            // Tab bar
            Picker("View", selection: $selectedTab) {
                ForEach(Tab.allCases, id: \.self) { tab in
                    Label(tab.rawValue, systemImage: tab.icon).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)
            .padding(.bottom, 8)

            // Content
            switch selectedTab {
            case .secrets:
                SecretsListView()
                    .environmentObject(model)
            case .audit:
                AuditLogView()
                    .environmentObject(model)
            case .settings:
                SettingsView()
                    .environmentObject(model)
            }
        }
        .task {
            vaultStats = await model.getStats()
        }
        .onChange(of: model.secrets.count) { _, _ in
            Task { vaultStats = await model.getStats() }
        }
    }
}
