import SwiftUI
import LocalAuthentication

struct SettingsView: View {
    @EnvironmentObject var model: VaultModel
    @State private var showingResetConfirm = false

    var body: some View {
        TabView {
            generalSettings
                .tabItem { Label("General", systemImage: "gearshape") }

            aboutSettings
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(width: 400, height: 280)
    }

    // MARK: - General

    var generalSettings: some View {
        Form {
            Section("Auto-Lock") {
                VStack(alignment: .leading, spacing: 4) {
                    Slider(value: $model.autoLockMinutes, in: 1...60, step: 1) {
                        Text("Auto-lock after:")
                    }
                    Text("\(Int(model.autoLockMinutes)) minute\(model.autoLockMinutes == 1 ? "" : "s") of inactivity")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Section("Security") {
                HStack {
                    Image(systemName: "touchid")
                        .foregroundColor(.accentColor)
                    Text("Touch ID / Face ID available")
                    Spacer()
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .help("Available on this device")
                }
                .font(.subheadline)

                HStack {
                    Image(systemName: "lock.shield")
                        .foregroundColor(.accentColor)
                    Text("AES-256-GCM encryption")
                    Spacer()
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundColor(.green)
                }
                .font(.subheadline)

                HStack {
                    Image(systemName: "memorychip")
                        .foregroundColor(.accentColor)
                    Text("Argon2id key derivation")
                    Spacer()
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundColor(.green)
                }
                .font(.subheadline)
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    // MARK: - About

    var aboutSettings: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 48))
                .foregroundStyle(.tint)

            Text("Keep")
                .font(.title.bold())

            Text("Encrypted secrets vault for agents and humans")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            Text("Version 1.0.0 • AES-256-GCM • Argon2id")
                .font(.caption)
                .foregroundColor(.secondary)

            Text("FromTheScope")
                .font(.caption2)
                .foregroundColor(.secondary)

            Divider()

            HStack {
                Button("Reset Vault...", role: .destructive) {
                    showingResetConfirm = true
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .alert("Reset Vault?", isPresented: $showingResetConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Delete All Secrets", role: .destructive) {
                resetVault()
            }
        } message: {
            Text("This will delete the vault file at ~/.keep/vault.enc. All secrets will be permanently lost. Are you sure?")
        }
    }

    private func resetVault() {
        model.lock()
        try? FileManager.default.removeItem(at: VaultService.vaultPath)
        try? FileManager.default.removeItem(at: VaultService.vaultDir)
        model.checkVaultExists()
    }
}
