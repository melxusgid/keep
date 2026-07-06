import SwiftUI

struct LockScreenView: View {
    @EnvironmentObject var model: VaultModel
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var showingInit = false
    @FocusState private var passwordFocus: Bool

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            // Icon
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 64))
                .foregroundStyle(.tint)

            Text("Keep")
                .font(.largeTitle.bold())

            Text(model.isInitialized ? "Unlock your vault" : "Create your vault")
                .font(.subheadline)
                .foregroundColor(.secondary)

            Spacer().frame(height: 20)

            // Password field
            VStack(spacing: 12) {
                SecureField("Master password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($passwordFocus)
                    .frame(width: 280)
                    .onSubmit { submit() }

                if !model.isInitialized {
                    SecureField("Confirm password", text: $confirmPassword)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 280)
                        .onSubmit { submit() }
                }

                if model.isInitialized {
                    Button("Unlock", action: submit)
                        .buttonStyle(.borderedProminent)
                        .disabled(password.isEmpty)

                    Button("Touch ID", systemImage: "touchid") {
                        Task { await model.unlockWithBiometrics() }
                    }
                    .buttonStyle(.bordered)
                } else {
                    Button("Create Vault", action: submit)
                        .buttonStyle(.borderedProminent)
                        .disabled(password.isEmpty || password != confirmPassword)
                }
            }

            if model.isLoading {
                ProgressView()
                    .scaleEffect(0.8)
            }

            Spacer()

            // Footer
            if model.isInitialized {
                Text("Vault: ~/.keep/vault.enc")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            // Help text
            VStack(spacing: 4) {
                if model.isInitialized {
                    Text("Auto-locks after \(Int(model.autoLockMinutes)) min of inactivity")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                } else {
                    Text("Choose a strong master password. It cannot be recovered.")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .frame(width: 280)
                        .multilineTextAlignment(.center)
                }
            }
        }
        .padding()
        .frame(width: 400, height: 420)
        .onAppear { passwordFocus = true }
    }

    private func submit() {
        guard !password.isEmpty else { return }
        Task {
            if model.isInitialized {
                await model.unlock(password: password)
                if model.isUnlocked { password = "" }
            } else {
                guard password == confirmPassword else {
                    model.errorMessage = "Passwords don't match"
                    model.showError = true
                    return
                }
                await model.initialize(password: password)
                if model.isUnlocked { password = ""; confirmPassword = "" }
            }
        }
    }
}
