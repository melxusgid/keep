import Foundation
import SwiftUI
import Combine
import LocalAuthentication

/// Observable state manager for the Keep vault. All view access goes through this.
/// Wraps the `VaultService` actor — all vault operations are async.
@MainActor
class VaultModel: ObservableObject {

    // MARK: - Published State

    @Published var isUnlocked = false
    @Published var isInitialized = false
    @Published var secrets: [SecretItem] = []
    @Published var auditEntries: [AuditEntry] = []
    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var showError = false
    @Published var autoLockMinutes: Double = 15 {
        didSet { Task { await vault.setAutoLock(seconds: autoLockMinutes * 60) } }
    }
    @Published var searchQuery = ""

    // MARK: - Internal

    private let vault = VaultService()
    private var unlockObserver: NSObjectProtocol?

    var filteredSecrets: [SecretItem] {
        if searchQuery.isEmpty { return secrets }
        return secrets.filter {
            $0.name.localizedCaseInsensitiveContains(searchQuery) ||
            $0.note.localizedCaseInsensitiveContains(searchQuery)
        }
    }

    // MARK: - Init

    init() {
        checkVaultExists()
    }

    func checkVaultExists() {
        isInitialized = FileManager.default.fileExists(atPath: VaultService.vaultPath.path)
    }

    // MARK: - Vault Operations

    func initialize(password: String) async {
        isLoading = true
        defer { isLoading = false }
        do {
            try await vault.initialize(password: password)
            isInitialized = true
            isUnlocked = true
            try await refreshSecrets()
        } catch {
            showError(error)
        }
    }

    func unlock(password: String) async {
        isLoading = true
        defer { isLoading = false }
        do {
            try await vault.unlock(password: password)
            isUnlocked = true
            try await refreshSecrets()
        } catch VaultError.wrongPassword {
            errorMessage = "Wrong password. Try again."
            showError = true
        } catch {
            showError(error)
        }
    }

    func lock() {
        Task {
            await vault.lock()
            isUnlocked = false
            secrets = []
            auditEntries = []
        }
    }

    func unlockWithBiometrics() async {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            errorMessage = "Biometrics not available: \(error?.localizedDescription ?? "unknown")"
            showError = true
            return
        }

        do {
            let reason = "Unlock Keep vault"
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            if success {
                // Biometrics authenticated — but we still need the actual vault password.
                // For a real Touch ID integration we'd store the key in the Secure Enclave.
                // For now, Touch ID is a gate before password entry.
                // Future: store derived key in Keychain, Touch ID unlocks Keychain.
                errorMessage = "Touch ID authenticated. Now enter your vault password."
                showError = true
            }
        } catch {
            errorMessage = "Biometrics failed: \(error.localizedDescription)"
            showError = true
        }
    }

    // MARK: - Secret Operations

    func setSecret(name: String, value: String, note: String = "") async {
        isLoading = true
        defer { isLoading = false }
        do {
            try await vault.set(name: name, value: value, note: note)
            try await refreshSecrets()
        } catch {
            showError(error)
        }
    }

    func getSecretValue(name: String) async -> String? {
        do {
            return try await vault.get(name: name)
        } catch {
            showError(error)
            return nil
        }
    }

    func deleteSecret(name: String) async {
        isLoading = true
        defer { isLoading = false }
        do {
            _ = try await vault.delete(name: name)
            try await refreshSecrets()
        } catch {
            showError(error)
        }
    }

    func rotateSecret(name: String, length: Int = 32) async -> String? {
        isLoading = true
        defer { isLoading = false }
        do {
            let newVal = try await vault.rotate(name: name, length: length)
            try await refreshSecrets()
            return newVal
        } catch {
            showError(error)
            return nil
        }
    }

    func refreshSecrets() async throws {
        secrets = try await vault.list()
    }

    // MARK: - Audit

    func refreshAuditLog() async {
        do {
            auditEntries = try await vault.getAuditLog(limit: 100)
        } catch {
            showError(error)
        }
    }

    // MARK: - Status

    func getStats() async -> VaultStats? {
        do {
            return try await vault.stats()
        } catch {
            return nil
        }
    }

    // MARK: - Helpers

    private func showError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }

    nonisolated private func showError(_ msg: String) {
        Task { @MainActor in
            self.errorMessage = msg
            self.showError = true
        }
    }
}
