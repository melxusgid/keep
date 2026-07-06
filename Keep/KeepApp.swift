import SwiftUI

@main
struct KeepApp: App {
    @StateObject private var model = VaultModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 600, minHeight: 400)
        }
        .windowResizability(.contentMinSize)
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(after: .importExport) {
                Button("Lock Vault") {
                    model.lock()
                }
                .keyboardShortcut("l", modifiers: [.command, .shift])
                .disabled(!model.isUnlocked)
            }
        }
    }
}
