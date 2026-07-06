import SwiftUI

struct SecretsListView: View {
    @EnvironmentObject var model: VaultModel
    @State private var showingAdd = false
    @State private var editingSecret: SecretItem?
    @State private var selectedSecret: SecretItem?
    @State private var secretValue: String?
    @State private var showValue = false

    var body: some View {
        VStack(spacing: 0) {
            // Search bar
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Search secrets...", text: $model.searchQuery)
                    .textFieldStyle(.plain)
                if !model.searchQuery.isEmpty {
                    Button { model.searchQuery = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(8)
            .background(Color(.textBackgroundColor))
            .cornerRadius(8)
            .padding(.horizontal)
            .padding(.vertical, 8)

            // Secret count
            HStack {
                Text("\(model.filteredSecrets.count) secret\(model.filteredSecrets.count == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
            }
            .padding(.horizontal)

            // List
            List {
                ForEach(model.filteredSecrets) { secret in
                    SecretRowView(
                        secret: secret,
                        onReveal: { Task { await revealValue(secret) } },
                        revealed: selectedSecret?.id == secret.id && showValue,
                        revealedValue: secretValue,
                        onEdit: { editingSecret = secret }
                    )
                    .contextMenu {
                        Button("Copy Value", systemImage: "doc.on.doc") {
                            Task { await copyValue(secret) }
                        }
                        Button("Edit", systemImage: "pencil") {
                            editingSecret = secret
                        }
                        Divider()
                        Button("Delete", systemImage: "trash", role: .destructive) {
                            Task { await model.deleteSecret(name: secret.name) }
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Add Secret", systemImage: "plus") {
                    showingAdd = true
                }
            }
        }
        .sheet(isPresented: $showingAdd) {
            SecretDetailView(mode: .add) { name, value, note in
                Task { await model.setSecret(name: name, value: value, note: note) }
            }
        }
        .sheet(item: $editingSecret) { secret in
            SecretDetailView(
                mode: .edit(name: secret.name, existingNote: secret.note)
            ) { name, value, note in
                Task { await model.setSecret(name: name, value: value, note: note) }
            }
        }
    }

    private func revealValue(_ secret: SecretItem) async {
        if selectedSecret?.id == secret.id && showValue {
            showValue = false
            secretValue = nil
            selectedSecret = nil
            return
        }
        selectedSecret = secret
        secretValue = await model.getSecretValue(name: secret.name)
        showValue = true
    }

    private func copyValue(_ secret: SecretItem) async {
        if let value = await model.getSecretValue(name: secret.name) {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(value, forType: .string)
        }
    }
}

// MARK: - Row

struct SecretRowView: View {
    let secret: SecretItem
    let onReveal: () -> Void
    let revealed: Bool
    let revealedValue: String?
    let onEdit: () -> Void

    var body: some View {
        HStack {
            // Icon
            Image(systemName: "key.fill")
                .foregroundColor(.accentColor)
                .font(.caption)

            VStack(alignment: .leading, spacing: 2) {
                Text(secret.name)
                    .font(.body)
                    .lineLimit(1)

                if revealed {
                    if let val = revealedValue {
                        Text(val)
                            .font(.caption.monospaced())
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    } else {
                        ProgressView()
                            .scaleEffect(0.6)
                    }
                } else if !secret.note.isEmpty {
                    Text(secret.note)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer()

            // Action buttons
            HStack(spacing: 8) {
                Button { onReveal() } label: {
                    Image(systemName: revealed ? "eye.slash.fill" : "eye.fill")
                        .font(.caption)
                }
                .buttonStyle(.plain)
                .help(revealed ? "Hide" : "Show value")

                Button { onEdit() } label: {
                    Image(systemName: "pencil")
                        .font(.caption)
                }
                .buttonStyle(.plain)
                .help("Edit")
            }
        }
        .padding(.vertical, 2)
    }
}
