import SwiftUI

enum SecretDetailMode {
    case add
    case edit(name: String, existingNote: String)

    var title: String {
        switch self {
        case .add: return "New Secret"
        case .edit(let name, _): return "Edit: \(name)"
        }
    }

    var isAdd: Bool {
        switch self { case .add: return true; case .edit: return false }
    }
}

struct SecretDetailView: View {
    let mode: SecretDetailMode
    let onSave: (String, String, String) -> Void

    @State private var name = ""
    @State private var value = ""
    @State private var note = ""
    @State private var showingGenerate = false
    @State private var generatedLength: Double = 32
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 20) {
            Text(mode.title)
                .font(.title2.bold())

            Form {
                if mode.isAdd {
                    TextField("Secret name", text: $name)
                        .textFieldStyle(.roundedBorder)
                } else {
                    TextField("Secret name", text: $name)
                        .textFieldStyle(.roundedBorder)
                        .disabled(true)
                }

                VStack(alignment: .leading, spacing: 4) {
                    TextField("Value", text: $value)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())

                    HStack {
                        Button("Generate Random", systemImage: "dice") {
                            showingGenerate.toggle()
                        }
                        .buttonStyle(.borderless)
                        .font(.caption)
                        Spacer()
                        Button("Paste from Clipboard", systemImage: "clipboard") {
                            value = NSPasteboard.general.string(forType: .string) ?? value
                        }
                        .buttonStyle(.borderless)
                        .font(.caption)
                    }
                }

                TextField("Note (optional)", text: $note)
                    .textFieldStyle(.roundedBorder)

                if showingGenerate {
                    VStack(spacing: 8) {
                        Slider(value: $generatedLength, in: 8...128, step: 8)
                        Text("Length: \(Int(generatedLength)) characters")
                            .font(.caption)
                        Button("Generate") {
                            value = generateRandom(length: Int(generatedLength))
                        }
                        .buttonStyle(.bordered)
                    }
                    .padding()
                    .background(Color(.textBackgroundColor))
                    .cornerRadius(8)
                }
            }
            .formStyle(.grouped)

            HStack {
                Button("Cancel", role: .cancel) { dismiss() }

                Button("Save") {
                    let secretName = mode.isAdd ? name : {
                        if case .edit(let n, _) = mode { return n }
                        return name
                    }()
                    onSave(secretName, value, note)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(name.isEmpty || value.isEmpty)
            }
            .padding(.bottom)
        }
        .padding()
        .frame(width: 420, height: showingGenerate ? 480 : 380)
        .onAppear {
            if case .edit(let n, let existingNote) = mode {
                name = n
                note = existingNote
            }
        }
    }

    private func generateRandom(length: Int) -> String {
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
        return String((0..<length).map { _ in chars.randomElement()! })
    }
}
