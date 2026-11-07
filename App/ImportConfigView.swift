#if canImport(SwiftUI)
import SwiftUI
import SSHCore
import UniformTypeIdentifiers

/// Importera värdar från en `~/.ssh/config`. Välj filen via dokumentväljaren
/// (iCloud Drive/Files) eller klistra in innehållet.
struct ImportConfigView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    let onImport: (String) async -> Int   // returnerar antal importerade

    @State private var result: String?
    @State private var showFileImporter = false
    @State private var isImporting = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading) {
                Button {
                    showFileImporter = true
                } label: {
                    Label("Välj ssh-config-fil…", systemImage: "doc.badge.plus")
                }
                .padding(.horizontal)
                .disabled(isImporting)
                .fileImporter(isPresented: $showFileImporter,
                              allowedContentTypes: FileImport.textLike,
                              allowsMultipleSelection: false) { result in
                    if let content = FileImport.readText(from: result) { text = content }
                }
                Text("…eller klistra in innehållet i din ssh-config:")
                    .font(.footnote).foregroundStyle(.secondary).padding(.horizontal)
                TextEditor(text: $text)
                    .font(.system(.footnote, design: .monospaced))
                    .autocorrectionDisabled()
                    .noAutocap()
                    .border(Color.secondary.opacity(0.3))
                    .padding(.horizontal)
                    .disabled(isImporting)
                if isImporting { ProgressView().padding(.horizontal) }
                if let result { Text(result).font(.footnote).padding(.horizontal) }
            }
            .navigationTitle("Importera")
            .navInlineTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Avbryt") { dismiss() }.disabled(isImporting)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Importera") {
                        isImporting = true
                        let input = text
                        Task {
                            let n = await onImport(input)
                            result = "Importerade \(n) värd(ar)."
                            isImporting = false
                            if n > 0 { dismiss() }
                        }
                    }.disabled(text.isEmpty || isImporting)
                }
            }
            .interactiveDismissDisabled(isImporting)
        }
    }
}
#endif
