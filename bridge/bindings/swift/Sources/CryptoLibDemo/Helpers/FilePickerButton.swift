import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct FilePickerButton: View {
    let title: String
    let allowedContentTypes: [UTType]
    let onPick: (URL) -> Void

    @State private var selectedPath: String?

    init(
        _ title: String = "Choose File",
        allowedContentTypes: [UTType] = [.item],
        onPick: @escaping (URL) -> Void
    ) {
        self.title = title
        self.allowedContentTypes = allowedContentTypes
        self.onPick = onPick
    }

    /// Legacy convenience: pass file extension strings.
    init(
        _ title: String = "Choose File",
        allowedTypes: [String],
        onPick: @escaping (URL) -> Void
    ) {
        self.title = title
        if allowedTypes.isEmpty {
            self.allowedContentTypes = [.item]
        } else {
            self.allowedContentTypes = allowedTypes.compactMap { UTType(filenameExtension: $0) }
        }
        self.onPick = onPick
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Button {
                openPanel()
            } label: {
                Label(title, systemImage: "folder")
            }

            if let path = selectedPath {
                Text(path)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
    }

    private func openPanel() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = title
        panel.treatsFilePackagesAsDirectories = false

        if allowedContentTypes != [.item] {
            panel.allowedContentTypes = allowedContentTypes
        }

        if panel.runModal() == .OK, let url = panel.url {
            selectedPath = url.path
            onPick(url)
        }
    }
}

struct SavePanelButton: View {
    let title: String
    let suggestedName: String
    let onSave: (URL) -> Void

    var body: some View {
        Button {
            let panel = NSSavePanel()
            panel.canCreateDirectories = true
            panel.nameFieldStringValue = suggestedName
            if panel.runModal() == .OK, let url = panel.url {
                onSave(url)
            }
        } label: {
            Label(title, systemImage: "square.and.arrow.down")
        }
    }
}
