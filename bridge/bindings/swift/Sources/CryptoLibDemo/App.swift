import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case hashing = "Hashing"
    case encryption = "Encryption"
    case asymmetric = "Asymmetric"
    case entropy = "Media Entropy"
    case vault = "Vault"
    case steganography = "Steganography"
    case advanced = "Advanced"
    case lavarandServer = "LavaRand Client"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .hashing: return "number.circle"
        case .encryption: return "lock.shield"
        case .asymmetric: return "arrow.left.arrow.right"
        case .entropy: return "waveform.circle"
        case .vault: return "archivebox"
        case .steganography: return "photo.on.rectangle"
        case .advanced: return "flask"
        case .lavarandServer: return "cloud"
        }
    }
}

struct ContentView: View {
    @State private var bridge = CryptoLibBridge()
    @State private var selectedItem: SidebarItem? = .hashing
    @State private var loadError: String?

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detailView
        }
        .navigationTitle("CryptoLib Demo")
        .onAppear {
            do {
                try bridge.load()
            } catch {
                loadError = error.localizedDescription
            }
        }
    }

    @ViewBuilder
    private var sidebar: some View {
        List(SidebarItem.allCases, selection: $selectedItem) { item in
            Label(item.rawValue, systemImage: item.icon)
                .tag(item)
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            VStack(alignment: .leading, spacing: 4) {
                if bridge.isLoaded {
                    Label("Library loaded", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    Text("v\(bridge.libraryVersion)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if let err = loadError {
                    Label("Load failed", systemImage: "xmark.circle.fill")
                        .foregroundStyle(.red)
                    Text(err)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(3)
                } else {
                    ProgressView("Loading...")
                }
            }
            .padding()
        }
    }

    @ViewBuilder
    private var detailView: some View {
        if !bridge.isLoaded {
            ContentUnavailableView(
                "Library Not Loaded",
                systemImage: "exclamationmark.triangle",
                description: Text(loadError ?? "Loading library...")
            )
        } else {
            switch selectedItem {
            case .hashing:
                HashingView(bridge: bridge)
            case .encryption:
                EncryptionView(bridge: bridge)
            case .asymmetric:
                AsymmetricView(bridge: bridge)
            case .entropy:
                EntropyView(bridge: bridge)
            case .vault:
                VaultView(bridge: bridge)
            case .steganography:
                SteganographyView(bridge: bridge)
            case .advanced:
                AdvancedView(bridge: bridge)
            case .lavarandServer:
                LavaRandClientView(bridge: bridge)
            case nil:
                ContentUnavailableView(
                    "Select a Feature",
                    systemImage: "sidebar.left",
                    description: Text("Choose a cryptographic feature from the sidebar.")
                )
            }
        }
    }
}
