import SwiftUI
import AppKit
import UniformTypeIdentifiers

// MARK: - Format metadata

enum StegoFormatSupport {
    case full
    case experimental
}

struct StegoFormat: Identifiable {
    let id: String          // file extension (lowercase)
    let label: String       // display name
    let category: String    // "Image", "Audio", "Video"
    let support: StegoFormatSupport
    let warning: String?    // shown when experimental format is selected

    var isFull: Bool { support == .full }
}

private let allFormats: [StegoFormat] = [
    // Images
    StegoFormat(id: "ppm",  label: "PPM",  category: "Image", support: .full,         warning: nil),
    StegoFormat(id: "bmp",  label: "BMP",  category: "Image", support: .full,         warning: nil),
    StegoFormat(id: "png",  label: "PNG",  category: "Image", support: .full,         warning: nil),
    StegoFormat(id: "gif",  label: "GIF",  category: "Image", support: .full,         warning: nil),
    StegoFormat(id: "jpg",  label: "JPEG", category: "Image", support: .experimental, warning: "JSteg embedding \u{2014} chi-square detectable"),
    // Audio
    StegoFormat(id: "wav",  label: "WAV",  category: "Audio", support: .full,         warning: nil),
    StegoFormat(id: "flac", label: "FLAC", category: "Audio", support: .experimental, warning: "Output converted to WAV internally"),
    StegoFormat(id: "mp3",  label: "MP3",  category: "Audio", support: .experimental, warning: "Ancillary data \u{2014} may be stripped by re-encoders"),
    // Video
    StegoFormat(id: "crvf", label: "CRVF", category: "Video", support: .full,         warning: nil),
    StegoFormat(id: "avi",  label: "AVI",  category: "Video", support: .full,         warning: nil),
    StegoFormat(id: "mp4",  label: "MP4",  category: "Video", support: .experimental, warning: "Free-box container \u{2014} destroyed by re-encoding"),
]

private let experimentalExtensions: Set<String> = Set(
    allFormats.filter { $0.support == .experimental }.map { $0.id }
).union(["jpeg"]) // .jpeg is an alias for .jpg

private func formatForExtension(_ ext: String) -> StegoFormat? {
    let lower = ext.lowercased()
    if lower == "jpeg" { return allFormats.first { $0.id == "jpg" } }
    return allFormats.first { $0.id == lower }
}

// MARK: - Payload mode enums

enum PayloadMode: String, CaseIterable, Identifiable {
    case text = "Text"
    case file = "File"
    var id: String { rawValue }
}

enum ExtractMode: String, CaseIterable, Identifiable {
    case text = "Extract as Text"
    case file = "Extract as File"
    var id: String { rawValue }
}

// MARK: - View model

@Observable
final class SteganographyViewModel {
    var coverFilePath: String?
    var stegoFilePath: String?
    var outputFilePath: String?
    var payload = "Hidden message inside media"
    var capacity: Int = 0
    var errorMessage: String?
    var isProcessing = false
    var embedSuccess = false
    var extractedPayload: String?

    // Payload mode
    var payloadMode: PayloadMode = .text

    // File payload state
    var payloadFilePath: String?
    var payloadFileName: String?
    var payloadFileSize: UInt64 = 0
    var payloadFileExtension: String?

    // Extract mode
    var extractMode: ExtractMode = .text
    var extractedFilePath: String?
    var extractedFileSize: UInt64 = 0

    // File size info
    var coverFileSize: UInt64 = 0
    var outputFileSize: UInt64 = 0

    // Detected format
    var detectedFormat: StegoFormat?
    var formatWarning: String?

    /// The byte count of the current payload (text or file).
    var currentPayloadSize: Int {
        switch payloadMode {
        case .text:
            return payload.data(using: .utf8)?.count ?? 0
        case .file:
            return Int(payloadFileSize)
        }
    }

    func updateDetectedFormat() {
        guard let path = coverFilePath else {
            detectedFormat = nil
            formatWarning = nil
            return
        }
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        detectedFormat = formatForExtension(ext)
        formatWarning = detectedFormat?.warning
    }

    func checkCapacity(bridge: CryptoLibBridge) {
        guard let path = coverFilePath else { return }
        capacity = bridge.stegoCapacity(path)

        if let attrs = try? FileManager.default.attributesOfItem(atPath: path) {
            coverFileSize = attrs[.size] as? UInt64 ?? 0
        }
    }

    func selectPayloadFile(url: URL) {
        payloadFilePath = url.path
        payloadFileName = url.lastPathComponent
        payloadFileExtension = url.pathExtension.isEmpty ? nil : url.pathExtension
        if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path) {
            payloadFileSize = attrs[.size] as? UInt64 ?? 0
        } else {
            payloadFileSize = 0
        }
    }

    func embed(bridge: CryptoLibBridge) {
        guard let coverPath = coverFilePath else {
            errorMessage = "Select a cover file first"
            return
        }

        // Generate output path
        let url = URL(fileURLWithPath: coverPath)
        let ext = url.pathExtension
        let name = url.deletingPathExtension().lastPathComponent
        let dir = url.deletingLastPathComponent().path
        let outPath = "\(dir)/\(name)_stego.\(ext)"

        let payloadData: Data
        switch payloadMode {
        case .text:
            guard let textData = payload.data(using: .utf8) else {
                errorMessage = "Invalid payload"
                return
            }
            payloadData = textData
        case .file:
            guard let filePath = payloadFilePath else {
                errorMessage = "Select a file to hide first"
                return
            }
            do {
                let fileBytes = try Data(contentsOf: URL(fileURLWithPath: filePath))
                // Prepend filename header: [len_hi][len_lo][filename_bytes...][file_data]
                let nameStr = URL(fileURLWithPath: filePath).lastPathComponent
                let nameBytes = Array(nameStr.utf8)
                let nameLen = min(nameBytes.count, 65535)
                var header = Data([UInt8((nameLen >> 8) & 0xFF), UInt8(nameLen & 0xFF)])
                header.append(contentsOf: nameBytes.prefix(nameLen))
                payloadData = header + fileBytes
            } catch {
                errorMessage = "Failed to read payload file: \(error.localizedDescription)"
                return
            }
        }

        if payloadData.count > capacity {
            errorMessage = "Payload (\(payloadData.count) bytes) exceeds capacity (\(capacity) bytes)"
            return
        }

        errorMessage = nil
        isProcessing = true
        embedSuccess = false
        extractedPayload = nil
        extractedFilePath = nil

        do {
            try bridge.stegoEmbed(coverPath, payload: payloadData, outputPath: outPath)
            outputFilePath = outPath
            embedSuccess = true

            if let attrs = try? FileManager.default.attributesOfItem(atPath: outPath) {
                outputFileSize = attrs[.size] as? UInt64 ?? 0
            }
        } catch {
            errorMessage = error.localizedDescription
        }
        isProcessing = false
    }

    func extract(bridge: CryptoLibBridge) {
        let path: String
        if let stegoPath = stegoFilePath {
            path = stegoPath
        } else if let outPath = outputFilePath {
            path = outPath
        } else {
            errorMessage = "No stego file to extract from"
            return
        }

        errorMessage = nil
        isProcessing = true
        extractedPayload = nil
        extractedFilePath = nil

        do {
            let data = try bridge.stegoExtract(path)

            switch extractMode {
            case .text:
                extractedPayload = String(data: data, encoding: .utf8) ?? data.hexString
            case .file:
                // Parse filename header: [len_hi][len_lo][filename...][data]
                var saveData = data
                var defaultName = "extracted_payload"
                if data.count >= 2 {
                    let nameLen = Int(data[0]) << 8 | Int(data[1])
                    if nameLen > 0 && nameLen < 1024 && data.count >= 2 + nameLen {
                        if let name = String(data: data[2..<(2 + nameLen)], encoding: .utf8),
                           name.contains(".") && !name.contains("/") && !name.contains("\\") {
                            defaultName = name
                            saveData = data.suffix(from: 2 + nameLen)
                        }
                    }
                }

                let panel = NSSavePanel()
                panel.canCreateDirectories = true
                panel.nameFieldStringValue = defaultName
                panel.message = "Choose where to save the extracted file"

                if panel.runModal() == .OK, let saveURL = panel.url {
                    try saveData.write(to: saveURL)
                    extractedFilePath = saveURL.path
                    extractedFileSize = UInt64(saveData.count)
                } else {
                    errorMessage = "Save cancelled"
                }
            }
        } catch {
            errorMessage = error.localizedDescription
        }
        isProcessing = false
    }
}

// MARK: - Main view

struct SteganographyView: View {
    let bridge: CryptoLibBridge
    @State private var vm = SteganographyViewModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                headerSection
                supportedFormatsSection
                coverFileSection
                detectedFormatSection
                capacitySection
                payloadSection
                embedSection
                extractSection
                comparisonSection
            }
            .padding()
        }
        .navigationTitle("Steganography")
    }

    // MARK: Header

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Steganography")
                .font(.title2.bold())
            Text("Hide data inside media files using DCT/QIM (images), phase coding (audio), or per-frame embedding (video).")
                .foregroundStyle(.secondary)
        }
    }

    // MARK: Supported Formats

    private var supportedFormatsSection: some View {
        GroupBox("Supported Formats") {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(["Image", "Audio", "Video"], id: \.self) { category in
                    formatRow(for: category)
                }

                Divider()

                HStack(spacing: 16) {
                    HStack(spacing: 4) {
                        Circle().fill(.green).frame(width: 8, height: 8)
                        Text("Fully supported")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: 4) {
                        Circle().fill(.orange).frame(width: 8, height: 8)
                        Text("Experimental")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(.vertical, 4)
        }
    }

    private func formatRow(for category: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(category)
                .font(.subheadline.weight(.semibold))
                .frame(width: 50, alignment: .leading)

            FlowLayout(spacing: 6) {
                ForEach(allFormats.filter { $0.category == category }) { fmt in
                    Text(fmt.label)
                        .font(.caption.weight(.medium))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(fmt.isFull ? Color.green.opacity(0.15) : Color.orange.opacity(0.15))
                        .foregroundColor(fmt.isFull ? .green : .orange)
                        .clipShape(Capsule())
                }
            }
        }
    }

    // MARK: Cover file

    private var coverFileSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Cover File")
                .font(.headline)
            FilePickerButton("Choose Cover Media", allowedContentTypes: [.item]) { url in
                vm.coverFilePath = url.path
                vm.updateDetectedFormat()
                vm.checkCapacity(bridge: bridge)
            }
        }
    }

    // MARK: Detected format + warning

    @ViewBuilder
    private var detectedFormatSection: some View {
        if let fmt = vm.detectedFormat {
            HStack(spacing: 6) {
                Image(systemName: "doc.text.magnifyingglass")
                    .foregroundStyle(.secondary)
                Text("Detected format:")
                    .foregroundStyle(.secondary)
                Text(fmt.label)
                    .fontWeight(.semibold)
                    .foregroundColor(fmt.isFull ? .green : .orange)
                Text("(\(fmt.category))")
                    .foregroundStyle(.secondary)
            }
            .font(.subheadline)

            if let warning = vm.formatWarning {
                Label {
                    Text(warning)
                        .font(.subheadline)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.orange.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        } else if vm.coverFilePath != nil {
            HStack(spacing: 6) {
                Image(systemName: "questionmark.circle")
                    .foregroundColor(.orange)
                Text("Unknown format \u{2014} the C library will attempt auto-detection.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: Capacity

    @ViewBuilder
    private var capacitySection: some View {
        if vm.coverFilePath != nil {
            GroupBox("File Info") {
                VStack(alignment: .leading, spacing: 6) {
                    LabeledContent("Cover File Size") {
                        Text(ByteCountFormatter.string(fromByteCount: Int64(vm.coverFileSize), countStyle: .file))
                    }
                    LabeledContent("Steganographic Capacity") {
                        Text("\(vm.capacity) bytes")
                            .foregroundColor(vm.capacity > 0 ? .primary : .red)
                    }

                    if vm.capacity > 0 {
                        let payloadSize = vm.currentPayloadSize
                        let fraction = min(Double(payloadSize) / Double(vm.capacity), 1.0)
                        Gauge(value: fraction) {
                            Text("Usage")
                        } currentValueLabel: {
                            Text("\(payloadSize) / \(vm.capacity) bytes")
                        }
                        .tint(fraction < 0.75 ? .green : (fraction < 1.0 ? .orange : .red))
                    }
                }
                .padding(.vertical, 4)
            }
        }
    }

    // MARK: Payload

    private var payloadSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Payload")
                    .font(.headline)
                Spacer()
                Picker("Payload Type", selection: $vm.payloadMode) {
                    ForEach(PayloadMode.allCases) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 160)
            }

            switch vm.payloadMode {
            case .text:
                textPayloadContent
            case .file:
                filePayloadContent
            }
        }
    }

    private var textPayloadContent: some View {
        VStack(alignment: .leading, spacing: 6) {
            TextEditor(text: $vm.payload)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 60, maxHeight: 100)
                .padding(4)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.tertiary))

            if let payloadData = vm.payload.data(using: .utf8) {
                Text("\(payloadData.count) bytes")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var filePayloadContent: some View {
        VStack(alignment: .leading, spacing: 8) {
            FilePickerButton("Select File to Hide", allowedContentTypes: [.item]) { url in
                vm.selectPayloadFile(url: url)
            }

            if let fileName = vm.payloadFileName {
                GroupBox {
                    VStack(alignment: .leading, spacing: 4) {
                        LabeledContent("File") {
                            Text(fileName)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        LabeledContent("Size") {
                            Text(ByteCountFormatter.string(fromByteCount: Int64(vm.payloadFileSize), countStyle: .file))
                        }
                        if let ext = vm.payloadFileExtension {
                            LabeledContent("Extension") {
                                Text(".\(ext)")
                                    .font(.system(.body, design: .monospaced))
                            }
                        }
                    }
                }

                if vm.capacity > 0 && vm.payloadFileSize > UInt64(vm.capacity) {
                    Label {
                        Text("File size (\(ByteCountFormatter.string(fromByteCount: Int64(vm.payloadFileSize), countStyle: .file))) exceeds capacity (\(vm.capacity) bytes)")
                            .font(.subheadline)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.red.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }
        }
    }

    // MARK: Embed

    private var embedSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Button {
                    vm.embed(bridge: bridge)
                } label: {
                    Label("Embed", systemImage: "eye.slash")
                }
                .buttonStyle(.borderedProminent)
                .disabled(vm.coverFilePath == nil || vm.isProcessing || vm.capacity <= 0 || (vm.payloadMode == .file && vm.payloadFilePath == nil))
            }

            if vm.isProcessing {
                ProgressView("Processing...")
            }

            if let error = vm.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundColor(.red)
            }

            if vm.embedSuccess, let outPath = vm.outputFilePath {
                Label("Embedded successfully", systemImage: "checkmark.circle.fill")
                    .foregroundColor(.green)
                Text("Output: \(outPath)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    // MARK: Extract

    private var extractSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            Text("Extract")
                .font(.title3.bold())

            Picker("Extract Mode", selection: $vm.extractMode) {
                ForEach(ExtractMode.allCases) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)

            HStack(spacing: 12) {
                FilePickerButton("Choose Stego File", allowedContentTypes: [.item]) { url in
                    vm.stegoFilePath = url.path
                }

                Button {
                    vm.extract(bridge: bridge)
                } label: {
                    Label("Extract", systemImage: "eye")
                }
                .buttonStyle(.bordered)
                .disabled((vm.stegoFilePath == nil && vm.outputFilePath == nil) || vm.isProcessing)
            }

            if vm.outputFilePath != nil && vm.stegoFilePath == nil {
                Text("Or extract from the embed output above.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            // Text extraction result
            if let extracted = vm.extractedPayload {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Extracted Payload")
                        .font(.headline)
                    Text(extracted)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.green.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }

            // File extraction result
            if let filePath = vm.extractedFilePath {
                VStack(alignment: .leading, spacing: 6) {
                    Label("File saved successfully", systemImage: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    LabeledContent("Path") {
                        Text(filePath)
                            .font(.caption)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                    LabeledContent("Size") {
                        Text(ByteCountFormatter.string(fromByteCount: Int64(vm.extractedFileSize), countStyle: .file))
                            .font(.caption)
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.green.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    // MARK: Comparison

    @ViewBuilder
    private var comparisonSection: some View {
        if vm.embedSuccess {
            Divider()
            GroupBox("File Comparison") {
                HStack(spacing: 20) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Original Cover")
                            .font(.subheadline.weight(.semibold))
                        Text(ByteCountFormatter.string(fromByteCount: Int64(vm.coverFileSize), countStyle: .file))
                            .font(.system(.body, design: .monospaced))
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(.quaternary)
                    .clipShape(RoundedRectangle(cornerRadius: 8))

                    Image(systemName: "arrow.right")
                        .font(.title2)
                        .foregroundStyle(.secondary)

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Stego Output")
                            .font(.subheadline.weight(.semibold))
                        Text(ByteCountFormatter.string(fromByteCount: Int64(vm.outputFileSize), countStyle: .file))
                            .font(.system(.body, design: .monospaced))
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(.quaternary)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                .padding(.vertical, 4)

                let diff = Int64(vm.outputFileSize) - Int64(vm.coverFileSize)
                Text("Size difference: \(diff >= 0 ? "+" : "")\(diff) bytes")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - FlowLayout helper

/// A simple horizontal flow layout that wraps items to the next line.
private struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let result = arrange(proposal: proposal, subviews: subviews)
        return result.size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = arrange(proposal: proposal, subviews: subviews)
        for (index, subview) in subviews.enumerated() {
            let point = CGPoint(
                x: bounds.minX + result.origins[index].x,
                y: bounds.minY + result.origins[index].y
            )
            subview.place(at: point, anchor: .topLeading, proposal: .unspecified)
        }
    }

    private func arrange(proposal: ProposedViewSize, subviews: Subviews) -> (origins: [CGPoint], size: CGSize) {
        let maxWidth = proposal.width ?? .infinity
        var origins: [CGPoint] = []
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        var totalWidth: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > maxWidth, x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            origins.append(CGPoint(x: x, y: y))
            rowHeight = max(rowHeight, size.height)
            x += size.width + spacing
            totalWidth = max(totalWidth, x - spacing)
        }

        return (origins, CGSize(width: totalWidth, height: y + rowHeight))
    }
}
