import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import '../cryptolib_ffi.dart';
import '../widgets/hex_display.dart';
import '../widgets/result_card.dart';

enum PayloadType { text, file }

enum ExtractMode { text, file }

class StegoPage extends StatefulWidget {
  final CryptoLib lib;

  const StegoPage({super.key, required this.lib});

  @override
  State<StegoPage> createState() => _StegoPageState();
}

class _StegoPageState extends State<StegoPage>
    with AutomaticKeepAliveClientMixin {
  final _payloadController = TextEditingController();

  String? _coverPath;
  String? _stegoPath;
  String? _detectedCoverFormat;
  String? _detectedStegoFormat;
  int _capacity = 0;
  String? _error;
  String _extractedText = '';
  String _extractedHex = '';
  String? _outputPath;

  // Payload type toggle
  PayloadType _payloadType = PayloadType.text;

  // File payload state
  String? _payloadFilePath;
  String? _payloadFileName;
  int _payloadFileSize = 0;

  // Extract mode toggle
  ExtractMode _extractMode = ExtractMode.text;
  String? _extractedFilePath;
  int _extractedFileSize = 0;

  // Format classification
  static const _fullSupportFormats = {
    'ppm', 'bmp', 'png', 'gif', 'wav', 'crvf', 'avi',
  };
  static const _experimentalFormats = {
    'jpg', 'jpeg', 'mp3', 'mp4', 'flac',
  };
  static const _experimentalWarnings = <String, String>{
    'jpg': 'JSteg embedding. Chi-square detectable.',
    'jpeg': 'JSteg embedding. Chi-square detectable.',
    'mp3': 'Ancillary data embedding. Re-encoders may strip data.',
    'mp4': 'Free-box container. Destroyed by re-encoding.',
    'flac': 'Output converted to WAV internally.',
  };

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _payloadController.dispose();
    super.dispose();
  }

  String? _detectFormat(String path) {
    final ext = p.extension(path).toLowerCase().replaceFirst('.', '');
    if (ext.isEmpty) return null;
    if (_fullSupportFormats.contains(ext) ||
        _experimentalFormats.contains(ext)) {
      return ext;
    }
    return ext; // still return it so UI can show "unsupported"
  }

  bool _isExperimental(String? fmt) =>
      fmt != null && _experimentalFormats.contains(fmt);

  bool _isSupported(String? fmt) =>
      fmt != null &&
      (_fullSupportFormats.contains(fmt) ||
          _experimentalFormats.contains(fmt));

  Future<void> _pickCoverFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select cover media file',
      type: FileType.any,
    );
    if (result != null && result.files.single.path != null) {
      final path = result.files.single.path!;
      final fmt = _detectFormat(path);
      int cap = 0;
      try {
        cap = widget.lib.stegoCapacity(path);
      } catch (_) {
        cap = 0;
      }
      setState(() {
        _coverPath = path;
        _detectedCoverFormat = fmt;
        _capacity = cap;
        _error = null;
        _outputPath = null;
        _extractedText = '';
        _extractedHex = '';
        _extractedFilePath = null;
        _extractedFileSize = 0;
      });
    }
  }

  Future<void> _pickStegoFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select stego file to extract from',
      type: FileType.any,
    );
    if (result != null && result.files.single.path != null) {
      final path = result.files.single.path!;
      setState(() {
        _stegoPath = path;
        _detectedStegoFormat = _detectFormat(path);
        _extractedText = '';
        _extractedHex = '';
        _extractedFilePath = null;
        _extractedFileSize = 0;
        _error = null;
      });
    }
  }

  Future<void> _pickPayloadFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select file to hide',
      type: FileType.any,
    );
    if (result != null && result.files.single.path != null) {
      final path = result.files.single.path!;
      final file = File(path);
      final size = file.lengthSync();
      setState(() {
        _payloadFilePath = path;
        _payloadFileName = p.basename(path);
        _payloadFileSize = size;
        _error = null;
      });
    }
  }

  Future<void> _embed() async {
    if (_coverPath == null) {
      setState(() => _error = 'Select a cover file first.');
      return;
    }

    Uint8List payload;

    if (_payloadType == PayloadType.text) {
      final payloadText = _payloadController.text;
      if (payloadText.isEmpty) {
        setState(() => _error = 'Enter a payload to embed.');
        return;
      }
      payload = Uint8List.fromList(utf8.encode(payloadText));
    } else {
      if (_payloadFilePath == null) {
        setState(() => _error = 'Select a file to embed.');
        return;
      }
      try {
        final fileBytes = File(_payloadFilePath!).readAsBytesSync();
        // Prepend filename header: [len_hi][len_lo][filename_bytes...][file_data]
        final nameBytes = utf8.encode(p.basename(_payloadFilePath!));
        final nameLen = nameBytes.length.clamp(0, 65535);
        final header = Uint8List(2 + nameLen);
        header[0] = (nameLen >> 8) & 0xFF;
        header[1] = nameLen & 0xFF;
        header.setRange(2, 2 + nameLen, nameBytes);
        payload = Uint8List(header.length + fileBytes.length);
        payload.setRange(0, header.length, header);
        payload.setRange(header.length, payload.length, fileBytes);
      } catch (e) {
        setState(() => _error = 'Failed to read payload file: $e');
        return;
      }
    }

    if (payload.length > _capacity && _capacity > 0) {
      setState(() => _error =
          'Payload (${payload.length} bytes) exceeds capacity ($_capacity bytes).');
      return;
    }

    try {
      // Generate output path in temp directory
      final tempDir = await getTemporaryDirectory();
      final ext = _coverPath!.split('.').last;
      final outPath =
          '${tempDir.path}/stego_output_${DateTime.now().millisecondsSinceEpoch}.$ext';

      widget.lib.stegoEmbed(_coverPath!, payload, outPath);

      setState(() {
        _outputPath = outPath;
        _stegoPath = outPath;
        _detectedStegoFormat = _detectFormat(outPath);
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  Future<void> _extract() async {
    final path = _stegoPath;
    if (path == null) {
      setState(() => _error = 'Select or embed a stego file first.');
      return;
    }

    try {
      final data = widget.lib.stegoExtract(path);

      if (_extractMode == ExtractMode.text) {
        setState(() {
          _extractedHex = toHex(data);
          _extractedFilePath = null;
          _extractedFileSize = 0;
          try {
            _extractedText = utf8.decode(data);
          } catch (_) {
            _extractedText = '(binary data, see hex below)';
          }
          _error = null;
        });
      } else {
        // File extraction mode: parse filename header and save
        final tempDir = await getTemporaryDirectory();
        String outName = 'stego_extracted_${DateTime.now().millisecondsSinceEpoch}.bin';
        Uint8List fileData = data;

        // Try to parse filename header: [len_hi][len_lo][filename...][data]
        if (data.length >= 2) {
          final nameLen = (data[0] << 8) | data[1];
          if (nameLen > 0 && nameLen < 1024 && data.length >= 2 + nameLen) {
            try {
              final name = utf8.decode(data.sublist(2, 2 + nameLen));
              if (name.contains('.') && !name.contains('/') && !name.contains('\\')) {
                outName = name;
                fileData = data.sublist(2 + nameLen);
              }
            } catch (_) {
              // Not a valid filename header — save raw bytes
            }
          }
        }

        final outPath = '${tempDir.path}/$outName';
        File(outPath).writeAsBytesSync(fileData);
        setState(() {
          _extractedFilePath = outPath;
          _extractedFileSize = fileData.length;
          _extractedText = '';
          _extractedHex = '';
          _error = null;
        });
      }
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  Widget _buildFormatChip(String label, {required bool experimental}) {
    return Chip(
      label: Text(
        label.toUpperCase(),
        style: TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.w600,
          color: experimental ? Colors.orange.shade900 : Colors.green.shade900,
        ),
      ),
      backgroundColor:
          experimental ? Colors.amber.shade100 : Colors.green.shade100,
      side: BorderSide(
        color: experimental ? Colors.amber.shade300 : Colors.green.shade300,
      ),
      padding: const EdgeInsets.symmetric(horizontal: 4),
      materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
      visualDensity: VisualDensity.compact,
    );
  }

  Widget _buildFormatSupportCard(ThemeData theme) {
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: theme.colorScheme.outlineVariant),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.info_outline,
                    size: 18, color: theme.colorScheme.primary),
                const SizedBox(width: 8),
                Text(
                  'Supported Formats',
                  style: theme.textTheme.titleSmall,
                ),
              ],
            ),
            const SizedBox(height: 12),
            _buildFormatRow('Images', ['PPM', 'BMP', 'PNG', 'GIF'],
                ['JPEG']),
            const SizedBox(height: 8),
            _buildFormatRow(
                'Audio', ['WAV'], ['FLAC', 'MP3']),
            const SizedBox(height: 8),
            _buildFormatRow(
                'Video', ['CRVF', 'AVI'], ['MP4']),
            const SizedBox(height: 12),
            Row(
              children: [
                Container(
                  width: 10,
                  height: 10,
                  decoration: BoxDecoration(
                    color: Colors.green.shade100,
                    border: Border.all(color: Colors.green.shade300),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
                const SizedBox(width: 6),
                Text('Full Support',
                    style: TextStyle(
                        fontSize: 11, color: Colors.green.shade800)),
                const SizedBox(width: 16),
                Container(
                  width: 10,
                  height: 10,
                  decoration: BoxDecoration(
                    color: Colors.amber.shade100,
                    border: Border.all(color: Colors.amber.shade300),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
                const SizedBox(width: 6),
                Text('Experimental',
                    style: TextStyle(
                        fontSize: 11, color: Colors.orange.shade800)),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFormatRow(
      String category, List<String> full, List<String> experimental) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        SizedBox(
          width: 56,
          child: Text(
            category,
            style: const TextStyle(
                fontSize: 12, fontWeight: FontWeight.w500),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: Wrap(
            spacing: 6,
            runSpacing: 4,
            children: [
              ...full.map(
                  (f) => _buildFormatChip(f, experimental: false)),
              ...experimental.map(
                  (f) => _buildFormatChip(f, experimental: true)),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildFormatDetection(
      String? format, String label, ThemeData theme) {
    if (format == null) return const SizedBox.shrink();

    final isExp = _isExperimental(format);
    final supported = _isSupported(format);
    final warning = _experimentalWarnings[format];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(
              supported ? Icons.check_circle : Icons.error,
              size: 16,
              color: !supported
                  ? Colors.red
                  : isExp
                      ? Colors.orange
                      : Colors.green,
            ),
            const SizedBox(width: 8),
            Text(
              '$label format detected: ',
              style: const TextStyle(fontSize: 13),
            ),
            _buildFormatChip(format, experimental: isExp),
          ],
        ),
        if (isExp && warning != null)
          Padding(
            padding: const EdgeInsets.only(top: 6, left: 24),
            child: Row(
              children: [
                const Icon(Icons.warning_amber, size: 14,
                    color: Colors.orange),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    warning,
                    style: TextStyle(
                      fontSize: 12,
                      color: Colors.orange.shade800,
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ),
              ],
            ),
          ),
        if (!supported)
          Padding(
            padding: const EdgeInsets.only(top: 6, left: 24),
            child: Text(
              'This format is not recognized. Embedding may fail.',
              style: TextStyle(
                fontSize: 12,
                color: Colors.red.shade700,
                fontStyle: FontStyle.italic,
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildPayloadTypeToggle(ThemeData theme) {
    return SegmentedButton<PayloadType>(
      segments: const [
        ButtonSegment<PayloadType>(
          value: PayloadType.text,
          label: Text('Text Payload'),
          icon: Icon(Icons.text_fields, size: 18),
        ),
        ButtonSegment<PayloadType>(
          value: PayloadType.file,
          label: Text('File Payload'),
          icon: Icon(Icons.attach_file, size: 18),
        ),
      ],
      selected: {_payloadType},
      onSelectionChanged: (selected) {
        setState(() {
          _payloadType = selected.first;
          _error = null;
        });
      },
    );
  }

  Widget _buildFilePayloadSelector(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        FilledButton.tonalIcon(
          onPressed: _pickPayloadFile,
          icon: const Icon(Icons.upload_file, size: 18),
          label: const Text('Select File to Hide'),
        ),
        if (_payloadFilePath != null) ...[
          const SizedBox(height: 12),
          Card(
            elevation: 0,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
              side: BorderSide(color: theme.colorScheme.outlineVariant),
            ),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.insert_drive_file, size: 20),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          _payloadFileName ?? '',
                          style: const TextStyle(
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Text(
                        'Size: ${_formatBytes(_payloadFileSize)}',
                        style: TextStyle(
                          fontSize: 13,
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Text(
                        'Type: ${p.extension(_payloadFilePath!).isNotEmpty ? p.extension(_payloadFilePath!).substring(1).toUpperCase() : "Unknown"}',
                        style: TextStyle(
                          fontSize: 13,
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                  if (_capacity > 0 && _payloadFileSize > _capacity) ...[
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        const Icon(Icons.warning_amber, size: 16,
                            color: Colors.red),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'File size (${_formatBytes(_payloadFileSize)}) exceeds cover capacity (${_formatBytes(_capacity)}).',
                            style: TextStyle(
                              fontSize: 12,
                              color: Colors.red.shade700,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildExtractModeToggle(ThemeData theme) {
    return SegmentedButton<ExtractMode>(
      segments: const [
        ButtonSegment<ExtractMode>(
          value: ExtractMode.text,
          label: Text('Extract as Text'),
          icon: Icon(Icons.text_fields, size: 18),
        ),
        ButtonSegment<ExtractMode>(
          value: ExtractMode.file,
          label: Text('Extract as File'),
          icon: Icon(Icons.save_alt, size: 18),
        ),
      ],
      selected: {_extractMode},
      onSelectionChanged: (selected) {
        setState(() {
          _extractMode = selected.first;
          _error = null;
        });
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final theme = Theme.of(context);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Steganography',
            style: theme.textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            'Hide data inside media files using DCT/QIM (images), phase coding (audio), '
            'or per-frame embedding (video). The StegoEngine auto-detects the format '
            'from the file extension.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 16),

          // -- Format support info --
          _buildFormatSupportCard(theme),
          const SizedBox(height: 24),

          // -- Embed section --
          Text('Embed Payload', style: theme.textTheme.titleMedium),
          const SizedBox(height: 16),

          Row(
            children: [
              FilledButton.icon(
                onPressed: _pickCoverFile,
                icon: const Icon(Icons.image, size: 18),
                label: const Text('Select Cover File'),
              ),
              const SizedBox(width: 16),
              if (_coverPath != null)
                Expanded(
                  child: Text(
                    _coverPath!,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
            ],
          ),
          const SizedBox(height: 12),

          if (_coverPath != null) ...[
            _buildFormatDetection(
                _detectedCoverFormat, 'Cover', theme),
            const SizedBox(height: 12),
            Card(
              elevation: 0,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
                side: BorderSide(color: theme.colorScheme.outlineVariant),
              ),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  children: [
                    const Icon(Icons.storage, size: 20),
                    const SizedBox(width: 12),
                    Text('Steganographic capacity: '),
                    Text(
                      _capacity > 0 ? _formatBytes(_capacity) : 'unknown',
                      style: const TextStyle(fontWeight: FontWeight.bold),
                    ),
                  ],
                ),
              ),
            ),
          ],
          const SizedBox(height: 16),

          // -- Payload type toggle --
          _buildPayloadTypeToggle(theme),
          const SizedBox(height: 16),

          // -- Text or File payload input --
          if (_payloadType == PayloadType.text)
            TextField(
              controller: _payloadController,
              decoration: const InputDecoration(
                labelText: 'Payload',
                hintText: 'Enter text to hide...',
                border: OutlineInputBorder(),
              ),
              maxLines: 3,
            )
          else
            _buildFilePayloadSelector(theme),
          const SizedBox(height: 16),

          FilledButton.icon(
            onPressed: _embed,
            icon: const Icon(Icons.hide_image, size: 18),
            label: const Text('Embed'),
          ),
          const SizedBox(height: 12),

          if (_outputPath != null)
            ResultCard.success(
              'Output: $_outputPath',
              title: 'Embedding Successful',
            ),

          const SizedBox(height: 32),
          const Divider(),
          const SizedBox(height: 16),

          // -- Extract section --
          Text('Extract Payload', style: theme.textTheme.titleMedium),
          const SizedBox(height: 16),

          Row(
            children: [
              FilledButton.tonalIcon(
                onPressed: _pickStegoFile,
                icon: const Icon(Icons.file_open, size: 18),
                label: const Text('Select Stego File'),
              ),
              const SizedBox(width: 16),
              if (_stegoPath != null)
                Expanded(
                  child: Text(
                    _stegoPath!,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
            ],
          ),
          const SizedBox(height: 12),

          if (_stegoPath != null)
            _buildFormatDetection(
                _detectedStegoFormat, 'Stego', theme),
          const SizedBox(height: 16),

          // -- Extract mode toggle --
          _buildExtractModeToggle(theme),
          const SizedBox(height: 16),

          OutlinedButton.icon(
            onPressed: _extract,
            icon: const Icon(Icons.visibility, size: 18),
            label: const Text('Extract'),
          ),
          const SizedBox(height: 16),

          if (_error != null) ResultCard.error(_error!),

          if (_extractedText.isNotEmpty) ...[
            ResultCard.success(
              _extractedText,
              title: 'Extracted Payload',
            ),
            const SizedBox(height: 12),
            HexDisplay(label: 'Extracted (hex)', hexString: _extractedHex),
          ],

          if (_extractedFilePath != null) ...[
            ResultCard.success(
              'Saved to: $_extractedFilePath\nSize: ${_formatBytes(_extractedFileSize)}',
              title: 'Extracted File',
            ),
          ],

          const SizedBox(height: 32),
        ],
      ),
    );
  }
}
