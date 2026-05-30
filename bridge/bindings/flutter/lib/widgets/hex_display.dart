import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Reusable widget: label, hex string in monospaced font, copy-to-clipboard button.
class HexDisplay extends StatelessWidget {
  final String label;
  final String hexString;
  final int? maxLines;

  const HexDisplay({
    super.key,
    required this.label,
    required this.hexString,
    this.maxLines,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(label, style: theme.textTheme.labelLarge?.copyWith(
              fontWeight: FontWeight.w600,
            )),
            const Spacer(),
            if (hexString.isNotEmpty)
              IconButton(
                icon: const Icon(Icons.copy, size: 18),
                tooltip: 'Copy to clipboard',
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: hexString));
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('$label copied to clipboard'),
                      duration: const Duration(seconds: 1),
                    ),
                  );
                },
              ),
          ],
        ),
        const SizedBox(height: 4),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: theme.colorScheme.outlineVariant),
          ),
          child: SelectableText(
            hexString.isEmpty ? '(empty)' : hexString,
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 13,
              color: hexString.isEmpty
                  ? theme.colorScheme.onSurfaceVariant
                  : theme.colorScheme.onSurface,
            ),
            maxLines: maxLines,
          ),
        ),
      ],
    );
  }
}
