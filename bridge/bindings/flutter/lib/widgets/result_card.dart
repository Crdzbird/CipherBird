import 'package:flutter/material.dart';

/// Reusable Card widget showing success (green) or error (red) with message.
class ResultCard extends StatelessWidget {
  final bool isError;
  final String message;
  final String? title;

  const ResultCard({
    super.key,
    required this.isError,
    required this.message,
    this.title,
  });

  factory ResultCard.success(String message, {String? title}) {
    return ResultCard(isError: false, message: message, title: title);
  }

  factory ResultCard.error(String message, {String? title}) {
    return ResultCard(isError: true, message: message, title: title);
  }

  @override
  Widget build(BuildContext context) {
    final color = isError
        ? Theme.of(context).colorScheme.error
        : Colors.green.shade700;
    final bgColor = isError
        ? Theme.of(context).colorScheme.errorContainer
        : Colors.green.shade50;
    final icon = isError ? Icons.error_outline : Icons.check_circle_outline;

    return Card(
      color: bgColor,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: color.withValues(alpha: 0.3)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, color: color, size: 20),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (title != null)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 4),
                      child: Text(
                        title!,
                        style: TextStyle(
                          fontWeight: FontWeight.w600,
                          color: color,
                        ),
                      ),
                    ),
                  SelectableText(
                    message,
                    style: TextStyle(color: color, fontSize: 13),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
