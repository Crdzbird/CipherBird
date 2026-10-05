import 'package:flutter/material.dart';

final class ResultBlock extends StatelessWidget {
  const ResultBlock({required this.title, required this.body, super.key});

  final String title;
  final String body;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(top: 12),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: Theme.of(context).textTheme.labelLarge),
        SelectableText(
          body,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
        ),
      ],
    ),
  );
}
