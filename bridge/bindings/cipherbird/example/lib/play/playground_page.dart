import 'package:cipherbird_example/play/playground.dart';
import 'package:flutter/material.dart';

/// Renders any [Playground]: its fields, its action buttons and its log.
final class PlaygroundPage extends StatelessWidget {
  const PlaygroundPage(this.model, {super.key});

  final Playground model;

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: Text(model.title),
      actions: [
        IconButton(
          onPressed: model.clear,
          icon: const Icon(Icons.delete_outline),
        ),
      ],
    ),
    body: ListenableBuilder(
      listenable: model,
      builder: (context, _) => ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(model.blurb, style: Theme.of(context).textTheme.bodyMedium),
          const SizedBox(height: 12),
          for (final f in model.fields)
            Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: TextField(
                controller: f.controller,
                maxLines: f.lines,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
                decoration: InputDecoration(
                  labelText: f.label,
                  border: const OutlineInputBorder(),
                ),
              ),
            ),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final a in model.actions)
                FilledButton.tonal(onPressed: a.run, child: Text(a.label)),
            ],
          ),
          const Divider(height: 32),
          for (final line in model.log)
            Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: SelectableText(
                line,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
        ],
      ),
    ),
  );
}
