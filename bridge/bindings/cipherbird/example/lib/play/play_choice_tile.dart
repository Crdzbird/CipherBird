import 'package:cipherbird_example/play/play_choice.dart';
import 'package:flutter/material.dart';

/// A drop-down for one [PlayChoice].
final class PlayChoiceTile extends StatelessWidget {
  const PlayChoiceTile(this.choice, {super.key});

  final PlayChoice choice;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 10),
    child: ValueListenableBuilder<String>(
      valueListenable: choice.selected,
      builder: (context, value, _) => DropdownButtonFormField<String>(
        initialValue: value,
        isExpanded: true,
        decoration: InputDecoration(
          labelText: choice.label,
          border: const OutlineInputBorder(),
        ),
        items: [
          for (final o in choice.options)
            DropdownMenuItem<String>(value: o, child: Text(o)),
        ],
        onChanged: (v) {
          if (v != null) {
            choice.selected.value = v;
          }
        },
      ),
    ),
  );
}
