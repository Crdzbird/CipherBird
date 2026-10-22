import 'dart:ui' as ui;

import 'package:cipherbird_example/play/play_picture.dart';
import 'package:flutter/material.dart';

/// Shows one [PlayPicture] with its label, or a placeholder.
final class PlayPictureTile extends StatelessWidget {
  const PlayPictureTile(this.picture, {super.key});

  final PlayPicture picture;

  @override
  Widget build(BuildContext context) => ValueListenableBuilder<ui.Image?>(
    valueListenable: picture.image,
    builder: (context, image, _) => Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 150,
          height: 150,
          decoration: BoxDecoration(
            border: Border.all(color: Theme.of(context).dividerColor),
          ),
          child: image == null
              ? const Center(child: Text('none'))
              : RawImage(image: image, fit: BoxFit.contain),
        ),
        const SizedBox(height: 4),
        Text(picture.label, style: Theme.of(context).textTheme.labelSmall),
      ],
    ),
  );
}
