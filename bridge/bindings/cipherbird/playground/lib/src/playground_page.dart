import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_playground/src/result_block.dart';
import 'package:cipherbird_playground/src/self_test.dart';
import 'package:flutter/material.dart';

part 'playground_actions.dart';
part 'playground_page_state.dart';

final class PlaygroundPage extends StatefulWidget {
  const PlaygroundPage({super.key});

  @override
  State<PlaygroundPage> createState() => _PlaygroundPageState();
}
