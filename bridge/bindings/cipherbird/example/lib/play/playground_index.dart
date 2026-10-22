import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/entropy_playground.dart';
import 'package:cipherbird_example/play/fips_playground.dart';
import 'package:cipherbird_example/play/hardware_playground.dart';
import 'package:cipherbird_example/play/hash_playground.dart';
import 'package:cipherbird_example/play/hpke_playground.dart';
import 'package:cipherbird_example/play/live_playground.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/play/playground_page.dart';
import 'package:cipherbird_example/play/session_playground.dart';
import 'package:cipherbird_example/play/signature_playground.dart';
import 'package:cipherbird_example/play/stego_playground.dart';
import 'package:cipherbird_example/play/suite2_playground.dart';
import 'package:cipherbird_example/play/symmetric_playground.dart';
import 'package:flutter/material.dart';

/// The list of playgrounds; tapping one opens it.
final class PlaygroundIndex extends StatelessWidget {
  const PlaygroundIndex({super.key});

  static List<Playground> all(CipherBird lib) => [
    HashPlayground(lib),
    SymmetricPlayground(lib),
    SignaturePlayground(lib),
    HpkePlayground(lib),
    Suite2Playground(lib),
    SessionPlayground(lib),
    StegoPlayground(lib),
    EntropyPlayground(lib),
    LivePlayground(lib),
    HardwarePlayground(lib),
    FipsPlayground(lib),
  ];

  @override
  Widget build(BuildContext context) {
    final items = all(CipherBird.instance);
    return Scaffold(
      appBar: AppBar(title: const Text('Playground')),
      body: ListView(
        children: [
          for (final p in items)
            ListTile(
              title: Text(p.title),
              subtitle: Text(
                p.blurb,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.of(context).push(
                MaterialPageRoute<void>(builder: (_) => PlaygroundPage(p)),
              ),
            ),
        ],
      ),
    );
  }
}
