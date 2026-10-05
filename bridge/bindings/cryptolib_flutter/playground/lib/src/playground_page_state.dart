part of 'playground_page.dart';

final class _PlaygroundPageState extends State<PlaygroundPage> {
  final _lib = CryptoLib.instance;
  final _key = SymmetricKey.generate();
  final _signer = SigningKey.generate(algorithm: SignatureAlgorithm.hybrid);
  final _kem = KemKeyPair.generate();
  final _input = TextEditingController(text: 'meet at dawn');
  final _passphrase = TextEditingController(
    text: 'correct horse battery staple',
  );
  late final List<(String, bool)> _checks = selfTest(_lib);
  final _out = <String, String>{};

  void _set(String field, String value) => setState(() => _out[field] = value);

  Widget _block(String field, String title) {
    final value = _out[field];
    if (value == null) return const SizedBox.shrink();
    return ResultBlock(title: title, body: value);
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('cryptolib_flutter playground')),
    body: ListView(
      padding: const EdgeInsets.all(16),
      children: [
        for (final (label, ok) in _checks)
          Text('${ok ? 'pass' : 'fail'}  $label'),
        const Divider(height: 32),
        TextField(
          controller: _input,
          decoration: const InputDecoration(labelText: 'Text'),
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          children: [
            FilledButton(onPressed: _encrypt, child: const Text('Encrypt')),
            FilledButton.tonal(
              onPressed: _flipBit,
              child: const Text('Flip a bit'),
            ),
            FilledButton(onPressed: _decrypt, child: const Text('Decrypt')),
          ],
        ),
        _block('ciphertext', 'Ciphertext (committing AEAD, base64)'),
        _block('decrypted', 'Decrypted'),
        const Divider(height: 32),
        Wrap(
          spacing: 8,
          children: [
            FilledButton(
              onPressed: _sign,
              child: const Text('Sign (Ed25519 + ML-DSA-65)'),
            ),
            FilledButton(onPressed: _verify, child: const Text('Verify')),
          ],
        ),
        _block('signature', 'Signature (base64)'),
        _block('verdict', 'Verdict'),
        const Divider(height: 32),
        FilledButton(
          onPressed: _kemSeal,
          child: const Text('Encrypt to my public key (X25519 + ML-KEM-768)'),
        ),
        _block('blob', 'Blob (base64)'),
        _block('opened', 'Opened with my secret key'),
        const Divider(height: 32),
        TextField(
          controller: _passphrase,
          decoration: const InputDecoration(labelText: 'Passphrase'),
        ),
        const SizedBox(height: 8),
        FilledButton(
          onPressed: _hashPassword,
          child: const Text('Hash with Argon2id on a worker'),
        ),
        _block('password', 'Password hash'),
      ],
    ),
  );
}
