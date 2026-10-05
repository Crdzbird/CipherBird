part of 'playground_page.dart';

extension _PlaygroundActions on _PlaygroundPageState {
  void _encrypt() => _set('ciphertext', _key.encryptText(_input.text));

  void _decrypt() {
    try {
      _set('decrypted', _key.decryptText(_out['ciphertext'] ?? ''));
    } on Object catch (error) {
      _set('decrypted', 'failed: $error');
    }
  }

  void _flipBit() {
    final bytes = (_out['ciphertext'] ?? '').base64Bytes;
    if (bytes.isEmpty) return;
    bytes[bytes.length - 1] ^= 1;
    _set('ciphertext', bytes.base64);
  }

  void _sign() => _set('signature', _signer.signText(_input.text));

  void _verify() {
    final ok = _signer.verifyKey.verifyText(
      _input.text,
      _out['signature'] ?? '',
    );
    _set(
      'verdict',
      ok
          ? 'signature valid for the current text'
          : 'signature does not match the current text',
    );
  }

  void _kemSeal() {
    final blob = KemKeyPair.encryptTextFor(_kem.publicKey, _input.text);
    _set('blob', blob);
    _set('opened', _kem.decryptText(blob));
  }

  Future<void> _hashPassword() async {
    final phc = await _lib.easy.hashPasswordAsync(_passphrase.text);
    final ok = await _lib.easy.verifyPasswordAsync(_passphrase.text, phc);
    _set('password', '${ok ? 'verified' : 'mismatch'}\n$phc');
  }
}
