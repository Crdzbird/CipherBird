/// How an engine call job's entry point returns.
enum JobReturn {
  /// A `CryptoBufferResult`; the bytes, or the error thrown.
  buffer,

  /// A `CryptoKeyPair`; both keys.
  keypair,

  /// A `CryptoResult`; true, or the error thrown.
  result,

  /// A plain integer.
  int32,

  /// Nothing.
  none,
}
