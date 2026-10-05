part of '../../cryptolib.dart';

/// Bls operations.
extension CryptoLibBlsAggregate on CryptoLib {
  /// Aggregate N BLS signatures (each a 96-byte compressed G2 point) into a
  /// single 96-byte signature. Throws if [sigs] is empty.
  Uint8List blsAggregate(List<Uint8List> sigs) {
    if (sigs.isEmpty) {
      throw ArgumentError('blsAggregate requires at least one signature');
    }
    final (ptrs, lens) = _toNativeList(sigs);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            int,
          )
        >('cryptolib_bls_aggregate')(ptrs, lens, sigs.length),
      );
    } finally {
      _freeNativeList(ptrs, lens, sigs.length);
    }
  }

  /// Verify an aggregate signature over N (message, public key) pairs in a
  /// single operation. [messages] and [publicKeys] must be the same length and
  /// positionally correspond. Returns true iff every signature is valid.
  bool blsAggregateVerify(
    List<Uint8List> messages,
    List<Uint8List> publicKeys,
    Uint8List aggSig,
  ) {
    if (messages.length != publicKeys.length) {
      throw ArgumentError(
        'blsAggregateVerify: messages (${messages.length}) and publicKeys '
        '(${publicKeys.length}) must have equal length',
      );
    }
    if (messages.isEmpty) {
      throw ArgumentError('blsAggregateVerify requires at least one pair');
    }
    final count = messages.length;
    final (mPtrs, mLens) = _toNativeList(messages);
    final (pPtrs, pLens) = _toNativeList(publicKeys);
    final ap = _toNative(aggSig);
    try {
      return _lib.lookupFunction<
            Int32 Function(
              Pointer<Pointer<Uint8>>,
              Pointer<Size>,
              Pointer<Pointer<Uint8>>,
              Pointer<Size>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            int Function(
              Pointer<Pointer<Uint8>>,
              Pointer<Size>,
              Pointer<Pointer<Uint8>>,
              Pointer<Size>,
              int,
              Pointer<Uint8>,
              int,
            )
          >('cryptolib_bls_aggregate_verify')(
            mPtrs,
            mLens,
            pPtrs,
            pLens,
            count,
            ap,
            aggSig.length,
          ) ==
          1;
    } finally {
      _freeNativeList(mPtrs, mLens, count);
      _freeNativeList(pPtrs, pLens, count);
      if (ap != nullptr) {
        calloc.free(ap);
      }
    }
  }
}
