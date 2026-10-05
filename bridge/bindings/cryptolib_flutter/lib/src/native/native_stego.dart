part of '../cryptolib.dart';

final class _NativeStego {
  _NativeStego(DynamicLibrary lib)
    : stegoEmbed = lib.lookupFunction<_StegoEmbedC, _StegoEmbedDart>(
        'cryptolib_stego_embed',
      ),
      stegoExtract = lib.lookupFunction<_StegoExtractC, _StegoExtractDart>(
        'cryptolib_stego_extract',
      ),
      stegoCapacity = lib.lookupFunction<_StegoCapacityC, _StegoCapacityDart>(
        'cryptolib_stego_capacity',
      );

  final _StegoEmbedDart stegoEmbed;
  final _StegoExtractDart stegoExtract;
  final _StegoCapacityDart stegoCapacity;
}
