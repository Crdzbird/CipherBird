/// CryptoLib for Dart/Flutter - an idiomatic dart:ffi wrapper around the
/// CryptoLib C ABI (libcryptolib_c).
///
/// The native library is bundled per platform (iOS/macOS via the Swift Package,
/// Android via jniLibs) and resolved automatically; no path or setup is needed.
///
/// ```dart
/// Future<void> main() async {
///   WidgetsFlutterBinding.ensureInitialized();
///   await CryptoLib.preload();
///   runApp(const MyApp());
/// }
///
/// final digest = CryptoLib.instance.sha256('abc'.bytes).hex;
/// ```
library;

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io' show Platform;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

part 'api/asymmetric.dart';
part 'api/asymmetric/box.dart';
part 'api/asymmetric/sealed_box.dart';
part 'api/asymmetric_vault.dart';
part 'api/asymmetric_vault/open.dart';
part 'api/bbs.dart';
part 'api/bbs/blind_issuance.dart';
part 'api/bbs/blind_sign_with_nym.dart';
part 'api/bbs/commit_with_nym.dart';
part 'api/bbs/proof_gen.dart';
part 'api/bbs/proof_gen_with_pseudonym.dart';
part 'api/bbs/proof_verify.dart';
part 'api/bbs/proof_verify_with_pseudonym.dart';
part 'api/bbs/pseudonym_secrets.dart';
part 'api/bbs/scalars.dart';
part 'api/bbs/sign.dart';
part 'api/bbs/verify.dart';
part 'api/bbs/verify_blind_sign.dart';
part 'api/bls.dart';
part 'api/bls/aggregate.dart';
part 'api/composed.dart';
part 'api/composed/hpke_stego_open.dart';
part 'api/composed/hpke_stego_seal.dart';
part 'api/composed/image_factor_open.dart';
part 'api/composed/image_factor_seal.dart';
part 'api/composed/physical_open.dart';
part 'api/composed/physical_seal.dart';
part 'api/core.dart';
part 'api/ecvrf.dart';
part 'api/ecvrf/verify.dart';
part 'api/entropy/crypto_lib_entropy.dart';
part 'api/entropy/crypto_lib_entropy/derivation.dart';
part 'api/entropy/crypto_lib_entropy/open_from_file.dart';
part 'api/entropy/crypto_lib_entropy_health.dart';
part 'api/entropy/health_report.dart';
part 'api/evm_btc.dart';
part 'api/evm_btc/secp256k1_verify.dart';
part 'api/frost/crypto_lib_frost.dart';
part 'api/frost/crypto_lib_frost/aggregate.dart';
part 'api/frost/crypto_lib_frost/commit_with_nonces.dart';
part 'api/frost/crypto_lib_frost/sign.dart';
part 'api/frost/crypto_lib_frost/verify.dart';
part 'api/frost/crypto_lib_frost/verify_share.dart';
part 'api/frost/frost_commitment.dart';
part 'api/frost/frost_copy.dart';
part 'api/frost/frost_key_gen.dart';
part 'api/frost/frost_nonces.dart';
part 'api/hashing.dart';
part 'api/hashing/argon2id.dart';
part 'api/hashing/blake3.dart';
part 'api/hashing/hkdf.dart';
part 'api/hashing/hkdf_derive.dart';
part 'api/hashing/hmac_sha256.dart';
part 'api/hpke/crypto_lib_hpke.dart';
part 'api/hpke/crypto_lib_hpke/handles.dart';
part 'api/hpke/crypto_lib_hpke/recipient_setup.dart';
part 'api/hpke/crypto_lib_hpke/sender_setup.dart';
part 'api/hpke/crypto_lib_hpke/single_shot.dart';
part 'api/hpke/hpke_context.dart';
part 'api/hpke/hpke_sender.dart';
part 'api/keyring.dart';
part 'api/keyring/management.dart';
part 'api/molecular_vault.dart';
part 'api/molecular_vault/open.dart';
part 'api/molecular_vault/open_with_key.dart';
part 'api/molecular_vault/seal_with_key.dart';
part 'api/noise/blake3_hasher.dart';
part 'api/noise/crypto_lib_noise.dart';
part 'api/noise/noise_x_x.dart';
part 'api/noise/noise_x_x/transport.dart';
part 'api/opaque/crypto_lib_opaque.dart';
part 'api/opaque/crypto_lib_opaque/client_finish.dart';
part 'api/opaque/crypto_lib_opaque/client_steps.dart';
part 'api/opaque/crypto_lib_opaque/server_finish.dart';
part 'api/opaque/crypto_lib_opaque/server_respond.dart';
part 'api/opaque/opaque_ke1.dart';
part 'api/opaque/opaque_ke2.dart';
part 'api/opaque/opaque_ke3.dart';
part 'api/opaque/opaque_record.dart';
part 'api/oprf/crypto_lib_oprf.dart';
part 'api/oprf/crypto_lib_oprf/evaluation.dart';
part 'api/oprf/oprf_blind_result.dart';
part 'api/post_quantum.dart';
part 'api/post_quantum/hybrid_kem.dart';
part 'api/post_quantum/hybrid_sig.dart';
part 'api/post_quantum/ml_dsa.dart';
part 'api/post_quantum/slh_dsa.dart';
part 'api/post_quantum/slh_dsa_verify.dart';
part 'api/post_quantum/sntrup_x25519.dart';
part 'api/rng/crypto_lib_rng.dart';
part 'api/rng/drbg.dart';
part 'api/rng/fortuna.dart';
part 'api/sealed/crypto_lib_sealed.dart';
part 'api/sealed/crypto_lib_sealed/open.dart';
part 'api/sealed/crypto_lib_sealed/opener.dart';
part 'api/sealed/crypto_lib_sealed/opener_steps.dart';
part 'api/sealed/crypto_lib_sealed/seal.dart';
part 'api/sealed/crypto_lib_sealed/sealer.dart';
part 'api/sealed/crypto_lib_sealed/sealer_finish.dart';
part 'api/sealed/identity.dart';
part 'api/sealed/sealed_info.dart';
part 'api/sealed/sealed_stream_opener.dart';
part 'api/sealed/sealed_stream_sealer.dart';
part 'api/sealed/sealed_tier.dart';
part 'api/session/crypto_lib_session.dart';
part 'api/session/crypto_lib_session/accept.dart';
part 'api/session/crypto_lib_session/messaging.dart';
part 'api/session/session.dart';
part 'api/steganography/crypto_lib_stego.dart';
part 'api/steganography/crypto_lib_stego_advanced.dart';
part 'api/steganography/crypto_lib_stego_advanced/encrypted.dart';
part 'api/steganography/crypto_lib_stego_advanced/inspection.dart';
part 'api/steganography/stego_file_inspection.dart';
part 'api/steganography/stego_hidden_data_report.dart';
part 'api/suite.dart';
part 'api/suite/file_call.dart';
part 'api/suite/keyring.dart';
part 'api/suite/keyring_factor_call.dart';
part 'api/suite/keyring_passphrase_call.dart';
part 'api/suite/open_threshold.dart';
part 'api/suite/seal_threshold.dart';
part 'api/suite/three_buffer_call.dart';
part 'api/suite/two_buffer_call.dart';
part 'api/symmetric.dart';
part 'api/symmetric/aes256gcm.dart';
part 'api/symmetric/committing_decrypt.dart';
part 'api/symmetric/committing_encrypt.dart';
part 'api/symmetric/secret_stream.dart';
part 'api/vault.dart';
part 'api/vault/management.dart';
part 'core/library_loader.dart';
part 'core/marshal_buffers.dart';
part 'core/marshal_lists.dart';
part 'core/marshal_structs.dart';
part 'core/warm_up.dart';
part 'easy/crypto_byte_list.dart';
part 'easy/crypto_bytes.dart';
part 'easy/crypto_lib_easy.dart';
part 'easy/crypto_text.dart';
part 'easy/easy_api.dart';
part 'easy/easy_api/async_api.dart';
part 'easy/easy_api/workers.dart';
part 'easy/easy_lib.dart';
part 'easy/identity_text.dart';
part 'easy/kem_key_pair.dart';
part 'easy/kem_key_pair/decryption.dart';
part 'easy/key_pair_text.dart';
part 'easy/signing_key.dart';
part 'easy/symmetric_key.dart';
part 'easy/symmetric_key/encryption.dart';
part 'easy/verify_key.dart';
part 'enums/fec_scheme.dart';
part 'enums/hpke_aead.dart';
part 'enums/hpke_kdf.dart';
part 'enums/hpke_mode.dart';
part 'enums/kdf_preset.dart';
part 'enums/media_format.dart';
part 'enums/ml_dsa_level.dart';
part 'enums/ml_kem_level.dart';
part 'enums/slh_dsa_hash.dart';
part 'enums/slh_dsa_level.dart';
part 'facade/aead_api.dart';
part 'facade/asym_api.dart';
part 'facade/bbs_api.dart';
part 'facade/bbs_api/pseudonyms.dart';
part 'facade/bbs_api/scalars.dart';
part 'facade/bls_api.dart';
part 'facade/chain_api.dart';
part 'facade/composed_api.dart';
part 'facade/composed_api/hpke_stego.dart';
part 'facade/crypto_lib_namespaces.dart';
part 'facade/ecvrf_api.dart';
part 'facade/entropy_api.dart';
part 'facade/frost_api.dart';
part 'facade/hash_api.dart';
part 'facade/hpke_api.dart';
part 'facade/keyring_api.dart';
part 'facade/noise_api.dart';
part 'facade/opaque_api.dart';
part 'facade/oprf_api.dart';
part 'facade/pq_api.dart';
part 'facade/pq_hybrid_kem_api.dart';
part 'facade/pq_hybrid_sig_api.dart';
part 'facade/pq_ml_dsa_api.dart';
part 'facade/pq_ml_kem_api.dart';
part 'facade/pq_slh_dsa_api.dart';
part 'facade/pq_sntrup_api.dart';
part 'facade/rng_api.dart';
part 'facade/sealed_api.dart';
part 'facade/session_api.dart';
part 'facade/stego_api.dart';
part 'facade/suite_api.dart';
part 'facade/suite_api/passphrase_and_threshold.dart';
part 'facade/vault_api.dart';
part 'facade/vault_api/molecular_open_with_key.dart';
part 'ffi/structs/crypto_asym_bundle.dart';
part 'ffi/structs/crypto_buffer.dart';
part 'ffi/structs/crypto_buffer_result.dart';
part 'ffi/structs/crypto_derived_keys.dart';
part 'ffi/structs/crypto_entropy_info.dart';
part 'ffi/structs/crypto_file_inspection.dart';
part 'ffi/structs/crypto_frost_commit.dart';
part 'ffi/structs/crypto_frost_key_gen.dart';
part 'ffi/structs/crypto_health_report.dart';
part 'ffi/structs/crypto_hidden_data_report.dart';
part 'ffi/structs/crypto_kem_encaps_result.dart';
part 'ffi/structs/crypto_key_pair.dart';
part 'ffi/structs/crypto_opaque_ke1.dart';
part 'ffi/structs/crypto_opaque_ke2.dart';
part 'ffi/structs/crypto_opaque_ke3.dart';
part 'ffi/structs/crypto_opaque_record.dart';
part 'ffi/structs/crypto_oprf_blind.dart';
part 'ffi/structs/crypto_packet.dart';
part 'ffi/structs/crypto_result.dart';
part 'ffi/structs/crypto_sealed_info.dart';
part 'ffi/typedefs/argon2id.dart';
part 'ffi/typedefs/asymmetric_vault.dart';
part 'ffi/typedefs/bbs_pseudonym.dart';
part 'ffi/typedefs/box.dart';
part 'ffi/typedefs/ed25519.dart';
part 'ffi/typedefs/entropy.dart';
part 'ffi/typedefs/entropyconvenience.dart';
part 'ffi/typedefs/hashing.dart';
part 'ffi/typedefs/init_and_version.dart';
part 'ffi/typedefs/memoryfree.dart';
part 'ffi/typedefs/opaque_server.dart';
part 'ffi/typedefs/random_andutility.dart';
part 'ffi/typedefs/sealed_box.dart';
part 'ffi/typedefs/secret_stream.dart';
part 'ffi/typedefs/steganography.dart';
part 'ffi/typedefs/symmetricencryption.dart';
part 'ffi/typedefs/vault.dart';
part 'ffi/typedefs/x25519.dart';
part 'models/asym_bundle_result.dart';
part 'models/derived_keys_result.dart';
part 'models/entropy_info_result.dart';
part 'models/key_pair_result.dart';
part 'models/packet.dart';
part 'native/native_asymmetric.dart';
part 'native/native_core.dart';
part 'native/native_entropy.dart';
part 'native/native_hashing.dart';
part 'native/native_stego.dart';
part 'native/native_symmetric.dart';
part 'native/native_vault.dart';
part 'runner/crypto_lib_inline_runner.dart';
part 'runner/crypto_lib_isolate_runner.dart';
part 'runner/crypto_lib_runner.dart';
part 'security/aes256_gcm_layer.dart';
part 'security/builtin.dart';
part 'security/cascade_layer.dart';
part 'security/committing_layer.dart';
part 'security/crypto_lib_security.dart';
part 'security/crypto_recipe.dart';
part 'security/crypto_recipe/builder.dart';
part 'security/crypto_recipe/fec.dart';
part 'security/crypto_recipe/header.dart';
part 'security/crypto_recipe/key_derivation.dart';
part 'security/crypto_recipe/opening.dart';
part 'security/crypto_recipe/sealing.dart';
part 'security/custom_ids.dart';
part 'security/ed25519_signature.dart';
part 'security/hybrid_signature.dart';
part 'security/key_file_source.dart';
part 'security/key_source.dart';
part 'security/molecular_layer.dart';
part 'security/parsed_header.dart';
part 'security/passphrase_key_source.dart';
part 'security/protection_layer.dart';
part 'security/raw_key_source.dart';
part 'security/security_profile.dart';
part 'security/signature_algorithm.dart';
part 'security/signature_scheme.dart';
part 'security/x_cha_cha20_layer.dart';
part 'utils.dart';

/// Entry point to the native library. Crypto operations live on the domain
/// extensions and the grouped views (`lib.hash`, `lib.pq`, `lib.easy`).
final class CryptoLib {
  CryptoLib._(this._lib);

  /// Opens the native library: an explicit [path], else `CRYPTOLIB_DYLIB`,
  /// else the platform default (process image on Apple platforms, the bundled
  /// `libcryptolib_c.so` on Android and Linux).
  factory CryptoLib.load([String? path]) => CryptoLib._(_openLibrary(path));

  static CryptoLib? _singleton;
  static bool _initialized = false;

  /// Process-wide instance, opened and initialised synchronously on first use.
  static CryptoLib get instance {
    final lib = _singleton ??= CryptoLib.load();
    if (_initialized) {
      return lib;
    }
    lib.init();
    _initialized = true;
    return lib;
  }

  /// Warms the native library on a worker so the first [instance] access on
  /// the UI isolate is instantaneous. Await it before `runApp`. Returns false
  /// if the warm-up failed; the lazy path still works in that case.
  static Future<bool> preload({
    CryptoLibRunner runner = const CryptoLibIsolateRunner(),
  }) => _warmUp(runner);

  final DynamicLibrary _lib;
  late final _NativeCore _core = _NativeCore(_lib);
  late final _NativeHashing _hashing = _NativeHashing(_lib);
  late final _NativeSymmetric _symmetric = _NativeSymmetric(_lib);
  late final _NativeAsymmetric _asymmetric = _NativeAsymmetric(_lib);
  late final _NativeVault _vault = _NativeVault(_lib);
  late final _NativeEntropy _entropy = _NativeEntropy(_lib);
  late final _NativeStego _stego = _NativeStego(_lib);
}
