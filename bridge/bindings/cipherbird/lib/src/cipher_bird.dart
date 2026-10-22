/// CipherBird for Dart/Flutter - an idiomatic dart:ffi wrapper around the
/// native engine's C ABI.
///
/// The engine is bundled per platform (iOS and macOS via the Swift Package,
/// Android via jniLibs, WebAssembly for the web) and resolved automatically;
/// no path is needed. One await at startup covers every platform: it returns
/// at once natively and, in the browser, joins the engine download that the
/// plugin registration started before `main`. `dart run cipherbird:web_setup`
/// adds the engine tag to `web/index.html` with its integrity digest; with
/// `--boot` and `--dart-define=CIPHERBIRD_PAGE_ENGINE=true` the page
/// instantiates the engine during Flutter's own bootstrap and no await is
/// needed on the web either; [CipherBird.preload] has the details.
///
/// ```dart
/// Future<void> main() async {
///   WidgetsFlutterBinding.ensureInitialized();
///   await CipherBird.preload();
///   runApp(const MyApp());
/// }
///
/// final digest = CipherBird.instance.sha256('abc'.bytes).hex;
/// ```
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cipherbird/src/platform/native/native_platform.dart'
    if (dart.library.js_interop) 'package:cipherbird/src/platform/web/web_platform.dart';
import 'package:cipherbird/src/runner/cipher_bird_inline_runner.dart';
import 'package:cipherbird/src/runner/cipher_bird_job.dart';
import 'package:cipherbird/src/runner/cipher_bird_runner.dart';

export 'package:cipherbird/src/platform/native/native_platform.dart'
    if (dart.library.js_interop) 'package:cipherbird/src/platform/web/web_platform.dart'
    show
        CipherBirdAsymBundle,
        CipherBirdBuffer,
        CipherBirdBufferResult,
        CipherBirdDerivedKeys,
        CipherBirdEntropyInfo,
        CipherBirdFileInspection,
        CipherBirdFipsStatus,
        CipherBirdFrostCommit,
        CipherBirdFrostKeyGen,
        CipherBirdHealthReport,
        CipherBirdHiddenDataReport,
        CipherBirdIsolateRunner,
        CipherBirdKemEncapsResult,
        CipherBirdKeyPair,
        CipherBirdOpaqueKe1,
        CipherBirdOpaqueKe2,
        CipherBirdOpaqueKe3,
        CipherBirdOpaqueRecord,
        CipherBirdOprfBlind,
        CipherBirdPacket,
        CipherBirdResult,
        CipherBirdSealedInfo;
export 'package:cipherbird/src/runner/cipher_bird_inline_runner.dart'
    show CipherBirdInlineRunner;
export 'package:cipherbird/src/runner/cipher_bird_job.dart' show CipherBirdJob;
export 'package:cipherbird/src/runner/cipher_bird_runner.dart'
    show CipherBirdRunner;

part 'api/approval.dart';
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
part 'api/entropy/cipher_bird_entropy.dart';
part 'api/entropy/cipher_bird_entropy/derivation.dart';
part 'api/entropy/cipher_bird_entropy/open_from_file.dart';
part 'api/entropy/cipher_bird_entropy_health.dart';
part 'api/entropy/cipher_bird_entropy_policy.dart';
part 'api/entropy/health_report.dart';
part 'api/evm_btc.dart';
part 'api/evm_btc/secp256k1_verify.dart';
part 'api/fips/cipher_bird_fips.dart';
part 'api/fips/cipher_bird_fips_envelope.dart';
part 'api/fips/fips_aes_gcm.dart';
part 'api/fips/fips_digest.dart';
part 'api/fips/fips_envelope.dart';
part 'api/fips/fips_envelope_ops.dart';
part 'api/fips/fips_envelope_slots.dart';
part 'api/fips/fips_hmac_verify.dart';
part 'api/fips/fips_hpke_p256_open.dart';
part 'api/fips/fips_hpke_p256_seal.dart';
part 'api/fips/fips_kdf.dart';
part 'api/fips/fips_p256.dart';
part 'api/fips/fips_p256_sign.dart';
part 'api/fips/fips_pbkdf2.dart';
part 'api/frost/cipher_bird_frost.dart';
part 'api/frost/cipher_bird_frost/aggregate.dart';
part 'api/frost/cipher_bird_frost/commit_with_nonces.dart';
part 'api/frost/cipher_bird_frost/sign.dart';
part 'api/frost/cipher_bird_frost/verify.dart';
part 'api/frost/cipher_bird_frost/verify_share.dart';
part 'api/frost/frost_commitment.dart';
part 'api/frost/frost_copy.dart';
part 'api/frost/frost_key_gen.dart';
part 'api/frost/frost_nonces.dart';
part 'api/hashing.dart';
part 'api/hashing/argon2id.dart';
part 'api/hashing/argon2id_text.dart';
part 'api/hashing/blake3.dart';
part 'api/hashing/hkdf.dart';
part 'api/hashing/hkdf_derive.dart';
part 'api/hashing/hmac_sha256.dart';
part 'api/hpke/cipher_bird_hpke.dart';
part 'api/hpke/cipher_bird_hpke/export.dart';
part 'api/hpke/cipher_bird_hpke/handles.dart';
part 'api/hpke/cipher_bird_hpke/kem_keys.dart';
part 'api/hpke/cipher_bird_hpke/kem_recipient_setup.dart';
part 'api/hpke/cipher_bird_hpke/kem_sender_setup.dart';
part 'api/hpke/cipher_bird_hpke/recipient_setup.dart';
part 'api/hpke/cipher_bird_hpke/sender_setup.dart';
part 'api/hpke/cipher_bird_hpke/single_shot.dart';
part 'api/hpke/hpke_context.dart';
part 'api/hpke/hpke_sender.dart';
part 'api/keyring.dart';
part 'api/keyring/hardware_slots.dart';
part 'api/keyring/hardware_slots_read.dart';
part 'api/keyring/management.dart';
part 'api/keyring/passphrase_slot.dart';
part 'api/molecular_vault.dart';
part 'api/molecular_vault/open.dart';
part 'api/molecular_vault/open_with_key.dart';
part 'api/molecular_vault/seal_with_key.dart';
part 'api/noise/blake3_hasher.dart';
part 'api/noise/cipher_bird_noise.dart';
part 'api/noise/noise_x_x.dart';
part 'api/noise/noise_x_x/transport.dart';
part 'api/opaque/cipher_bird_opaque.dart';
part 'api/opaque/cipher_bird_opaque/client_finish.dart';
part 'api/opaque/cipher_bird_opaque/client_steps.dart';
part 'api/opaque/cipher_bird_opaque/server_finish.dart';
part 'api/opaque/cipher_bird_opaque/server_respond.dart';
part 'api/opaque/opaque_ke1.dart';
part 'api/opaque/opaque_ke2.dart';
part 'api/opaque/opaque_ke3.dart';
part 'api/opaque/opaque_record.dart';
part 'api/oprf/cipher_bird_oprf.dart';
part 'api/oprf/cipher_bird_oprf/blind_with_scalar.dart';
part 'api/oprf/cipher_bird_oprf/evaluate.dart';
part 'api/oprf/cipher_bird_oprf/evaluation.dart';
part 'api/oprf/oprf_blind_result.dart';
part 'api/post_quantum.dart';
part 'api/post_quantum/hybrid_kem.dart';
part 'api/post_quantum/hybrid_sig.dart';
part 'api/post_quantum/ml_dsa.dart';
part 'api/post_quantum/slh_dsa.dart';
part 'api/post_quantum/slh_dsa_verify.dart';
part 'api/post_quantum/sntrup_x25519.dart';
part 'api/rng/cipher_bird_rng.dart';
part 'api/rng/drbg.dart';
part 'api/rng/drbg/reseed.dart';
part 'api/rng/fortuna.dart';
part 'api/sealed/cipher_bird_sealed.dart';
part 'api/sealed/cipher_bird_sealed/open.dart';
part 'api/sealed/cipher_bird_sealed/opener.dart';
part 'api/sealed/cipher_bird_sealed/opener_steps.dart';
part 'api/sealed/cipher_bird_sealed/seal.dart';
part 'api/sealed/cipher_bird_sealed/sealer.dart';
part 'api/sealed/cipher_bird_sealed/sealer_finish.dart';
part 'api/sealed/identity.dart';
part 'api/sealed/sealed_info.dart';
part 'api/sealed/sealed_stream_opener.dart';
part 'api/sealed/sealed_stream_sealer.dart';
part 'api/sealed/sealed_tier.dart';
part 'api/session/cipher_bird_session.dart';
part 'api/session/cipher_bird_session/accept.dart';
part 'api/session/cipher_bird_session/messaging.dart';
part 'api/session/session.dart';
part 'api/session2/cipher_bird_session2.dart';
part 'api/session2/cipher_bird_session2/accept.dart';
part 'api/session2/cipher_bird_session2/initiate.dart';
part 'api/session2/cipher_bird_session2/messaging.dart';
part 'api/session2/session2.dart';
part 'api/steganography/cipher_bird_stego.dart';
part 'api/steganography/cipher_bird_stego_advanced.dart';
part 'api/steganography/cipher_bird_stego_advanced/encrypted.dart';
part 'api/steganography/cipher_bird_stego_advanced/inspection.dart';
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
part 'api/suite2/cipher_bird_suite2.dart';
part 'api/suite2/cipher_bird_suite2_open.dart';
part 'api/symmetric.dart';
part 'api/symmetric/aes256gcm.dart';
part 'api/symmetric/committing_decrypt.dart';
part 'api/symmetric/committing_encrypt.dart';
part 'api/symmetric/secret_stream.dart';
part 'api/vault.dart';
part 'api/vault/management.dart';
part 'api/xwing/cipher_bird_xwing.dart';
part 'api/xwing/cipher_bird_xwing_encapsulate.dart';
part 'core/marshal_buffers.dart';
part 'core/marshal_lists.dart';
part 'core/marshal_structs.dart';
part 'easy/cipher_bird_easy.dart';
part 'easy/crypto_byte_list.dart';
part 'easy/crypto_bytes.dart';
part 'easy/crypto_text.dart';
part 'easy/easy_api.dart';
part 'easy/easy_api/async_api.dart';
part 'easy/easy_api/jobs/argon2_derive_job.dart';
part 'easy/easy_api/jobs/argon2_hash_job.dart';
part 'easy/easy_api/jobs/argon2_verify_job.dart';
part 'easy/easy_api/passwords.dart';
part 'easy/easy_lib.dart';
part 'easy/identity_text.dart';
part 'easy/kem_key_pair.dart';
part 'easy/kem_key_pair/decryption.dart';
part 'easy/key_pair_text.dart';
part 'easy/secret_bytes.dart';
part 'easy/signing_key.dart';
part 'easy/symmetric_key.dart';
part 'easy/symmetric_key/encoding.dart';
part 'easy/symmetric_key/encryption.dart';
part 'easy/verify_key.dart';
part 'enums/fec_scheme.dart';
part 'enums/fips_hash.dart';
part 'enums/hpke_aead.dart';
part 'enums/hpke_kdf.dart';
part 'enums/hpke_kem.dart';
part 'enums/hpke_mode.dart';
part 'enums/kdf_preset.dart';
part 'enums/media_format.dart';
part 'enums/ml_dsa_level.dart';
part 'enums/ml_kem_level.dart';
part 'enums/protected_data_class.dart';
part 'enums/slh_dsa_hash.dart';
part 'enums/slh_dsa_level.dart';
part 'enums/suite2_id.dart';
part 'facade/aead_api.dart';
part 'facade/asym_api.dart';
part 'facade/bbs_api.dart';
part 'facade/bbs_api/pseudonyms.dart';
part 'facade/bbs_api/scalars.dart';
part 'facade/bls_api.dart';
part 'facade/chain_api.dart';
part 'facade/cipher_bird_namespaces.dart';
part 'facade/composed_api.dart';
part 'facade/composed_api/hpke_stego.dart';
part 'facade/ecvrf_api.dart';
part 'facade/entropy_api.dart';
part 'facade/frost_api.dart';
part 'facade/hash_api.dart';
part 'facade/hash_api_passwords.dart';
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
part 'models/fips_status.dart';
part 'models/key_pair_result.dart';
part 'models/packet.dart';
part 'native/native_asymmetric.dart';
part 'native/native_core.dart';
part 'native/native_entropy.dart';
part 'native/native_hashing.dart';
part 'native/native_stego.dart';
part 'native/native_symmetric.dart';
part 'native/native_vault.dart';
part 'security/aes256_gcm_layer.dart';
part 'security/builtin.dart';
part 'security/cascade_layer.dart';
part 'security/cipher_bird_security.dart';
part 'security/committing_layer.dart';
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
part 'security/security_profile_kem.dart';
part 'security/signature_algorithm.dart';
part 'security/signature_scheme.dart';
part 'security/x_cha_cha20_layer.dart';
part 'utils.dart';

/// Entry point to the native engine. Crypto operations live on the domain
/// extensions and the grouped views (`lib.hash`, `lib.pq`, `lib.easy`).
final class CipherBird {
  CipherBird._(this._lib);

  /// Opens the native library: an explicit [path], else `CRYPTOLIB_DYLIB`,
  /// else the platform default (process image on Apple platforms, the bundled
  /// `libcipherbird.so` on Android and Linux).
  factory CipherBird.load([String? path]) =>
      CipherBird._(openEngineLibrary(path));

  static CipherBird? _singleton;
  static bool _initialized = false;

  /// Process-wide instance, opened and initialised synchronously on first use.
  static CipherBird get instance {
    final lib = _singleton ??= CipherBird.load();
    if (_initialized) {
      return lib;
    }
    lib.init();
    _initialized = true;
    return lib;
  }

  /// The same readiness as [preload], for code that runs after `main` and
  /// only needs to wait: completes at once natively, and in the browser once
  /// the WebAssembly engine is compiled, or at once when the page booted the
  /// engine with the scripts described on [preload].
  static Future<void> get ready => prepareEngine(null);

  /// The one startup call. Await it once in `main` before `runApp`. Natively
  /// it returns immediately, because the library opens synchronously on first
  /// use. In the browser it joins the fetch and compilation of the
  /// WebAssembly engine that the plugin registration started before `main`,
  /// so the wait is only whatever download time is left; [library] overrides
  /// the URL of `cipherbird.js`. Every file is checked against the
  /// Subresource Integrity digests the package was built with.
  /// `dart run cipherbird:web_setup` writes the engine tag with the same
  /// digest so the download starts during Flutter's bootstrap. With
  /// `web_setup --boot` and `--dart-define=CIPHERBIRD_PAGE_ENGINE=true` the
  /// page also instantiates the engine and this call returns at once, so
  /// the await can be dropped on the web; that opt-in trusts the
  /// `self.cipherbirdEngine` global, that is, the scripts on the page.
  ///
  /// [runner] is accepted for source compatibility and unused. Returns true.
  static Future<bool> preload({
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
    String? library,
  }) async {
    if (!engineLoadsAsynchronously) {
      return true;
    }
    await prepareEngine(library);
    return true;
  }

  final DynamicLibrary _lib;
  late final _NativeCore _core = _NativeCore(_lib);
  late final _NativeHashing _hashing = _NativeHashing(_lib);
  late final _NativeSymmetric _symmetric = _NativeSymmetric(_lib);
  late final _NativeAsymmetric _asymmetric = _NativeAsymmetric(_lib);
  late final _NativeVault _vault = _NativeVault(_lib);
  late final _NativeEntropy _entropy = _NativeEntropy(_lib);
  late final _NativeStego _stego = _NativeStego(_lib);
}
