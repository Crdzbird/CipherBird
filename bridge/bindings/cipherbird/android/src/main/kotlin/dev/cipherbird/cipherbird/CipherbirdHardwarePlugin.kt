package dev.cipherbird.cipherbird

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed key wrapping over the Android Keystore, served to Dart on
 * the "cipherbird/hardware" method channel.
 *
 * Each label owns an AES-256-GCM wrapping key that never leaves the
 * keystore, created in StrongBox when the device has one and otherwise in
 * the trusted execution environment (the fallback is reported, never
 * silent). Keys created with biometric gating require the user to pass the
 * system BiometricPrompt for every unwrap, through a CryptoObject so the
 * keystore itself enforces it. Key attestation uses a companion EC key under
 * the same label, generated with the caller's challenge at the same security
 * level; its certificate chain is returned for server-side verification.
 */
class CipherbirdHardwarePlugin : FlutterPlugin, MethodChannel.MethodCallHandler, ActivityAware {
    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private var activity: Activity? = null
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    private var fips: CipherbirdFipsChannel? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, "cipherbird/hardware")
        channel.setMethodCallHandler(this)
        fips = CipherbirdFipsChannel(binding.binaryMessenger)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        fips?.dispose()
        fips = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) { activity = binding.activity }
    override fun onDetachedFromActivityForConfigChanges() { activity = null }
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) { activity = binding.activity }
    override fun onDetachedFromActivity() { activity = null }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        val label = call.argument<String>("label")
        if (label.isNullOrEmpty()) { result.error("bad_argument", "label is required", null); return }
        if (call.method == "unwrap") { unwrap(label, call, result); return }
        worker.execute {
            try {
                val value: Any? = when (call.method) {
                    "create" -> create(label, call.argument<Boolean>("biometric") == true)
                    "exists" -> keyStore().containsAlias(wrapAlias(label))
                    "delete" -> delete(label)
                    "backing" -> backing(label)
                    "wrap" -> wrap(label, call.argument<ByteArray>("input")!!)
                    "attest" -> attest(label, call.argument<ByteArray>("challenge")!!)
                    "publicKey" -> publicKey(label)
                    else -> null
                }
                main.post { if (value == null) result.notImplemented() else result.success(value) }
            } catch (e: HardwareKeyError) {
                main.post { result.error(e.code, e.message, null) }
            } catch (e: Exception) {
                main.post { result.error("failed", e.toString(), null) }
            }
        }
    }

    private class HardwareKeyError(val code: String, message: String) : Exception(message)

    private fun wrapAlias(label: String) = "dev.cipherbird.hardware.$label"
    private fun attestAlias(label: String) = "dev.cipherbird.hardware.$label.attest"

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun requireApi(level: Int, what: String) {
        if (Build.VERSION.SDK_INT < level) throw HardwareKeyError("unsupported", "$what needs Android API $level")
    }

    /** Creates the wrapping key; returns the backing it landed in. */
    private fun create(label: String, biometric: Boolean): String {
        requireApi(Build.VERSION_CODES.P, "hardware keys")
        if (keyStore().containsAlias(wrapAlias(label))) throw HardwareKeyError("exists", "a key named $label already exists")
        try {
            generateWrappingKey(label, biometric, strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generateWrappingKey(label, biometric, strongBox = false)
        }
        return backing(label)
    }

    private fun generateWrappingKey(label: String, biometric: Boolean, strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            wrapAlias(label), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (strongBox) builder.setIsStrongBoxBacked(true)
        if (biometric) {
            builder.setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
        }
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(builder.build()); generateKey()
        }
    }

    private fun wrappingKey(label: String): SecretKey =
        keyStore().getKey(wrapAlias(label), null) as? SecretKey
            ?: throw HardwareKeyError("not_found", "no key named $label")

    private fun delete(label: String): Boolean {
        val ks = keyStore()
        if (ks.containsAlias(wrapAlias(label))) ks.deleteEntry(wrapAlias(label))
        if (ks.containsAlias(attestAlias(label))) ks.deleteEntry(attestAlias(label))
        return true
    }

    /** "strongbox", "tee" or "software" from the keystore's own report. */
    private fun backing(label: String): String {
        val key = wrappingKey(label)
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                else -> "software"
            }
        }
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) "tee" else "software"
    }

    /** iv(12) | ciphertext | tag; no user interaction. */
    private fun wrap(label: String, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey(label))
        val iv = cipher.iv
        val ct = cipher.doFinal(input)
        return iv + ct
    }

    private fun unwrapCipher(label: String, blob: ByteArray): Cipher {
        if (blob.size < 13) throw HardwareKeyError("bad_argument", "blob too short")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(label), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        return cipher
    }

    private fun finishUnwrap(cipher: Cipher, blob: ByteArray): ByteArray =
        cipher.doFinal(blob.copyOfRange(12, blob.size))

    /** Unwraps on the worker; a biometric-gated key goes through BiometricPrompt first. */
    private fun unwrap(label: String, call: MethodCall, result: MethodChannel.Result) {
        val blob = call.argument<ByteArray>("input")
        val reason = call.argument<String>("reason") ?: "Unlock your keys"
        if (blob == null) { result.error("bad_argument", "input is required", null); return }
        worker.execute {
            try {
                val cipher = unwrapCipher(label, blob)
                val info = SecretKeyFactory.getInstance("AES", "AndroidKeyStore")
                    .getKeySpec(wrappingKey(label), KeyInfo::class.java) as KeyInfo
                if (!info.isUserAuthenticationRequired) {
                    val plain = finishUnwrap(cipher, blob)
                    main.post { result.success(plain) }
                    return@execute
                }
                main.post { promptAndUnwrap(cipher, blob, reason, result) }
            } catch (e: android.security.keystore.UserNotAuthenticatedException) {
                main.post { result.error("authentication_failed", e.toString(), null) }
            } catch (e: HardwareKeyError) {
                main.post { result.error(e.code, e.message, null) }
            } catch (e: Exception) {
                main.post { result.error("failed", e.toString(), null) }
            }
        }
    }

    private fun promptAndUnwrap(cipher: Cipher, blob: ByteArray, reason: String, result: MethodChannel.Result) {
        val host = activity
        if (host == null) { result.error("failed", "no activity for the biometric prompt", null); return }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) { result.error("unsupported", "biometric gating needs Android API 28", null); return }
        val prompt = BiometricPrompt.Builder(host)
            .setTitle(reason)
            .setNegativeButton("Cancel", host.mainExecutor) { _, _ ->
                result.error("authentication_failed", "cancelled", null)
            }
            .build()
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(res: BiometricPrompt.AuthenticationResult) {
                worker.execute {
                    try {
                        val plain = finishUnwrap(res.cryptoObject?.cipher ?: cipher, blob)
                        main.post { result.success(plain) }
                    } catch (e: Exception) {
                        main.post { result.error("failed", e.toString(), null) }
                    }
                }
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                result.error("authentication_failed", msg.toString(), null)
            }
        }
        prompt.authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), host.mainExecutor, callback)
    }

    /** Generates (once) the companion EC key with the challenge and returns
     *  its attestation chain as len(4 BE) | DER records, plus the level. */
    private fun attest(label: String, challenge: ByteArray): Map<String, Any> {
        requireApi(Build.VERSION_CODES.P, "key attestation")
        wrappingKey(label)
        val ks = keyStore()
        if (ks.containsAlias(attestAlias(label))) ks.deleteEntry(attestAlias(label))
        val strongBox = backing(label) == "strongbox"
        val builder = KeyGenParameterSpec.Builder(attestAlias(label), KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
        if (strongBox) builder.setIsStrongBoxBacked(true)
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(builder.build()); generateKeyPair()
        }
        val chain = ks.getCertificateChain(attestAlias(label)) ?: throw HardwareKeyError("failed", "no certificate chain")
        var out = ByteArray(0)
        for (cert in chain) {
            val der = cert.encoded
            val len = der.size
            out += byteArrayOf((len shr 24).toByte(), (len shr 16).toByte(), (len shr 8).toByte(), len.toByte()) + der
        }
        return mapOf("keyId" to attestAlias(label), "document" to out, "publicKey" to chain[0].publicKey.encoded)
    }

    /** X.509 DER public key of the companion attestation key, when present. */
    private fun publicKey(label: String): ByteArray {
        val cert = keyStore().getCertificate(attestAlias(label)) ?: throw HardwareKeyError("not_found", "no attestation key for $label")
        return cert.publicKey.encoded
    }
}
