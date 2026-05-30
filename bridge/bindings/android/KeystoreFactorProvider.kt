package com.cryptolib.keyring

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Android Keystore device-factor provider for the CryptoLib keyring.
 *
 * Creates a NON-EXPORTABLE HMAC-SHA256 key in the Android Keystore (hardware /
 * TEE / StrongBox backed on capable devices). The 32-byte device factor is
 * `HMAC(key, label)` — deterministic across launches, but the key bytes never
 * leave secure hardware. Feed the returned factor to the keyring's device slot:
 *
 *   val factor = KeystoreFactorProvider.deviceFactorKey(requireBiometric = true)
 *   // then, over JNI/JNA to libcryptolib_c.so (Android has no java.lang.foreign),
 *   // or via a Flutter MethodChannel handing the bytes to the Dart keyring binding:
 *   //   cryptolib_keyring_add_device_slot(kr, factor, factor.size)   // enroll
 *   //   cryptolib_keyring_unlock_with_device(kr, factor, factor.size) // unlock
 *
 * BUILD/RUN: this is app code — it needs the Android SDK + Gradle and runs on a
 * device/emulator inside an app process (the AndroidKeyStore JCA provider
 * requires the Android runtime). It is NOT buildable from a desktop CLI. The
 * factor→keyring round-trip itself is verified by the cross-platform keyring
 * tests (any 32-byte factor drives `*_device_slot`).
 *
 * BIOMETRIC GATING (production): with requireBiometric = true, every factor
 * fetch requires a fresh strong biometric (Class 3). Combine with StrongBox via
 * setIsStrongBoxBacked(true) where supported. Pair with a passphrase slot for a
 * revocable cross-device recovery path.
 */
object KeystoreFactorProvider {
    private const val ALIAS = "cryptolib.keyring.device.factor"
    private const val LABEL = "cryptolib:keyring:factor:v1"
    private const val STORE = "AndroidKeyStore"

    private fun getOrCreateKey(requireBiometric: Boolean): SecretKey {
        val ks = KeyStore.getInstance(STORE).apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, STORE)
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply {
                if (requireBiometric) {
                    setUserAuthenticationRequired(true)
                    // API 30+: require a strong biometric for every use (no time window).
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                }
            }
            .build()
        gen.init(spec)
        return gen.generateKey()
    }

    /** Deterministic 32-byte device factor key, bound to this device's hardware. */
    fun deviceFactorKey(requireBiometric: Boolean = false): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(getOrCreateKey(requireBiometric))
        return mac.doFinal(LABEL.toByteArray(Charsets.UTF_8)) // 32 bytes
    }

    /** Revoke the device factor (e.g. on logout / re-enrollment). */
    fun deleteFactor() {
        KeyStore.getInstance(STORE).apply { load(null) }.deleteEntry(ALIAS)
    }
}
