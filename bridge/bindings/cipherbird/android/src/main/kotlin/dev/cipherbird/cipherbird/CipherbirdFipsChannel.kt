package dev.cipherbird.cipherbird

import android.os.Build
import android.os.Handler
import android.os.Looper
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Validated-module cryptography on Android, served to Dart on the
 * "cipherbird/fips" method channel.
 *
 * Every operation goes through javax.crypto and java.security, which the
 * platform routes to its default provider: Conscrypt (BoringCrypto) on
 * current Android releases. The provider that served each algorithm is
 * reported by "module" so the app can pin what it accepts. HKDF and PBKDF2 are
 * the only compositions done here: every HMAC call runs in the provider and
 * the RFC 5869 and RFC 8018 arithmetic around them in this class, which
 * "module" reports as hkdfComposed and pbkdf2Composed. Wire formats match the engine's fips profile.
 */
class CipherbirdFipsChannel(messenger: BinaryMessenger) : MethodChannel.MethodCallHandler {
    private val channel = MethodChannel(messenger, "cipherbird/fips")
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val random = SecureRandom()

    init { channel.setMethodCallHandler(this) }

    fun dispose() { channel.setMethodCallHandler(null) }

    private class FipsError(val code: String, message: String) : Exception(message)

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        worker.execute {
            try {
                val value: Any? = when (call.method) {
                    "module" -> module()
                    "digest" -> MessageDigest.getInstance(digestName(call.argument("hash")!!)).digest(call.argument("data")!!)
                    "hmac" -> hmac(call.argument("hash")!!, call.argument("key")!!, call.argument("data")!!)
                    "hkdf" -> hkdf(call.argument("hash")!!, call.argument("ikm")!!, call.argument("salt") ?: ByteArray(0),
                        call.argument("info") ?: ByteArray(0), call.argument("count")!!)
                    "pbkdf2" -> pbkdf2(call.argument("hash")!!, call.argument("password")!!, call.argument("salt")!!,
                        call.argument("iterations")!!, call.argument("count")!!)
                    "random" -> ByteArray(call.argument<Int>("count")!!).also { random.nextBytes(it) }
                    "aesGcmEncrypt" -> aesGcmEncrypt(call.argument("key")!!, call.argument("plaintext")!!, call.argument("aad") ?: ByteArray(0))
                    "aesGcmDecrypt" -> aesGcmDecrypt(call.argument("key")!!, call.argument("wire")!!, call.argument("aad") ?: ByteArray(0))
                    "p256Keygen" -> p256Keygen()
                    "p256Ecdh" -> p256Ecdh(call.argument("privateKey")!!, call.argument("peerPublic")!!)
                    "p256Sign" -> p256Sign(call.argument("privateKey")!!, call.argument("message")!!)
                    "p256Verify" -> p256Verify(call.argument("publicKey")!!, call.argument("message")!!, call.argument("signature")!!)
                    else -> null
                }
                main.post { if (value == null) result.notImplemented() else result.success(value) }
            } catch (e: FipsError) {
                main.post { result.error(e.code, e.message, null) }
            } catch (e: Exception) {
                main.post { result.error("failed", e.toString(), null) }
            }
        }
    }

    private fun digestName(hash: Int): String = when (hash) {
        0 -> "SHA-256"
        1 -> "SHA-384"
        2 -> "SHA-512"
        3 -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) "SHA3-256" else throw FipsError("unsupported", "SHA3-256 needs API 28")
        else -> throw FipsError("unsupported", "unknown hash id $hash")
    }

    private fun macName(hash: Int): String = when (hash) {
        0 -> "HmacSHA256"
        1 -> "HmacSHA384"
        2 -> "HmacSHA512"
        else -> throw FipsError("unsupported", "no HMAC for hash id $hash")
    }

    private fun module(): Map<String, Any> {
        val providers = mapOf(
            "digest" to MessageDigest.getInstance("SHA-256").provider.name,
            "hmac" to Mac.getInstance("HmacSHA256").provider.name,
            "aesGcm" to Cipher.getInstance("AES/GCM/NoPadding").provider.name,
            "ec" to KeyPairGenerator.getInstance("EC").provider.name,
            "ecdsa" to Signature.getInstance("SHA256withECDSA").provider.name,
            "pbkdf2" to Mac.getInstance("HmacSHA256").provider.name,
            "random" to random.provider.name,
        )
        return mapOf(
            "module" to "Android platform providers (Conscrypt/BoringCrypto where reported as AndroidOpenSSL)",
            "platform" to "Android API ${Build.VERSION.SDK_INT}",
            "providers" to providers,
            "hkdfComposed" to true,
            "pbkdf2Composed" to true,
        )
    }

    private fun hmac(hash: Int, key: ByteArray, data: ByteArray): ByteArray {
        if (key.size < 14) throw FipsError("bad_argument", "HMAC key must be at least 14 bytes")
        return Mac.getInstance(macName(hash)).run { init(SecretKeySpec(key, algorithm)); doFinal(data) }
    }

    private fun hkdf(hash: Int, ikm: ByteArray, salt: ByteArray, info: ByteArray, count: Int): ByteArray {
        val name = macName(hash)
        val mac = Mac.getInstance(name)
        val hashLen = mac.macLength
        if (count < 14 || count > 255 * hashLen) throw FipsError("bad_argument", "HKDF output length out of range")
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(hashLen) else salt, name))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, name))
        val okm = ByteArray(count)
        var previous = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < count) {
            mac.update(previous); mac.update(info); mac.update(counter.toByte())
            previous = mac.doFinal()
            val take = minOf(previous.size, count - written)
            System.arraycopy(previous, 0, okm, written, take)
            written += take; counter += 1
        }
        prk.fill(0); previous.fill(0)
        return okm
    }

    /** RFC 8018 PBKDF2 over the provider's HMAC: the PRF runs in the module,
     *  the iteration loop here (the platform's own PBKDF2 is served by the
     *  software BouncyCastle provider, which is not the validated module). */
    private fun pbkdf2(hash: Int, password: ByteArray, salt: ByteArray, iterations: Int, count: Int): ByteArray {
        if (salt.size < 16 || iterations < 1000 || count < 14) throw FipsError("bad_argument", "PBKDF2 outside policy")
        val name = macName(hash)
        val mac = Mac.getInstance(name)
        mac.init(SecretKeySpec(if (password.isEmpty()) ByteArray(1) else password, name))
        val hashLen = mac.macLength
        val out = ByteArray(count)
        var written = 0
        var block = 1
        while (written < count) {
            mac.update(salt)
            mac.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (i in 2..iterations) {
                u = mac.doFinal(u)
                for (j in t.indices) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
            }
            val take = minOf(hashLen, count - written)
            System.arraycopy(t, 0, out, written, take)
            t.fill(0); u.fill(0)
            written += take; block += 1
        }
        return out
    }

    private fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        if (key.size != 32) throw FipsError("bad_argument", "AES-256-GCM key must be 32 bytes")
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        return iv + cipher.doFinal(plaintext)
    }

    private fun aesGcmDecrypt(key: ByteArray, wire: ByteArray, aad: ByteArray): ByteArray {
        if (key.size != 32 || wire.size < 28) throw FipsError("bad_argument", "AES-256-GCM input too short")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, wire, 0, 12))
        cipher.updateAAD(aad)
        try {
            return cipher.doFinal(wire, 12, wire.size - 12)
        } catch (e: Exception) {
            throw FipsError("authentication_failed", "AES-256-GCM authentication failed")
        }
    }

    private fun p256Params(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC").run { init(ECGenParameterSpec("secp256r1")); getParameterSpec(ECParameterSpec::class.java) }

    private fun padded(n: BigInteger): ByteArray {
        val raw = n.toByteArray()
        val out = ByteArray(32)
        val start = maxOf(0, raw.size - 32)
        System.arraycopy(raw, start, out, 32 - (raw.size - start), raw.size - start)
        return out
    }

    private fun encodePublic(key: ECPublicKey): ByteArray = byteArrayOf(4) + padded(key.w.affineX) + padded(key.w.affineY)

    private fun decodePublic(bytes: ByteArray): ECPublicKey {
        if (bytes.size != 65 || bytes[0] != 4.toByte()) throw FipsError("bad_argument", "P-256 public key must be 65 bytes uncompressed")
        val point = ECPoint(BigInteger(1, bytes.copyOfRange(1, 33)), BigInteger(1, bytes.copyOfRange(33, 65)))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, p256Params())) as ECPublicKey
    }

    private fun decodePrivate(bytes: ByteArray): ECPrivateKey {
        if (bytes.size != 32) throw FipsError("bad_argument", "P-256 private key must be 32 bytes")
        return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, bytes), p256Params())) as ECPrivateKey
    }

    private fun p256Keygen(): Map<String, ByteArray> {
        val pair = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        return mapOf("publicKey" to encodePublic(pair.public as ECPublicKey), "privateKey" to padded((pair.private as ECPrivateKey).s))
    }

    private fun p256Ecdh(priv: ByteArray, peer: ByteArray): ByteArray =
        KeyAgreement.getInstance("ECDH").run { init(decodePrivate(priv)); doPhase(decodePublic(peer), true); generateSecret() }

    private fun p256Sign(priv: ByteArray, message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run { initSign(decodePrivate(priv)); update(message); sign() }

    private fun p256Verify(pub: ByteArray, message: ByteArray, signature: ByteArray): Boolean = try {
        Signature.getInstance("SHA256withECDSA").run { initVerify(decodePublic(pub)); update(message); verify(signature) }
    } catch (e: Exception) { false }
}
