// CryptoLib Kotlin/JVM demo using the Foreign Function & Memory API (JDK 22+).
//
// Kotlin calls java.lang.foreign directly — the same binding strategy as the
// Java demo, no JNI. On Android, prefer the prebuilt .so (see `make android`)
// loaded via JNI/JNA, since Android's runtime does not expose the FFM API.
//
// Build/run (needs kotlinc 2.x + JDK 22+; see Makefile target `kotlin`):
//   kotlinc CryptoLibDemo.kt -include-runtime -d demo.jar
//   java --enable-native-access=ALL-UNNAMED -jar demo.jar <path-to-libcryptolib_c.dylib>

import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*
import java.lang.invoke.MethodHandle
import java.nio.file.Path

private val CRYPTO_BUFFER: GroupLayout = MemoryLayout.structLayout(
    ADDRESS.withName("data"), JAVA_LONG.withName("len"))
private val CRYPTO_BUFFER_RESULT: GroupLayout = MemoryLayout.structLayout(
    CRYPTO_BUFFER.withName("buf"), ADDRESS.withName("error"))
private val CRYPTO_PACKET: GroupLayout = MemoryLayout.structLayout(
    CRYPTO_BUFFER.withName("ciphertext"),
    CRYPTO_BUFFER.withName("signature"),
    CRYPTO_BUFFER.withName("kdf_salt"))
private val CRYPTO_KEYPAIR: GroupLayout = MemoryLayout.structLayout(
    CRYPTO_BUFFER.withName("public_key"), CRYPTO_BUFFER.withName("secret_key"))

class CryptoLib(libPath: String) {
    private val arena: Arena = Arena.ofConfined()
    private val linker = Linker.nativeLinker()
    private val lib = SymbolLookup.libraryLookup(Path.of(libPath), arena)

    private fun h(name: String, fd: FunctionDescriptor): MethodHandle =
        linker.downcallHandle(lib.find(name).orElseThrow { RuntimeException("missing: $name") }, fd)

    private val init        = h("cryptolib_init",         FunctionDescriptor.of(JAVA_INT))
    private val version     = h("cryptolib_version",      FunctionDescriptor.of(ADDRESS))
    private val randomBytes = h("cryptolib_random_bytes", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, JAVA_LONG))
    private val sha256      = h("cryptolib_sha256",       FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG))
    private val vaultCreate = h("cryptolib_vault_create", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT))
    private val vaultSeal    = h("cryptolib_vault_seal",  FunctionDescriptor.of(CRYPTO_PACKET, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS))
    private val vaultOpen    = h("cryptolib_vault_open",  FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, ADDRESS))
    private val bufferFree  = h("cryptolib_buffer_free",  FunctionDescriptor.ofVoid(ADDRESS))
    private val packetFree  = h("cryptolib_packet_free",  FunctionDescriptor.ofVoid(ADDRESS))
    private val vaultFree   = h("cryptolib_vault_free",   FunctionDescriptor.ofVoid(ADDRESS))
    private val krCreate    = h("cryptolib_keyring_create",   FunctionDescriptor.of(ADDRESS))
    private val krAddDev    = h("cryptolib_keyring_add_device_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG))
    private val krAddPw     = h("cryptolib_keyring_add_passphrase_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT))
    private val krCount     = h("cryptolib_keyring_slot_count", FunctionDescriptor.of(JAVA_LONG, ADDRESS))
    private val krSer       = h("cryptolib_keyring_serialise", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS))
    private val krDeser     = h("cryptolib_keyring_deserialise", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, ADDRESS))
    private val krUnlockDev = h("cryptolib_keyring_unlock_with_device", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, JAVA_LONG))
    private val krUnlockPw  = h("cryptolib_keyring_unlock_with_passphrase", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS))
    private val krFree      = h("cryptolib_keyring_free",     FunctionDescriptor.ofVoid(ADDRESS))
    private val keypairFree = h("cryptolib_keypair_free",     FunctionDescriptor.ofVoid(ADDRESS))
    private val strFree     = h("cryptolib_str_free",         FunctionDescriptor.ofVoid(ADDRESS))

    // Newly exposed feature functions.
    private val committingEnc = h("cryptolib_committing_encrypt",
        FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
    private val committingDec = h("cryptolib_committing_decrypt",
        FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
    private val hmac256       = h("cryptolib_hmac_sha256",
        FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
    private val hmac256Verify = h("cryptolib_hmac_sha256_verify",
        FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
    private val hkdfExtract   = h("cryptolib_hkdf_extract",
        FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
    private val hkdfExpand    = h("cryptolib_hkdf_expand",
        FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG))
    private val hkdfDerive    = h("cryptolib_hkdf_derive",
        FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG))
    private val hybridSigKeygen = h("cryptolib_hybrid_sig_keygen", FunctionDescriptor.of(CRYPTO_KEYPAIR))
    private val hybridSigSign = h("cryptolib_hybrid_sig_sign",
        FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
    private val hybridSigVerify = h("cryptolib_hybrid_sig_verify",
        FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
    private val blsKeygenFromIkm = h("cryptolib_bls_keygen_from_ikm",
        FunctionDescriptor.of(CRYPTO_KEYPAIR, ADDRESS, JAVA_LONG))

    private fun consume(result: MemorySegment): ByteArray {
        val data = result.get(ADDRESS, 0)
        val len = result.get(JAVA_LONG, ADDRESS.byteSize())
        if (data == MemorySegment.NULL || len == 0L) return ByteArray(0)
        val out = data.reinterpret(len).toArray(JAVA_BYTE)
        bufferFree.invoke(result)
        return out
    }

    private fun consumeKeypair(kp: MemorySegment): Pair<ByteArray, ByteArray> {
        val bufSz = CRYPTO_BUFFER.byteSize()
        val pubData = kp.get(ADDRESS, 0); val pubLen = kp.get(JAVA_LONG, ADDRESS.byteSize())
        val secData = kp.get(ADDRESS, bufSz); val secLen = kp.get(JAVA_LONG, bufSz + ADDRESS.byteSize())
        val pub = if (pubData == MemorySegment.NULL) ByteArray(0) else pubData.reinterpret(pubLen).toArray(JAVA_BYTE)
        val sec = if (secData == MemorySegment.NULL) ByteArray(0) else secData.reinterpret(secLen).toArray(JAVA_BYTE)
        keypairFree.invoke(kp)
        return pub to sec
    }

    fun run() {
        check(init.invoke() as Int == 0) { "init failed" }
        val ver = (version.invoke() as MemorySegment).reinterpret(Long.MAX_VALUE).getString(0)
        println("CryptoLib version: $ver")

        val rnd = consume(randomBytes.invoke(arena, 32L) as MemorySegment)
        println("random(32):  " + rnd.joinToString("") { "%02x".format(it) })

        val msg = arena.allocateFrom(JAVA_BYTE, *"abc".toByteArray())
        val digest = consume(sha256.invoke(arena, msg, 3L) as MemorySegment)
        println("sha256(abc): " + digest.joinToString("") { "%02x".format(it) })

        val key = arena.allocateFrom(JAVA_BYTE, *consume(randomBytes.invoke(arena, 32L) as MemorySegment))
        val vault = vaultCreate.invoke(key, key.byteSize(), 0) as MemorySegment
        val pt = "hello from kotlin".toByteArray()
        val ptSeg = arena.allocateFrom(JAVA_BYTE, *pt)
        val aad = arena.allocateFrom("ctx")
        val errOut = arena.allocate(ADDRESS)
        val packet = vaultSeal.invoke(arena, vault, ptSeg, pt.size.toLong(), aad, errOut) as MemorySegment
        check(errOut.get(ADDRESS, 0) == MemorySegment.NULL) { "seal failed" }
        val opened = consume(vaultOpen.invoke(arena, vault, packet, aad) as MemorySegment)
        println("vault roundtrip: \"${String(opened)}\"")
        packetFree.invoke(packet)
        vaultFree.invoke(vault)

        // Keyring: default device slot + opt-in passphrase slot → cross-device.
        val factor = consume(randomBytes.invoke(arena, 32L) as MemorySegment)
        val factorSeg = arena.allocateFrom(JAVA_BYTE, *factor)
        val kr = krCreate.invoke() as MemorySegment
        krAddDev.invoke(kr, factorSeg, factor.size.toLong())
        krAddPw.invoke(kr, arena.allocateFrom("cross-device pass"), 0)
        val blob = consume(krSer.invoke(arena, kr) as MemorySegment)
        val blobSeg = arena.allocateFrom(JAVA_BYTE, *blob)
        val krErr = arena.allocate(ADDRESS)
        val kr2 = krDeser.invoke(blobSeg, blob.size.toLong(), krErr) as MemorySegment
        val mDev  = consume(krUnlockDev.invoke(arena, kr2, factorSeg, factor.size.toLong()) as MemorySegment)
        val mPass = consume(krUnlockPw.invoke(arena, kr2, arena.allocateFrom("cross-device pass")) as MemorySegment)
        println("keyring slots: ${krCount.invoke(kr) as Long} · device==passphrase master: ${mDev.contentEquals(mPass)}")
        krFree.invoke(kr)
        krFree.invoke(kr2)

        // ── Newly exposed feature functions ──
        // Committing AEAD (UtC): wrong key must fail.
        val caKey = consume(randomBytes.invoke(arena, 32L) as MemorySegment)
        val caKeySeg = arena.allocateFrom(JAVA_BYTE, *caKey)
        val caPt = "commit me".toByteArray(); val caPtSeg = arena.allocateFrom(JAVA_BYTE, *caPt)
        val caAad = "ctx".toByteArray(); val caAadSeg = arena.allocateFrom(JAVA_BYTE, *caAad)
        val caCt = consume(committingEnc.invoke(arena, caPtSeg, caPt.size.toLong(), caKeySeg, caKey.size.toLong(), caAadSeg, caAad.size.toLong()) as MemorySegment)
        val caCtSeg = arena.allocateFrom(JAVA_BYTE, *caCt)
        val caDec = consume(committingDec.invoke(arena, caCtSeg, caCt.size.toLong(), caKeySeg, caKey.size.toLong(), caAadSeg, caAad.size.toLong()) as MemorySegment)
        val wrongKey = consume(randomBytes.invoke(arena, 32L) as MemorySegment)
        val wrongKeySeg = arena.allocateFrom(JAVA_BYTE, *wrongKey)
        val caBad = committingDec.invoke(arena, caCtSeg, caCt.size.toLong(), wrongKeySeg, wrongKey.size.toLong(), caAadSeg, caAad.size.toLong()) as MemorySegment
        val caReject = caBad.get(ADDRESS, 0) == MemorySegment.NULL
        val caBadErr = caBad.get(ADDRESS, CRYPTO_BUFFER.byteSize())
        if (caBadErr != MemorySegment.NULL) strFree.invoke(caBadErr)
        println("committing AEAD: roundtrip=\"${String(caDec)}\" reject-wrong-key=$caReject")

        // HKDF-SHA256 + HMAC-SHA256.
        val ikm = consume(randomBytes.invoke(arena, 32L) as MemorySegment)
        val ikmSeg = arena.allocateFrom(JAVA_BYTE, *ikm)
        val saltB = "salt".toByteArray(); val infoB = "app".toByteArray()
        val saltSeg = arena.allocateFrom(JAVA_BYTE, *saltB); val infoSeg = arena.allocateFrom(JAVA_BYTE, *infoB)
        val prk = consume(hkdfExtract.invoke(arena, saltSeg, saltB.size.toLong(), ikmSeg, ikm.size.toLong()) as MemorySegment)
        val prkSeg = arena.allocateFrom(JAVA_BYTE, *prk)
        val okm = consume(hkdfExpand.invoke(arena, prkSeg, prk.size.toLong(), infoSeg, infoB.size.toLong(), 42L) as MemorySegment)
        val okm1 = consume(hkdfDerive.invoke(arena, ikmSeg, ikm.size.toLong(), saltSeg, saltB.size.toLong(), infoSeg, infoB.size.toLong(), 42L) as MemorySegment)
        val macMsg = "mac me".toByteArray(); val macMsgSeg = arena.allocateFrom(JAVA_BYTE, *macMsg)
        val mac256b = consume(hmac256.invoke(arena, macMsgSeg, macMsg.size.toLong(), ikmSeg, ikm.size.toLong()) as MemorySegment)
        val macSeg = arena.allocateFrom(JAVA_BYTE, *mac256b)
        val macOk = (hmac256Verify.invoke(macMsgSeg, macMsg.size.toLong(), macSeg, mac256b.size.toLong(), ikmSeg, ikm.size.toLong()) as Int) == 1
        println("hkdf len=${okm.size} consistent=${okm.contentEquals(okm1)} · hmac256 verify=$macOk")

        // Hybrid signature (Ed25519 + ML-DSA-65).
        val (hPub, hSec) = consumeKeypair(hybridSigKeygen.invoke(arena) as MemorySegment)
        val hPubSeg = arena.allocateFrom(JAVA_BYTE, *hPub); val hSecSeg = arena.allocateFrom(JAVA_BYTE, *hSec)
        val sMsg = "sign me".toByteArray(); val sMsgSeg = arena.allocateFrom(JAVA_BYTE, *sMsg)
        val hsig = consume(hybridSigSign.invoke(arena, sMsgSeg, sMsg.size.toLong(), hSecSeg, hSec.size.toLong()) as MemorySegment)
        val hsigSeg = arena.allocateFrom(JAVA_BYTE, *hsig)
        val hsigOk = (hybridSigVerify.invoke(sMsgSeg, sMsg.size.toLong(), hsigSeg, hsig.size.toLong(), hPubSeg, hPub.size.toLong()) as Int) == 1
        println("hybrid sig: len=${hsig.size} verify=$hsigOk")

        // BLS deterministic keygen from IKM.
        val blsIkm = consume(randomBytes.invoke(arena, 32L) as MemorySegment)
        val blsIkmSeg = arena.allocateFrom(JAVA_BYTE, *blsIkm)
        val (d1Pub, _) = consumeKeypair(blsKeygenFromIkm.invoke(arena, blsIkmSeg, blsIkm.size.toLong()) as MemorySegment)
        val (d2Pub, _) = consumeKeypair(blsKeygenFromIkm.invoke(arena, blsIkmSeg, blsIkm.size.toLong()) as MemorySegment)
        println("bls keygen-from-ikm deterministic: ${d1Pub.contentEquals(d2Pub)}")

        println("Kotlin demo OK")
    }
}

fun main(args: Array<String>) {
    val path = if (args.isNotEmpty()) args[0] else "build/release/libcryptolib_c.dylib"
    CryptoLib(path).run()
}
