// CryptoLib Kotlin/JVM — FULL showcase of every capability family via the FFM API.
//   kotlinc Showcase.kt -include-runtime -d showcase.jar
//   java --enable-native-access=ALL-UNNAMED -jar showcase.jar <dylib>

import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*
import java.lang.invoke.MethodHandle
import java.nio.file.Path

private val BUF: GroupLayout = MemoryLayout.structLayout(ADDRESS.withName("data"), JAVA_LONG.withName("len"))
private val RES: GroupLayout = MemoryLayout.structLayout(BUF.withName("buf"), ADDRESS.withName("error"))
private val KP: GroupLayout = MemoryLayout.structLayout(BUF.withName("pub"), BUF.withName("sec"))
private val PKT: GroupLayout = MemoryLayout.structLayout(BUF.withName("ct"), BUF.withName("sig"), BUF.withName("salt"))
private val BUND: GroupLayout = MemoryLayout.structLayout(BUF.withName("bp"), BUF.withName("bs"), BUF.withName("sp"), BUF.withName("ss"))
private val KEM: GroupLayout = MemoryLayout.structLayout(BUF.withName("ct"), BUF.withName("ss"))
private val Bsz = BUF.byteSize()

class Showcase(path: String) {
    private val a = Arena.ofConfined()
    private val linker = Linker.nativeLinker()
    private val lib = SymbolLookup.libraryLookup(Path.of(path), a)
    private fun h(n: String, fd: FunctionDescriptor) =
        linker.downcallHandle(lib.find(n).orElseThrow { RuntimeException("missing $n") }, fd)
    private fun seg(b: ByteArray) = a.allocateFrom(JAVA_BYTE, *b)
    private fun str(s: String) = a.allocateFrom(s)
    private fun readBuf(s: MemorySegment, off: Long): ByteArray {
        val d = s.get(ADDRESS, off); val n = s.get(JAVA_LONG, off + ADDRESS.byteSize())
        return if (d == MemorySegment.NULL) ByteArray(0) else d.reinterpret(n).toArray(JAVA_BYTE)
    }
    private var pass = 0; private var fail = 0
    private fun ck(l: String, ok: Boolean) { println("  ${if (ok) "✓" else "✗"} $l"); if (ok) pass++ else fail++ }
    private fun hx(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    fun run() {
        val init = h("cryptolib_init", FunctionDescriptor.of(JAVA_INT))
        val version = h("cryptolib_version", FunctionDescriptor.of(ADDRESS))
        val random = h("cryptolib_random_bytes", FunctionDescriptor.of(RES, JAVA_LONG))
        val sha256 = h("cryptolib_sha256", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG))
        val sha512 = h("cryptolib_sha512", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG))
        val blake2b = h("cryptolib_blake2b", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val blake3 = h("cryptolib_blake3", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, JAVA_LONG))
        val hmac256 = h("cryptolib_hmac_sha256", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val hmac256v = h("cryptolib_hmac_sha256_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val hkdf = h("cryptolib_hkdf_derive", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG))
        val argonH = h("cryptolib_argon2id_hash_str", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, JAVA_LONG))
        val argonV = h("cryptolib_argon2id_verify_str", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS))
        val symKey = h("cryptolib_sym_keygen", FunctionDescriptor.of(RES))
        val xEnc = h("cryptolib_xchacha20_encrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val xDec = h("cryptolib_xchacha20_decrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val aesAvail = h("cryptolib_aes256gcm_available", FunctionDescriptor.of(JAVA_INT))
        val aesEnc = h("cryptolib_aes256gcm_encrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val aesDec = h("cryptolib_aes256gcm_decrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val edKg = h("cryptolib_ed25519_keygen", FunctionDescriptor.of(KP))
        val edSign = h("cryptolib_ed25519_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val edVer = h("cryptolib_ed25519_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val xKg = h("cryptolib_x25519_keygen", FunctionDescriptor.of(KP))
        val xSh = h("cryptolib_x25519_shared_secret", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val boxKg = h("cryptolib_box_keygen", FunctionDescriptor.of(KP))
        val boxEnc = h("cryptolib_box_encrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val boxDec = h("cryptolib_box_decrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val sealEnc = h("cryptolib_sealedbox_encrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val sealDec = h("cryptolib_sealedbox_decrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val vCreate = h("cryptolib_vault_create", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT))
        val vSeal = h("cryptolib_vault_seal", FunctionDescriptor.of(PKT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS))
        val vOpen = h("cryptolib_vault_open", FunctionDescriptor.of(RES, ADDRESS, ADDRESS, ADDRESS))
        val vFree = h("cryptolib_vault_free", FunctionDescriptor.ofVoid(ADDRESS))
        val bundleGen = h("cryptolib_asym_bundle_generate", FunctionDescriptor.of(BUND))
        val avSeal = h("cryptolib_asym_vault_seal", FunctionDescriptor.of(PKT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS))
        val avOpen = h("cryptolib_asym_vault_open", FunctionDescriptor.of(RES, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS))
        val kemKg = h("cryptolib_ml_kem_keygen", FunctionDescriptor.of(KP, JAVA_INT))
        val kemEn = h("cryptolib_ml_kem_encapsulate", FunctionDescriptor.of(KEM, ADDRESS, JAVA_LONG, JAVA_INT, ADDRESS))
        val kemDe = h("cryptolib_ml_kem_decapsulate", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT))
        val hyKg = h("cryptolib_hybrid_kem_keygen", FunctionDescriptor.of(KP))
        val hyEn = h("cryptolib_hybrid_kem_encapsulate", FunctionDescriptor.of(KEM, ADDRESS, JAVA_LONG, ADDRESS))
        val hyDe = h("cryptolib_hybrid_kem_decapsulate", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val dsaKg = h("cryptolib_ml_dsa_keygen", FunctionDescriptor.of(KP, JAVA_INT))
        val dsaSign = h("cryptolib_ml_dsa_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT))
        val dsaVer = h("cryptolib_ml_dsa_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT))
        val slhKg = h("cryptolib_slh_dsa_keygen", FunctionDescriptor.of(KP, JAVA_INT, JAVA_INT))
        val slhSign = h("cryptolib_slh_dsa_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT))
        val slhVer = h("cryptolib_slh_dsa_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT))
        val blsKg = h("cryptolib_bls_keygen", FunctionDescriptor.of(KP))
        val blsSign = h("cryptolib_bls_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val blsVer = h("cryptolib_bls_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
        val krCreate = h("cryptolib_keyring_create", FunctionDescriptor.of(ADDRESS))
        val krAddDev = h("cryptolib_keyring_add_device_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG))
        val krAddPw = h("cryptolib_keyring_add_passphrase_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT))
        val krCount = h("cryptolib_keyring_slot_count", FunctionDescriptor.of(JAVA_LONG, ADDRESS))
        val krSer = h("cryptolib_keyring_serialise", FunctionDescriptor.of(RES, ADDRESS))
        val krDeser = h("cryptolib_keyring_deserialise", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, ADDRESS))
        val krUnDev = h("cryptolib_keyring_unlock_with_device", FunctionDescriptor.of(RES, ADDRESS, ADDRESS, JAVA_LONG))
        val krUnPw = h("cryptolib_keyring_unlock_with_passphrase", FunctionDescriptor.of(RES, ADDRESS, ADDRESS))
        val krFree = h("cryptolib_keyring_free", FunctionDescriptor.ofVoid(ADDRESS))
        val bufFree = h("cryptolib_buffer_free", FunctionDescriptor.ofVoid(ADDRESS))
        val pktFree = h("cryptolib_packet_free", FunctionDescriptor.ofVoid(ADDRESS))
        val kpFree = h("cryptolib_keypair_free", FunctionDescriptor.ofVoid(ADDRESS))
        val bundleFree = h("cryptolib_bundle_free", FunctionDescriptor.ofVoid(ADDRESS))
        val kemFree = h("cryptolib_kem_encaps_free", FunctionDescriptor.ofVoid(ADDRESS))

        fun consume(res: MemorySegment): ByteArray { val out = readBuf(res, 0); bufFree.invoke(res); return out }

        check(init.invoke() as Int == 0) { "init" }
        val ver = (version.invoke() as MemorySegment).reinterpret(Long.MAX_VALUE).getString(0)
        println("CryptoLib $ver — Kotlin full showcase\n")
        val abc = "abc".toByteArray(); val msg = "secret payload".toByteArray()
        val ABC = seg(abc); val MSG = seg(msg)

        println("HASHING")
        ck("SHA-256(abc) KAT", hx(consume(sha256.invoke(a, ABC, 3L) as MemorySegment)) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        ck("SHA-512", consume(sha512.invoke(a, ABC, 3L) as MemorySegment).size == 64)
        ck("BLAKE2b", consume(blake2b.invoke(a, ABC, 3L, MemorySegment.NULL, 0L) as MemorySegment).size == 64)
        ck("BLAKE3", consume(blake3.invoke(a, ABC, 3L, 32L) as MemorySegment).size == 32)
        val hk = consume(symKey.invoke(a) as MemorySegment); val HK = seg(hk)
        val mac = consume(hmac256.invoke(a, ABC, 3L, HK, hk.size.toLong()) as MemorySegment)
        ck("HMAC-SHA256 verify", hmac256v.invoke(ABC, 3L, seg(mac), mac.size.toLong(), HK, hk.size.toLong()) as Int == 1)
        ck("HKDF derive", consume(hkdf.invoke(a, HK, hk.size.toLong(), MemorySegment.NULL, 0L, MemorySegment.NULL, 0L, 32L) as MemorySegment).size == 32)
        val phc = String(consume(argonH.invoke(a, str("hunter2"), 2L, 67108864L) as MemorySegment)).trim()
        ck("Argon2id PHC verify", argonV.invoke(str("hunter2"), str(phc)) as Int == 1)

        println("\nSYMMETRIC")
        val sk = consume(symKey.invoke(a) as MemorySegment); val SK = seg(sk)
        val xct = consume(xEnc.invoke(a, MSG, msg.size.toLong(), SK, sk.size.toLong(), MemorySegment.NULL, 0L) as MemorySegment)
        val xpt = consume(xDec.invoke(a, seg(xct), xct.size.toLong(), SK, sk.size.toLong(), MemorySegment.NULL, 0L) as MemorySegment)
        ck("XChaCha20 round-trip", xpt.contentEquals(msg))
        if (aesAvail.invoke() as Int == 1) {
            val act = consume(aesEnc.invoke(a, MSG, msg.size.toLong(), SK, sk.size.toLong(), MemorySegment.NULL, 0L) as MemorySegment)
            val apt = consume(aesDec.invoke(a, seg(act), act.size.toLong(), SK, sk.size.toLong(), MemorySegment.NULL, 0L) as MemorySegment)
            ck("AES-256-GCM round-trip", apt.contentEquals(msg))
        } else println("    AES-256-GCM unavailable")

        println("\nASYMMETRIC")
        val ed = edKg.invoke(a) as MemorySegment; val edPub = readBuf(ed, 0); val edSec = readBuf(ed, Bsz); kpFree.invoke(ed)
        val sig = consume(edSign.invoke(a, ABC, 3L, seg(edSec), edSec.size.toLong()) as MemorySegment)
        ck("Ed25519 sign/verify", edVer.invoke(ABC, 3L, seg(sig), sig.size.toLong(), seg(edPub), edPub.size.toLong()) as Int == 1)
        val xaK = xKg.invoke(a) as MemorySegment; val xaPub = readBuf(xaK, 0); val xaSec = readBuf(xaK, Bsz); kpFree.invoke(xaK)
        val xbK = xKg.invoke(a) as MemorySegment; val xbPub = readBuf(xbK, 0); val xbSec = readBuf(xbK, Bsz); kpFree.invoke(xbK)
        val s1 = consume(xSh.invoke(a, seg(xaSec), xaSec.size.toLong(), seg(xbPub), xbPub.size.toLong()) as MemorySegment)
        val s2 = consume(xSh.invoke(a, seg(xbSec), xbSec.size.toLong(), seg(xaPub), xaPub.size.toLong()) as MemorySegment)
        ck("X25519 ECDH", s1.contentEquals(s2))
        val rK = boxKg.invoke(a) as MemorySegment; val rPub = readBuf(rK, 0); val rSec = readBuf(rK, Bsz); kpFree.invoke(rK)
        val sKp = boxKg.invoke(a) as MemorySegment; val sPub = readBuf(sKp, 0); val sSec = readBuf(sKp, Bsz); kpFree.invoke(sKp)
        val bct = consume(boxEnc.invoke(a, MSG, msg.size.toLong(), seg(rPub), rPub.size.toLong(), seg(sSec), sSec.size.toLong()) as MemorySegment)
        val bpt = consume(boxDec.invoke(a, seg(bct), bct.size.toLong(), seg(sPub), sPub.size.toLong(), seg(rSec), rSec.size.toLong()) as MemorySegment)
        ck("Box round-trip", bpt.contentEquals(msg))
        val sct = consume(sealEnc.invoke(a, MSG, msg.size.toLong(), seg(rPub), rPub.size.toLong()) as MemorySegment)
        val spt = consume(sealDec.invoke(a, seg(sct), sct.size.toLong(), seg(rPub), rPub.size.toLong(), seg(rSec), rSec.size.toLong()) as MemorySegment)
        ck("SealedBox round-trip", spt.contentEquals(msg))

        println("\nVAULTS")
        val vk = consume(random.invoke(a, 32L) as MemorySegment)
        val vault = vCreate.invoke(seg(vk), vk.size.toLong(), 0) as MemorySegment
        val pkt = vSeal.invoke(a, vault, MSG, msg.size.toLong(), str("ctx"), a.allocate(ADDRESS)) as MemorySegment
        ck("SecureVault round-trip", consume(vOpen.invoke(a, vault, pkt, str("ctx")) as MemorySegment).contentEquals(msg))
        pktFree.invoke(pkt); vFree.invoke(vault)
        val alice = bundleGen.invoke(a) as MemorySegment; val bob = bundleGen.invoke(a) as MemorySegment
        val bobBoxPub = readBuf(bob, 0); val aliceSignPub = readBuf(alice, 2 * Bsz)
        val apkt = avSeal.invoke(a, alice, seg(bobBoxPub), bobBoxPub.size.toLong(), MSG, msg.size.toLong(), str("ctx"), a.allocate(ADDRESS)) as MemorySegment
        ck("AsymmetricVault round-trip", consume(avOpen.invoke(a, apkt, bob, seg(aliceSignPub), aliceSignPub.size.toLong(), str("ctx")) as MemorySegment).contentEquals(msg))
        pktFree.invoke(apkt); bundleFree.invoke(alice); bundleFree.invoke(bob)

        println("\nPOST-QUANTUM")
        val kemK = kemKg.invoke(a, 1) as MemorySegment; val kemPub = readBuf(kemK, 0); val kemSec = readBuf(kemK, Bsz); kpFree.invoke(kemK)
        val enc = kemEn.invoke(a, seg(kemPub), kemPub.size.toLong(), 1, a.allocate(ADDRESS)) as MemorySegment
        val ssE = readBuf(enc, Bsz); val kemCt = readBuf(enc, 0)
        val ssD = consume(kemDe.invoke(a, seg(kemCt), kemCt.size.toLong(), seg(kemSec), kemSec.size.toLong(), 1) as MemorySegment)
        ck("ML-KEM-768 encaps/decaps", ssE.contentEquals(ssD) && ssE.size == 32)
        kemFree.invoke(enc)
        val hKemK = hyKg.invoke(a) as MemorySegment; val hPub = readBuf(hKemK, 0); val hSec = readBuf(hKemK, Bsz); kpFree.invoke(hKemK)
        val hEnc = hyEn.invoke(a, seg(hPub), hPub.size.toLong(), a.allocate(ADDRESS)) as MemorySegment
        val hSsE = readBuf(hEnc, Bsz); val hCt = readBuf(hEnc, 0)
        val hSsD = consume(hyDe.invoke(a, seg(hCt), hCt.size.toLong(), seg(hSec), hSec.size.toLong()) as MemorySegment)
        ck("Hybrid X25519+ML-KEM-768 encaps/decaps", hSsE.contentEquals(hSsD) && hSsE.size == 32)
        kemFree.invoke(hEnc)
        val dsaK = dsaKg.invoke(a, 1) as MemorySegment; val dPub = readBuf(dsaK, 0); val dSec = readBuf(dsaK, Bsz); kpFree.invoke(dsaK)
        val dsig = consume(dsaSign.invoke(a, ABC, 3L, seg(dSec), dSec.size.toLong(), 1) as MemorySegment)
        ck("ML-DSA-65 sign/verify", dsaVer.invoke(ABC, 3L, seg(dsig), dsig.size.toLong(), seg(dPub), dPub.size.toLong(), 1) as Int == 1)
        val slhK = slhKg.invoke(a, 1, 0) as MemorySegment; val slPub = readBuf(slhK, 0); val slSec = readBuf(slhK, Bsz); kpFree.invoke(slhK)
        val ssig = consume(slhSign.invoke(a, ABC, 3L, seg(slSec), slSec.size.toLong(), 1, 0) as MemorySegment)
        ck("SLH-DSA-128f sign/verify", slhVer.invoke(ABC, 3L, seg(ssig), ssig.size.toLong(), seg(slPub), slPub.size.toLong(), 1, 0) as Int == 1)

        println("\nBLS12-381")
        val blsK = blsKg.invoke(a) as MemorySegment; val blsPub = readBuf(blsK, 0); val blsSec = readBuf(blsK, Bsz); kpFree.invoke(blsK)
        val bsig = consume(blsSign.invoke(a, ABC, 3L, seg(blsSec), blsSec.size.toLong()) as MemorySegment)
        ck("BLS sign/verify", blsVer.invoke(ABC, 3L, seg(bsig), bsig.size.toLong(), seg(blsPub), blsPub.size.toLong()) as Int == 1)

        println("\nKEYRING")
        val factor = consume(random.invoke(a, 32L) as MemorySegment); val FACTOR = seg(factor)
        val kr = krCreate.invoke() as MemorySegment
        krAddDev.invoke(kr, FACTOR, factor.size.toLong())
        krAddPw.invoke(kr, str("cross-device pass"), 0)
        val blob = consume(krSer.invoke(a, kr) as MemorySegment)
        val kr2 = krDeser.invoke(seg(blob), blob.size.toLong(), a.allocate(ADDRESS)) as MemorySegment
        val mDev = consume(krUnDev.invoke(a, kr2, FACTOR, factor.size.toLong()) as MemorySegment)
        val mPass = consume(krUnPw.invoke(a, kr2, str("cross-device pass")) as MemorySegment)
        ck("Keyring device==passphrase master (${krCount.invoke(kr) as Long} slots)", mDev.contentEquals(mPass) && mDev.size == 32)
        krFree.invoke(kr); krFree.invoke(kr2)

        println("\nKotlin showcase ${if (fail == 0) "OK" else "FAILED"} ($pass passed, $fail failed)")
        if (fail != 0) kotlin.system.exitProcess(1)
    }
}

fun main(args: Array<String>) {
    Showcase(if (args.isNotEmpty()) args[0] else "build/release/libcryptolib_c.dylib").run()
}
