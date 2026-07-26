// Verifies the Phase 1-4 stego/FEC/analysis bindings from Kotlin/JVM via the
// Foreign Function & Memory API (java.lang.foreign) — the same path as Java.
//   kotlinc Phase4Verify.kt -include-runtime -d phase4.jar
//   java --enable-native-access=ALL-UNNAMED -jar phase4.jar <path-to-dylib>
import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*
import java.lang.invoke.MethodHandle
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

private var failures = 0
private fun check(ok: Boolean, label: String) {
    println((if (ok) "  ok   " else " FAIL  ") + label)
    if (!ok) failures++
}

private val CRYPTO_BUFFER = MemoryLayout.structLayout(ADDRESS.withName("data"), JAVA_LONG.withName("len"))
private val CRYPTO_BUFFER_RESULT = MemoryLayout.structLayout(CRYPTO_BUFFER.withName("buf"), ADDRESS.withName("error"))
private val CRYPTO_RESULT = MemoryLayout.structLayout(JAVA_INT.withName("ok"), MemoryLayout.paddingLayout(4), ADDRESS.withName("error"))
private val CRYPTO_FILE_INSPECTION = MemoryLayout.structLayout(
    JAVA_INT.withName("parses"), JAVA_BYTE.withName("format"), MemoryLayout.paddingLayout(3),
    JAVA_INT.withName("ext_matches"), MemoryLayout.paddingLayout(4),
    JAVA_LONG.withName("width"), JAVA_LONG.withName("height"), JAVA_LONG.withName("file_size"),
    ADDRESS.withName("detail"), ADDRESS.withName("error"))
private val CRYPTO_HIDDEN = MemoryLayout.structLayout(
    JAVA_INT.withName("cryptolib_payload"), MemoryLayout.paddingLayout(4),
    JAVA_DOUBLE.withName("lsb_chi_square"), JAVA_DOUBLE.withName("lsb_embedding_likelihood"),
    JAVA_LONG.withName("samples_analysed"), ADDRESS.withName("note"), ADDRESS.withName("error"))
private val CRYPTO_KEYPAIR = MemoryLayout.structLayout(
    CRYPTO_BUFFER.withName("public_key"), CRYPTO_BUFFER.withName("secret_key"))
private val CRYPTO_HEALTH = MemoryLayout.structLayout(
    JAVA_DOUBLE.withName("min_entropy_per_byte"), JAVA_LONG.withName("longest_run"),
    JAVA_LONG.withName("max_window_count"), JAVA_INT.withName("rct_passed"),
    JAVA_INT.withName("apt_passed"), ADDRESS.withName("error"))

class Native(libPath: String) {
    val arena: Arena = Arena.ofConfined()
    private val linker = Linker.nativeLinker()
    private val lib = SymbolLookup.libraryLookup(Path.of(libPath), arena)
    private fun h(name: String, fd: FunctionDescriptor): MethodHandle =
        linker.downcallHandle(lib.find(name).orElseThrow { RuntimeException("missing: $name") }, fd)

    val init = h("cryptolib_init", FunctionDescriptor.of(JAVA_INT))
    val strFree = h("cryptolib_str_free", FunctionDescriptor.ofVoid(ADDRESS))
    val bufferFree = h("cryptolib_buffer_free", FunctionDescriptor.ofVoid(ADDRESS))
    val embed = h("cryptolib_stego_embed", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS))
    val embedKeyed = h("cryptolib_stego_embed_keyed", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG))
    val extractKeyed = h("cryptolib_stego_extract_keyed", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, JAVA_LONG))
    val embedEnc = h("cryptolib_stego_embed_encrypted", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG))
    val extractDec = h("cryptolib_stego_extract_decrypt", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, JAVA_LONG))
    val physSeal = h("cryptolib_physical_seal", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS))
    val physOpen = h("cryptolib_physical_open", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS))
    val fecEncode = h("cryptolib_fec_encode", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, JAVA_INT))
    val fecDecode = h("cryptolib_fec_decode", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_LONG))
    val inspect = h("cryptolib_stego_inspect", FunctionDescriptor.of(CRYPTO_FILE_INSPECTION, ADDRESS))
    val digest = h("cryptolib_stego_content_digest", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS))
    val detect = h("cryptolib_stego_detect_hidden", FunctionDescriptor.of(CRYPTO_HIDDEN, ADDRESS))
    val ifSeal = h("cryptolib_image_factor_seal", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS))
    val ifOpen = h("cryptolib_image_factor_open", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS))
    val hpkeKeygen = h("cryptolib_hpke_keygen", FunctionDescriptor.of(CRYPTO_KEYPAIR))
    val keypairFree = h("cryptolib_keypair_free", FunctionDescriptor.ofVoid(ADDRESS))
    val hsSeal = h("cryptolib_hpke_stego_seal", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS))
    val hsOpen = h("cryptolib_hpke_stego_open", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS))
    val drbgNew = h("cryptolib_drbg_instantiate", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS))
    val drbgGen = h("cryptolib_drbg_generate", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG))
    val drbgFree = h("cryptolib_drbg_free", FunctionDescriptor.ofVoid(ADDRESS))
    val fortNew = h("cryptolib_fortuna_new", FunctionDescriptor.of(ADDRESS))
    val fortAdd = h("cryptolib_fortuna_add_entropy", FunctionDescriptor.ofVoid(ADDRESS, JAVA_BYTE, ADDRESS, JAVA_LONG))
    val fortGen = h("cryptolib_fortuna_generate", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG))
    val fortReseed = h("cryptolib_fortuna_reseed", FunctionDescriptor.ofVoid(ADDRESS))
    val fortCount = h("cryptolib_fortuna_reseed_count", FunctionDescriptor.of(JAVA_LONG, ADDRESS))
    val fortFree = h("cryptolib_fortuna_free", FunctionDescriptor.ofVoid(ADDRESS))
    val assessHealth = h("cryptolib_entropy_assess_file_health", FunctionDescriptor.of(CRYPTO_HEALTH, ADDRESS, JAVA_LONG))

    fun cstr(s: String): MemorySegment = arena.allocateFrom(s)
    fun bytes(b: ByteArray): MemorySegment {
        if (b.isEmpty()) return MemorySegment.NULL
        val seg = arena.allocate(b.size.toLong())
        MemorySegment.copy(b, 0, seg, JAVA_BYTE, 0L, b.size)
        return seg
    }
    fun consume(result: MemorySegment): ByteArray {
        val data = result.get(ADDRESS, 0)
        val len = result.get(JAVA_LONG, ADDRESS.byteSize())
        if (data == MemorySegment.NULL || len == 0L) {
            val err = result.get(ADDRESS, CRYPTO_BUFFER.byteSize())
            if (err != MemorySegment.NULL) strFree.invoke(err)
            return ByteArray(0)
        }
        val out = data.reinterpret(len).toArray(JAVA_BYTE)
        bufferFree.invoke(result)
        return out
    }
    fun okResult(r: MemorySegment): Boolean {
        val ok = r.get(JAVA_INT, 0)
        val err = r.get(ADDRESS, 8)
        if (err != MemorySegment.NULL) strFree.invoke(err)
        return ok != 0
    }
}

private fun noisePpm(p: Path, w: Int, h: Int, seed: Int) {
    val out = java.io.ByteArrayOutputStream()
    out.write("P6\n$w $h\n255\n".toByteArray())
    var s = if (seed == 0) 1 else seed
    for (i in 0 until w * h * 3) { s = s xor (s shl 13); s = s xor (s ushr 17); s = s xor (s shl 5); out.write(s and 0xFF) }
    Files.write(p, out.toByteArray())
}

fun main(args: Array<String>) {
    val libPath = if (args.isNotEmpty()) args[0] else "build/release/libcryptolib_c.dylib"
    val n = Native(libPath)
    if (n.init.invoke() as Int != 0) throw RuntimeException("init failed")
    val dir = Files.createTempDirectory("cl_p4_kt_")
    val key = ByteArray(32) { 0x5a }; val keySeg = n.bytes(key)

    // 1. Keyed stego
    run {
        val cover = dir.resolve("c1.ppm"); val out = dir.resolve("o1.ppm")
        noisePpm(cover, 256, 256, 0xC0FFEE)
        val payload = "keyed stego via Kotlin".toByteArray()
        check(n.okResult(n.embedKeyed.invoke(n.arena, n.cstr(cover.toString()), n.bytes(payload), payload.size.toLong(), n.cstr(out.toString()), keySeg, 32L) as MemorySegment), "keyed embed")
        val got = n.consume(n.extractKeyed.invoke(n.arena, n.cstr(out.toString()), keySeg, 32L) as MemorySegment)
        check(got.contentEquals(payload), "keyed stego round-trip")
        val wrong = ByteArray(32) { 0x99.toByte() }
        val bad = n.consume(n.extractKeyed.invoke(n.arena, n.cstr(out.toString()), n.bytes(wrong), 32L) as MemorySegment)
        check(bad.isEmpty(), "keyed stego wrong-key rejected")
    }

    // 2. Always-encrypt
    run {
        val cover = dir.resolve("c2.ppm"); val out = dir.resolve("o2.ppm")
        noisePpm(cover, 256, 256, 0xBEEF)
        val secret = "never in the clear".toByteArray()
        check(n.okResult(n.embedEnc.invoke(n.arena, n.cstr(cover.toString()), n.bytes(secret), secret.size.toLong(), n.cstr(out.toString()), keySeg, 32L) as MemorySegment), "embed_encrypted")
        val got = n.consume(n.extractDec.invoke(n.arena, n.cstr(out.toString()), keySeg, 32L) as MemorySegment)
        check(got.contentEquals(secret), "always-encrypt round-trip")
    }

    // 3. PhysicalSeal
    run {
        val km = dir.resolve("k3.ppm"); val cover = dir.resolve("c3.ppm"); val out = dir.resolve("o3.ppm")
        noisePpm(km, 64, 64, 0xABCDEF); noisePpm(cover, 256, 256, 0x123456)
        val msg = "the photo is the key".toByteArray(); val aad = "kotlin-ctx".toByteArray()
        check(n.okResult(n.physSeal.invoke(n.arena, n.cstr(km.toString()), n.bytes(msg), msg.size.toLong(), n.bytes(aad), aad.size.toLong(), n.cstr(cover.toString()), n.cstr(out.toString())) as MemorySegment), "physical_seal")
        val got = n.consume(n.physOpen.invoke(n.arena, n.cstr(km.toString()), n.bytes(aad), aad.size.toLong(), n.cstr(out.toString())) as MemorySegment)
        check(got.contentEquals(msg), "PhysicalSeal round-trip")
    }

    // 4. FEC single-flip
    run {
        val data = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte(), 0x00, 0xFF.toByte())
        for (scheme in 1..3) {
            val enc = n.consume(n.fecEncode.invoke(n.arena, n.bytes(data), data.size.toLong(), scheme) as MemorySegment)
            enc[0] = (enc[0].toInt() xor 0x40).toByte()
            val dec = n.consume(n.fecDecode.invoke(n.arena, n.bytes(enc), enc.size.toLong(), scheme, data.size.toLong()) as MemorySegment)
            check(dec.contentEquals(data), "FEC scheme $scheme corrects a single flip")
        }
    }

    // 5. Analysis
    run {
        val cover = dir.resolve("a.ppm"); val stego = dir.resolve("as.ppm")
        noisePpm(cover, 128, 128, 0x99)
        val insp = n.inspect.invoke(n.arena, n.cstr(cover.toString())) as MemorySegment
        val parses = insp.get(JAVA_INT, 0) != 0
        val ext = insp.get(JAVA_INT, 8) != 0
        val width = insp.get(JAVA_LONG, 16)
        val idetail = insp.get(ADDRESS, 40); if (idetail != MemorySegment.NULL) n.strFree.invoke(idetail)
        check(parses && ext && width == 128L, "inspect valid PPM")

        val d1 = n.consume(n.digest.invoke(n.arena, n.cstr(cover.toString())) as MemorySegment)
        Files.write(cover, byteArrayOf(0), StandardOpenOption.APPEND)
        val d2 = n.consume(n.digest.invoke(n.arena, n.cstr(cover.toString())) as MemorySegment)
        check(!d1.contentEquals(d2), "content digest changes on tamper")

        noisePpm(cover, 128, 128, 0x99)
        val hi = "hi".toByteArray()
        n.okResult(n.embed.invoke(n.arena, n.cstr(cover.toString()), n.bytes(hi), hi.size.toLong(), n.cstr(stego.toString())) as MemorySegment)
        val rep = n.detect.invoke(n.arena, n.cstr(stego.toString())) as MemorySegment
        val payload = rep.get(JAVA_INT, 0) != 0
        val note = rep.get(ADDRESS, 32)
        val noteStr = if (note == MemorySegment.NULL) "" else note.reinterpret(Long.MAX_VALUE).getString(0)
        if (note != MemorySegment.NULL) n.strFree.invoke(note)
        check(payload && noteStr.isNotEmpty(), "detect unkeyed payload + honesty note")
    }

    // 6. ImageFactorSeal (C2)
    run {
        val img = dir.resolve("ref.ppm"); val cover = dir.resolve("ifs_cover.ppm"); val out = dir.resolve("ifs_out.ppm")
        noisePpm(img, 64, 64, 0xFEED); noisePpm(cover, 256, 256, 0xCAFE)
        val seed = ByteArray(32) { 0x42 }
        val msg = "image is the second factor".toByteArray()
        check(n.okResult(n.ifSeal.invoke(n.arena, n.bytes(seed), seed.size.toLong(), n.cstr(img.toString()), n.bytes(msg), msg.size.toLong(), MemorySegment.NULL, 0L, n.cstr(cover.toString()), n.cstr(out.toString())) as MemorySegment), "image_factor_seal")
        val got = n.consume(n.ifOpen.invoke(n.arena, n.bytes(seed), seed.size.toLong(), n.cstr(img.toString()), MemorySegment.NULL, 0L, n.cstr(out.toString())) as MemorySegment)
        check(got.contentEquals(msg), "ImageFactorSeal round-trip")
        val other = dir.resolve("ref2.ppm"); noisePpm(other, 64, 64, 0xBEEF)
        val bad = n.consume(n.ifOpen.invoke(n.arena, n.bytes(seed), seed.size.toLong(), n.cstr(other.toString()), MemorySegment.NULL, 0L, n.cstr(out.toString())) as MemorySegment)
        check(bad.isEmpty(), "ImageFactorSeal wrong-image rejected")
    }

    // 7. HpkeStegoSeal (C3)
    run {
        val cover = dir.resolve("hss_cover.ppm"); val out = dir.resolve("hss_out.ppm")
        noisePpm(cover, 256, 256, 0x4321)
        val bufSz = CRYPTO_BUFFER.byteSize()
        val kp = n.hpkeKeygen.invoke(n.arena) as MemorySegment
        val pk = kp.get(ADDRESS, 0).reinterpret(kp.get(JAVA_LONG, ADDRESS.byteSize())).toArray(JAVA_BYTE)
        val sk = kp.get(ADDRESS, bufSz).reinterpret(kp.get(JAVA_LONG, bufSz + ADDRESS.byteSize())).toArray(JAVA_BYTE)
        n.keypairFree.invoke(kp)
        val info = "session".toByteArray(); val msg = "one session keys both".toByteArray()
        val enc = n.consume(n.hsSeal.invoke(n.arena, n.bytes(pk), pk.size.toLong(), n.bytes(msg), msg.size.toLong(), MemorySegment.NULL, 0L, n.bytes(info), info.size.toLong(), n.cstr(cover.toString()), n.cstr(out.toString())) as MemorySegment)
        val got = n.consume(n.hsOpen.invoke(n.arena, n.bytes(sk), sk.size.toLong(), n.bytes(enc), enc.size.toLong(), MemorySegment.NULL, 0L, n.bytes(info), info.size.toLong(), n.cstr(out.toString())) as MemorySegment)
        check(got.contentEquals(msg), "HpkeStegoSeal round-trip")
        val kp2 = n.hpkeKeygen.invoke(n.arena) as MemorySegment
        val sk2 = kp2.get(ADDRESS, bufSz).reinterpret(kp2.get(JAVA_LONG, bufSz + ADDRESS.byteSize())).toArray(JAVA_BYTE)
        n.keypairFree.invoke(kp2)
        val bad = n.consume(n.hsOpen.invoke(n.arena, n.bytes(sk2), sk2.size.toLong(), n.bytes(enc), enc.size.toLong(), MemorySegment.NULL, 0L, n.bytes(info), info.size.toLong(), n.cstr(out.toString())) as MemorySegment)
        check(bad.isEmpty(), "HpkeStegoSeal wrong-recipient rejected")
    }

    // 8. HMAC-DRBG handle (A3)
    run {
        val seed = ByteArray(32) { 0x01 }; val perso = "beacon".toByteArray()
        val errBox = n.arena.allocate(ADDRESS)
        val h1 = n.drbgNew.invoke(n.bytes(seed), seed.size.toLong(), MemorySegment.NULL, 0L, n.bytes(perso), perso.size.toLong(), errBox) as MemorySegment
        val a = n.consume(n.drbgGen.invoke(n.arena, h1, 64L, MemorySegment.NULL, 0L) as MemorySegment)
        val b = n.consume(n.drbgGen.invoke(n.arena, h1, 64L, MemorySegment.NULL, 0L) as MemorySegment)
        check(!a.contentEquals(b), "DRBG successive blocks differ")
        val h2 = n.drbgNew.invoke(n.bytes(seed), seed.size.toLong(), MemorySegment.NULL, 0L, n.bytes(perso), perso.size.toLong(), errBox) as MemorySegment
        check(a.contentEquals(n.consume(n.drbgGen.invoke(n.arena, h2, 64L, MemorySegment.NULL, 0L) as MemorySegment)), "DRBG reproducible from same seed")
        n.drbgFree.invoke(h1); n.drbgFree.invoke(h2)
        val bad = n.drbgNew.invoke(n.bytes(byteArrayOf(1, 2, 3)), 3L, MemorySegment.NULL, 0L, MemorySegment.NULL, 0L, errBox) as MemorySegment
        val err = errBox.get(ADDRESS, 0)
        check(bad == MemorySegment.NULL && err != MemorySegment.NULL, "DRBG short-entropy rejected")
        if (err != MemorySegment.NULL) n.strFree.invoke(err)
    }

    // 9. Fortuna handle (A5)
    run {
        val h = n.fortNew.invoke() as MemorySegment
        check(n.consume(n.fortGen.invoke(n.arena, h, 32L) as MemorySegment).isEmpty(), "Fortuna unseeded generate rejected")
        for (i in 0 until 40) { val d = ByteArray(16) { i.toByte() }; n.fortAdd.invoke(h, (i and 7).toByte(), n.bytes(d), d.size.toLong()) }
        n.fortReseed.invoke(h)
        check((n.fortCount.invoke(h) as Long) >= 1, "Fortuna reseed count advances")
        check(n.consume(n.fortGen.invoke(n.arena, h, 64L) as MemorySegment).size == 64, "Fortuna generate after seeding")
        n.fortFree.invoke(h)
    }

    // 10. assess_file_health (A1)
    run {
        val good = dir.resolve("good.ppm"); noisePpm(good, 128, 128, 0x1357)
        val hr = n.assessHealth.invoke(n.arena, n.cstr(good.toString()), 0L) as MemorySegment
        val healthy = hr.get(ADDRESS, 32) == MemorySegment.NULL &&
            hr.get(JAVA_DOUBLE, 0) > 1.0 && hr.get(JAVA_INT, 24) != 0 && hr.get(JAVA_INT, 28) != 0
        check(healthy, "assess_file_health: noise carrier healthy")
        val flat = dir.resolve("flat.ppm")
        val header = "P6\n64 64\n255\n".toByteArray()
        val body = ByteArray(header.size + 64 * 64 * 3); System.arraycopy(header, 0, body, 0, header.size)
        Files.write(flat, body)
        val hf = n.assessHealth.invoke(n.arena, n.cstr(flat.toString()), 0L) as MemorySegment
        val flatHealthy = hf.get(JAVA_DOUBLE, 0) >= 1.0 && hf.get(JAVA_INT, 24) != 0 && hf.get(JAVA_INT, 28) != 0
        check(!flatHealthy, "assess_file_health: constant carrier flagged")
    }

    println(if (failures == 0) "ALL PASS" else "$failures FAILURE(S)")
    kotlin.system.exitProcess(if (failures == 0) 0 else 1)
}
