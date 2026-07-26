// Verifies the Phase 1-4 stego/FEC/analysis bindings via the Foreign Function &
// Memory API. Pure Java, no JNI.
//   javac Phase4Verify.java
//   java --enable-native-access=ALL-UNNAMED Phase4Verify <path-to-libcryptolib_c.dylib>
// Exits non-zero on any failure.
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static java.lang.foreign.ValueLayout.*;

public final class Phase4Verify {

    static final GroupLayout CRYPTO_BUFFER = MemoryLayout.structLayout(
            ADDRESS.withName("data"), JAVA_LONG.withName("len"));
    static final GroupLayout CRYPTO_BUFFER_RESULT = MemoryLayout.structLayout(
            CRYPTO_BUFFER.withName("buf"), ADDRESS.withName("error"));
    static final GroupLayout CRYPTO_RESULT = MemoryLayout.structLayout(
            JAVA_INT.withName("ok"), MemoryLayout.paddingLayout(4), ADDRESS.withName("error"));
    static final GroupLayout CRYPTO_FILE_INSPECTION = MemoryLayout.structLayout(
            JAVA_INT.withName("parses"), JAVA_BYTE.withName("format"), MemoryLayout.paddingLayout(3),
            JAVA_INT.withName("ext_matches"), MemoryLayout.paddingLayout(4),
            JAVA_LONG.withName("width"), JAVA_LONG.withName("height"), JAVA_LONG.withName("file_size"),
            ADDRESS.withName("detail"), ADDRESS.withName("error"));
    static final GroupLayout CRYPTO_HIDDEN = MemoryLayout.structLayout(
            JAVA_INT.withName("cryptolib_payload"), MemoryLayout.paddingLayout(4),
            JAVA_DOUBLE.withName("lsb_chi_square"), JAVA_DOUBLE.withName("lsb_embedding_likelihood"),
            JAVA_LONG.withName("samples_analysed"), ADDRESS.withName("note"), ADDRESS.withName("error"));

    final Arena arena = Arena.ofConfined();
    static final GroupLayout CRYPTO_KEYPAIR = MemoryLayout.structLayout(
            CRYPTO_BUFFER.withName("public_key"), CRYPTO_BUFFER.withName("secret_key"));
    static final GroupLayout CRYPTO_HEALTH = MemoryLayout.structLayout(
            JAVA_DOUBLE.withName("min_entropy_per_byte"), JAVA_LONG.withName("longest_run"),
            JAVA_LONG.withName("max_window_count"), JAVA_INT.withName("rct_passed"),
            JAVA_INT.withName("apt_passed"), ADDRESS.withName("error"));

    final MethodHandle init, strFree, bufferFree, embed,
            embedKeyed, extractKeyed, embedEnc, extractDec,
            physSeal, physOpen, fecEncode, fecDecode,
            inspect, digest, detect,
            ifSeal, ifOpen, hpkeKeygen, keypairFree, hsSeal, hsOpen,
            drbgNew, drbgGen, drbgFree, fortNew, fortAdd, fortGen, fortReseed, fortCount, fortFree,
            assessHealth;

    static int failures = 0;
    static void check(boolean ok, String label) {
        System.out.println((ok ? "  ok   " : " FAIL  ") + label);
        if (!ok) failures++;
    }

    Phase4Verify(String libPath) {
        Linker l = Linker.nativeLinker();
        SymbolLookup lib = SymbolLookup.libraryLookup(Path.of(libPath), arena);
        init        = h(l, lib, "cryptolib_init", FunctionDescriptor.of(JAVA_INT));
        strFree     = h(l, lib, "cryptolib_str_free", FunctionDescriptor.ofVoid(ADDRESS));
        bufferFree  = h(l, lib, "cryptolib_buffer_free", FunctionDescriptor.ofVoid(ADDRESS));
        embed       = h(l, lib, "cryptolib_stego_embed", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        embedKeyed  = h(l, lib, "cryptolib_stego_embed_keyed", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG));
        extractKeyed= h(l, lib, "cryptolib_stego_extract_keyed", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, JAVA_LONG));
        embedEnc    = h(l, lib, "cryptolib_stego_embed_encrypted", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG));
        extractDec  = h(l, lib, "cryptolib_stego_extract_decrypt", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, JAVA_LONG));
        physSeal    = h(l, lib, "cryptolib_physical_seal", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
        physOpen    = h(l, lib, "cryptolib_physical_open", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        fecEncode   = h(l, lib, "cryptolib_fec_encode", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, JAVA_INT));
        fecDecode   = h(l, lib, "cryptolib_fec_decode", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_LONG));
        inspect     = h(l, lib, "cryptolib_stego_inspect", FunctionDescriptor.of(CRYPTO_FILE_INSPECTION, ADDRESS));
        digest      = h(l, lib, "cryptolib_stego_content_digest", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS));
        detect      = h(l, lib, "cryptolib_stego_detect_hidden", FunctionDescriptor.of(CRYPTO_HIDDEN, ADDRESS));
        ifSeal      = h(l, lib, "cryptolib_image_factor_seal", FunctionDescriptor.of(CRYPTO_RESULT, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
        ifOpen      = h(l, lib, "cryptolib_image_factor_open", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        hpkeKeygen  = h(l, lib, "cryptolib_hpke_keygen", FunctionDescriptor.of(CRYPTO_KEYPAIR));
        keypairFree = h(l, lib, "cryptolib_keypair_free", FunctionDescriptor.ofVoid(ADDRESS));
        hsSeal      = h(l, lib, "cryptolib_hpke_stego_seal", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
        hsOpen      = h(l, lib, "cryptolib_hpke_stego_open", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS));
        drbgNew     = h(l, lib, "cryptolib_drbg_instantiate", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS));
        drbgGen     = h(l, lib, "cryptolib_drbg_generate", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        drbgFree    = h(l, lib, "cryptolib_drbg_free", FunctionDescriptor.ofVoid(ADDRESS));
        fortNew     = h(l, lib, "cryptolib_fortuna_new", FunctionDescriptor.of(ADDRESS));
        fortAdd     = h(l, lib, "cryptolib_fortuna_add_entropy", FunctionDescriptor.ofVoid(ADDRESS, JAVA_BYTE, ADDRESS, JAVA_LONG));
        fortGen     = h(l, lib, "cryptolib_fortuna_generate", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG));
        fortReseed  = h(l, lib, "cryptolib_fortuna_reseed", FunctionDescriptor.ofVoid(ADDRESS));
        fortCount   = h(l, lib, "cryptolib_fortuna_reseed_count", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
        fortFree    = h(l, lib, "cryptolib_fortuna_free", FunctionDescriptor.ofVoid(ADDRESS));
        assessHealth= h(l, lib, "cryptolib_entropy_assess_file_health", FunctionDescriptor.of(CRYPTO_HEALTH, ADDRESS, JAVA_LONG));
    }

    static MethodHandle h(Linker l, SymbolLookup lib, String name, FunctionDescriptor fd) {
        return l.downcallHandle(lib.find(name).orElseThrow(() -> new RuntimeException("missing: " + name)), fd);
    }

    MemorySegment cstr(String s) { return arena.allocateFrom(s); }
    MemorySegment bytes(byte[] b) { return b.length == 0 ? MemorySegment.NULL : arena.allocateFrom(JAVA_BYTE, b); }

    byte[] consume(MemorySegment result) throws Throwable {
        MemorySegment data = result.get(ADDRESS, 0);
        long len = result.get(JAVA_LONG, ADDRESS.byteSize());
        if (data.equals(MemorySegment.NULL) || len == 0) {
            MemorySegment err = result.get(ADDRESS, CRYPTO_BUFFER.byteSize());
            if (!err.equals(MemorySegment.NULL)) strFree.invoke(err);
            return new byte[0];
        }
        byte[] out = data.reinterpret(len).toArray(JAVA_BYTE);
        bufferFree.invoke(result);
        return out;
    }

    boolean okResult(MemorySegment r) throws Throwable {
        int ok = r.get(JAVA_INT, 0);
        MemorySegment err = r.get(ADDRESS, 8);
        if (!err.equals(MemorySegment.NULL)) strFree.invoke(err);
        return ok != 0;
    }

    void noisePpm(Path p, int w, int h, int seed) throws Exception {
        try (FileOutputStream f = new FileOutputStream(p.toFile())) {
            f.write(("P6\n" + w + " " + h + "\n255\n").getBytes());
            byte[] body = new byte[w * h * 3];
            int s = seed == 0 ? 1 : seed;
            for (int i = 0; i < body.length; i++) { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; body[i] = (byte) s; }
            f.write(body);
        }
    }

    static boolean eq(byte[] a, byte[] b) { return java.util.Arrays.equals(a, b); }

    void run() throws Throwable {
        if ((int) init.invoke() != 0) throw new RuntimeException("init failed");
        Path dir = Files.createTempDirectory("cl_p4_java_");
        byte[] key = new byte[32]; java.util.Arrays.fill(key, (byte) 0x5a);
        MemorySegment keySeg = bytes(key);

        // 1. Keyed stego
        {
            Path cover = dir.resolve("c1.ppm"), out = dir.resolve("o1.ppm");
            noisePpm(cover, 256, 256, 0xC0FFEE);
            byte[] payload = "keyed stego via Java".getBytes();
            check(okResult((MemorySegment) embedKeyed.invoke(arena, cstr(cover.toString()), bytes(payload), (long) payload.length, cstr(out.toString()), keySeg, 32L)), "keyed embed");
            byte[] got = consume((MemorySegment) extractKeyed.invoke(arena, cstr(out.toString()), keySeg, 32L));
            check(eq(got, payload), "keyed stego round-trip");
            byte[] wrong = new byte[32]; java.util.Arrays.fill(wrong, (byte) 0x99);
            byte[] bad = consume((MemorySegment) extractKeyed.invoke(arena, cstr(out.toString()), bytes(wrong), 32L));
            check(bad.length == 0, "keyed stego wrong-key rejected");
        }

        // 2. Always-encrypt
        {
            Path cover = dir.resolve("c2.ppm"), out = dir.resolve("o2.ppm");
            noisePpm(cover, 256, 256, 0xBEEF);
            byte[] secret = "never in the clear".getBytes();
            check(okResult((MemorySegment) embedEnc.invoke(arena, cstr(cover.toString()), bytes(secret), (long) secret.length, cstr(out.toString()), keySeg, 32L)), "embed_encrypted");
            byte[] got = consume((MemorySegment) extractDec.invoke(arena, cstr(out.toString()), keySeg, 32L));
            check(eq(got, secret), "always-encrypt round-trip");
        }

        // 3. PhysicalSeal
        {
            Path km = dir.resolve("k3.ppm"), cover = dir.resolve("c3.ppm"), out = dir.resolve("o3.ppm");
            noisePpm(km, 64, 64, 0xABCDEF); noisePpm(cover, 256, 256, 0x123456);
            byte[] msg = "the photo is the key".getBytes(), aad = "java-ctx".getBytes();
            check(okResult((MemorySegment) physSeal.invoke(arena, cstr(km.toString()), bytes(msg), (long) msg.length, bytes(aad), (long) aad.length, cstr(cover.toString()), cstr(out.toString()))), "physical_seal");
            byte[] got = consume((MemorySegment) physOpen.invoke(arena, cstr(km.toString()), bytes(aad), (long) aad.length, cstr(out.toString())));
            check(eq(got, msg), "PhysicalSeal round-trip");
        }

        // 4. FEC single-flip
        {
            byte[] data = {(byte)0xDE,(byte)0xAD,(byte)0xBE,(byte)0xEF,0x00,(byte)0xFF};
            for (int scheme = 1; scheme <= 3; scheme++) {
                byte[] enc = consume((MemorySegment) fecEncode.invoke(arena, bytes(data), (long) data.length, scheme));
                enc[0] ^= 0x40;
                byte[] dec = consume((MemorySegment) fecDecode.invoke(arena, bytes(enc), (long) enc.length, scheme, (long) data.length));
                check(eq(dec, data), "FEC scheme " + scheme + " corrects a single flip");
            }
        }

        // 5. Analysis
        {
            Path cover = dir.resolve("a.ppm"), stego = dir.resolve("as.ppm");
            noisePpm(cover, 128, 128, 0x99);
            MemorySegment insp = (MemorySegment) inspect.invoke(arena, cstr(cover.toString()));
            boolean parses = insp.get(JAVA_INT, 0) != 0;
            boolean extMatch = insp.get(JAVA_INT, 8) != 0;
            long width = insp.get(JAVA_LONG, 16);
            MemorySegment idetail = insp.get(ADDRESS, 40);
            if (!idetail.equals(MemorySegment.NULL)) strFree.invoke(idetail);
            check(parses && extMatch && width == 128, "inspect valid PPM");

            byte[] d1 = consume((MemorySegment) digest.invoke(arena, cstr(cover.toString())));
            Files.write(cover, new byte[]{0}, java.nio.file.StandardOpenOption.APPEND);
            byte[] d2 = consume((MemorySegment) digest.invoke(arena, cstr(cover.toString())));
            check(!eq(d1, d2), "content digest changes on tamper");

            noisePpm(cover, 128, 128, 0x99);
            byte[] hi = "hi".getBytes();
            okResult((MemorySegment) embed.invoke(arena, cstr(cover.toString()), bytes(hi), (long) hi.length, cstr(stego.toString())));
            MemorySegment rep = (MemorySegment) detect.invoke(arena, cstr(stego.toString()));
            boolean payload = rep.get(JAVA_INT, 0) != 0;
            MemorySegment note = rep.get(ADDRESS, 32);
            String noteStr = note.equals(MemorySegment.NULL) ? "" : note.reinterpret(Long.MAX_VALUE).getString(0);
            if (!note.equals(MemorySegment.NULL)) strFree.invoke(note);
            check(payload && !noteStr.isEmpty(), "detect unkeyed payload + honesty note");
        }

        // 6. ImageFactorSeal (C2)
        {
            Path img = dir.resolve("ref.ppm"), cover = dir.resolve("ifs_cover.ppm"), out = dir.resolve("ifs_out.ppm");
            noisePpm(img, 64, 64, 0xFEED); noisePpm(cover, 256, 256, 0xCAFE);
            byte[] seed = new byte[32]; java.util.Arrays.fill(seed, (byte) 0x42);
            byte[] msg = "image is the second factor".getBytes();
            check(okResult((MemorySegment) ifSeal.invoke(arena, bytes(seed), (long) seed.length, cstr(img.toString()), bytes(msg), (long) msg.length, MemorySegment.NULL, 0L, cstr(cover.toString()), cstr(out.toString()))), "image_factor_seal");
            byte[] got = consume((MemorySegment) ifOpen.invoke(arena, bytes(seed), (long) seed.length, cstr(img.toString()), MemorySegment.NULL, 0L, cstr(out.toString())));
            check(eq(got, msg), "ImageFactorSeal round-trip");
            Path other = dir.resolve("ref2.ppm"); noisePpm(other, 64, 64, 0xBEEF);
            byte[] bad = consume((MemorySegment) ifOpen.invoke(arena, bytes(seed), (long) seed.length, cstr(other.toString()), MemorySegment.NULL, 0L, cstr(out.toString())));
            check(bad.length == 0, "ImageFactorSeal wrong-image rejected");
        }

        // 7. HpkeStegoSeal (C3)
        {
            Path cover = dir.resolve("hss_cover.ppm"), out = dir.resolve("hss_out.ppm");
            noisePpm(cover, 256, 256, 0x4321);
            MemorySegment kp = (MemorySegment) hpkeKeygen.invoke(arena);
            long bufSz = CRYPTO_BUFFER.byteSize();
            byte[] pk = kp.get(ADDRESS, 0).reinterpret(kp.get(JAVA_LONG, ADDRESS.byteSize())).toArray(JAVA_BYTE);
            byte[] sk = kp.get(ADDRESS, bufSz).reinterpret(kp.get(JAVA_LONG, bufSz + ADDRESS.byteSize())).toArray(JAVA_BYTE);
            keypairFree.invoke(kp);
            byte[] info = "session".getBytes(), msg = "one session keys both".getBytes();
            byte[] enc = consume((MemorySegment) hsSeal.invoke(arena, bytes(pk), (long) pk.length, bytes(msg), (long) msg.length, MemorySegment.NULL, 0L, bytes(info), (long) info.length, cstr(cover.toString()), cstr(out.toString())));
            byte[] got = consume((MemorySegment) hsOpen.invoke(arena, bytes(sk), (long) sk.length, bytes(enc), (long) enc.length, MemorySegment.NULL, 0L, bytes(info), (long) info.length, cstr(out.toString())));
            check(eq(got, msg), "HpkeStegoSeal round-trip");
            MemorySegment kp2 = (MemorySegment) hpkeKeygen.invoke(arena);
            byte[] sk2 = kp2.get(ADDRESS, bufSz).reinterpret(kp2.get(JAVA_LONG, bufSz + ADDRESS.byteSize())).toArray(JAVA_BYTE);
            keypairFree.invoke(kp2);
            byte[] bad = consume((MemorySegment) hsOpen.invoke(arena, bytes(sk2), (long) sk2.length, bytes(enc), (long) enc.length, MemorySegment.NULL, 0L, bytes(info), (long) info.length, cstr(out.toString())));
            check(bad.length == 0, "HpkeStegoSeal wrong-recipient rejected");
        }

        // 8. HMAC-DRBG handle (A3)
        {
            byte[] seed = new byte[32]; java.util.Arrays.fill(seed, (byte) 0x01);
            byte[] perso = "beacon".getBytes();
            MemorySegment errBox = arena.allocate(ADDRESS);
            MemorySegment h1 = (MemorySegment) drbgNew.invoke(bytes(seed), (long) seed.length, MemorySegment.NULL, 0L, bytes(perso), (long) perso.length, errBox);
            byte[] a = consume((MemorySegment) drbgGen.invoke(arena, h1, 64L, MemorySegment.NULL, 0L));
            byte[] b = consume((MemorySegment) drbgGen.invoke(arena, h1, 64L, MemorySegment.NULL, 0L));
            check(!eq(a, b), "DRBG successive blocks differ");
            MemorySegment h2 = (MemorySegment) drbgNew.invoke(bytes(seed), (long) seed.length, MemorySegment.NULL, 0L, bytes(perso), (long) perso.length, errBox);
            check(eq(a, consume((MemorySegment) drbgGen.invoke(arena, h2, 64L, MemorySegment.NULL, 0L))), "DRBG reproducible from same seed");
            drbgFree.invoke(h1); drbgFree.invoke(h2);
            MemorySegment bad = (MemorySegment) drbgNew.invoke(bytes(new byte[]{1, 2, 3}), 3L, MemorySegment.NULL, 0L, MemorySegment.NULL, 0L, errBox);
            MemorySegment err = errBox.get(ADDRESS, 0);
            check(bad.equals(MemorySegment.NULL) && !err.equals(MemorySegment.NULL), "DRBG short-entropy rejected");
            if (!err.equals(MemorySegment.NULL)) strFree.invoke(err);
        }

        // 9. Fortuna handle (A5)
        {
            MemorySegment h = (MemorySegment) fortNew.invoke();
            check(consume((MemorySegment) fortGen.invoke(arena, h, 32L)).length == 0, "Fortuna unseeded generate rejected");
            for (int i = 0; i < 40; i++) {
                byte[] d = new byte[16]; java.util.Arrays.fill(d, (byte) i);
                fortAdd.invoke(h, (byte) (i & 7), bytes(d), (long) d.length);
            }
            fortReseed.invoke(h);
            check((long) fortCount.invoke(h) >= 1, "Fortuna reseed count advances");
            check(consume((MemorySegment) fortGen.invoke(arena, h, 64L)).length == 64, "Fortuna generate after seeding");
            fortFree.invoke(h);
        }

        // 10. assess_file_health (A1)
        {
            Path good = dir.resolve("good.ppm"); noisePpm(good, 128, 128, 0x1357);
            MemorySegment hr = (MemorySegment) assessHealth.invoke(arena, cstr(good.toString()), 0L);
            boolean healthy = hr.get(ADDRESS, CRYPTO_HEALTH.byteOffset(MemoryLayout.PathElement.groupElement("error"))).equals(MemorySegment.NULL)
                    && hr.get(JAVA_DOUBLE, 0) > 1.0
                    && hr.get(JAVA_INT, 24) != 0 && hr.get(JAVA_INT, 28) != 0;
            check(healthy, "assess_file_health: noise carrier healthy");
            Path flat = dir.resolve("flat.ppm");
            byte[] header = "P6\n64 64\n255\n".getBytes();
            byte[] body = new byte[header.length + 64 * 64 * 3];
            System.arraycopy(header, 0, body, 0, header.length);
            Files.write(flat, body);
            MemorySegment hf = (MemorySegment) assessHealth.invoke(arena, cstr(flat.toString()), 0L);
            boolean flatHealthy = hf.get(JAVA_DOUBLE, 0) >= 1.0 && hf.get(JAVA_INT, 24) != 0 && hf.get(JAVA_INT, 28) != 0;
            check(!flatHealthy, "assess_file_health: constant carrier flagged");
        }
    }

    public static void main(String[] args) throws Throwable {
        String path = args.length > 0 ? args[0] : "build/release/libcryptolib_c.dylib";
        new Phase4Verify(path).run();
        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        System.exit(failures == 0 ? 0 : 1);
    }
}
