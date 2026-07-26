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
    final MethodHandle init, strFree, bufferFree, embed,
            embedKeyed, extractKeyed, embedEnc, extractDec,
            physSeal, physOpen, fecEncode, fecDecode,
            inspect, digest, detect;

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
    }

    public static void main(String[] args) throws Throwable {
        String path = args.length > 0 ? args[0] : "build/release/libcryptolib_c.dylib";
        new Phase4Verify(path).run();
        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        System.exit(failures == 0 ? 0 : 1);
    }
}
