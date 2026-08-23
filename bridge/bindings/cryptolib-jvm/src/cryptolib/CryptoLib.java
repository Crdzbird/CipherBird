package cryptolib;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import static java.lang.foreign.ValueLayout.*;

/**
 * CryptoLib JVM binding (Java FFM / Panama). The native library is loaded
 * automatically from the bundled resource via {@link NativeLoader}; no path
 * needed. Exposes a focused surface (hashing, symmetric, hybrid post-quantum
 * KEM); the full C ABI can be bound the same way.
 */
public final class CryptoLib implements AutoCloseable {
    private final Arena arena = Arena.ofConfined();
    private final Linker linker = Linker.nativeLinker();
    private final SymbolLookup lib;

    static final GroupLayout BUF = MemoryLayout.structLayout(ADDRESS.withName("data"), JAVA_LONG.withName("len"));
    static final GroupLayout RES = MemoryLayout.structLayout(BUF.withName("buf"), ADDRESS.withName("error"));
    static final GroupLayout KP  = MemoryLayout.structLayout(BUF.withName("pub"), BUF.withName("sec"));
    static final GroupLayout KEM = MemoryLayout.structLayout(BUF.withName("ct"), BUF.withName("ss"));
    /** CryptoResult { int ok; char* error; } — the int needs explicit padding before the pointer. */
    static final GroupLayout CRES = MemoryLayout.structLayout(
            JAVA_INT.withName("ok"), MemoryLayout.paddingLayout(4), ADDRESS.withName("error"));
    static final long B = BUF.byteSize();

    private final MethodHandle init, version, random, sha256, hyKg, hyEn, hyDe, bufFree, kpFree, kemFree, strFree;
    // Primitives the composable Recipe pipeline is built from.
    private final MethodHandle argon2idDerive, hkdfDerive,
            xEnc, xDec, aesEnc, aesDec, cmtEnc, cmtDec, molSeal, molOpen,
            edKg, edKgSeed, edSign, edVerify, hySigKg, hySigSign, hySigVerify,
            entFromFileDet, entSymKey, entFree, stegoEmbed, stegoExtract, fecEnc, fecDec;

    public CryptoLib() {
        lib = SymbolLookup.libraryLookup(NativeLoader.extract(), arena);
        init    = h("cryptolib_init", FunctionDescriptor.of(JAVA_INT));
        version = h("cryptolib_version", FunctionDescriptor.of(ADDRESS));
        random  = h("cryptolib_random_bytes", FunctionDescriptor.of(RES, JAVA_LONG));
        sha256  = h("cryptolib_sha256", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG));
        hyKg    = h("cryptolib_hybrid_kem_keygen", FunctionDescriptor.of(KP));
        hyEn    = h("cryptolib_hybrid_kem_encapsulate", FunctionDescriptor.of(KEM, ADDRESS, JAVA_LONG, ADDRESS));
        hyDe    = h("cryptolib_hybrid_kem_decapsulate", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        bufFree = h("cryptolib_buffer_free", FunctionDescriptor.ofVoid(ADDRESS));
        kpFree  = h("cryptolib_keypair_free", FunctionDescriptor.ofVoid(ADDRESS));
        kemFree = h("cryptolib_kem_encaps_free", FunctionDescriptor.ofVoid(ADDRESS));
        strFree = h("cryptolib_str_free", FunctionDescriptor.ofVoid(ADDRESS));

        argon2idDerive = h("cryptolib_argon2id_derive",
                FunctionDescriptor.of(RES, ADDRESS, ADDRESS, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG));
        hkdfDerive = h("cryptolib_hkdf_derive",
                FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG));
        FunctionDescriptor aead = FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG);
        xEnc = h("cryptolib_xchacha20_encrypt", aead);
        xDec = h("cryptolib_xchacha20_decrypt", aead);
        aesEnc = h("cryptolib_aes256gcm_encrypt", aead);
        aesDec = h("cryptolib_aes256gcm_decrypt", aead);
        cmtEnc = h("cryptolib_committing_encrypt", aead);
        cmtDec = h("cryptolib_committing_decrypt", aead);
        molSeal = h("cryptolib_molecular_seal_with_key", aead);
        molOpen = h("cryptolib_molecular_open_with_key", aead);
        edKg = h("cryptolib_ed25519_keygen", FunctionDescriptor.of(KP));
        edKgSeed = h("cryptolib_ed25519_keygen_from_seed", FunctionDescriptor.of(KP, ADDRESS, JAVA_LONG));
        edSign = h("cryptolib_ed25519_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        edVerify = h("cryptolib_ed25519_verify",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        hySigKg = h("cryptolib_hybrid_sig_keygen", FunctionDescriptor.of(KP));
        hySigSign = h("cryptolib_hybrid_sig_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        hySigVerify = h("cryptolib_hybrid_sig_verify",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        entFromFileDet = h("cryptolib_entropy_from_file_deterministic", FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS));
        entSymKey = h("cryptolib_entropy_symmetric_key", FunctionDescriptor.of(RES, ADDRESS));
        entFree = h("cryptolib_entropy_free", FunctionDescriptor.ofVoid(ADDRESS));
        stegoEmbed = h("cryptolib_stego_embed", FunctionDescriptor.of(CRES, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        stegoExtract = h("cryptolib_stego_extract", FunctionDescriptor.of(RES, ADDRESS));
        fecEnc = h("cryptolib_fec_encode", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, JAVA_INT));
        fecDec = h("cryptolib_fec_decode", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_LONG));
    }

    // ── Primitives used by Recipe ─────────────────────────────────────────────

    /** Stretch a passphrase into a key with Argon2id. */
    public byte[] argon2idDerive(String password, byte[] salt, int keyLen, long ops, long memoryBytes) {
        try {
            return consume((MemorySegment) argon2idDerive.invoke(arena, arena.allocateFrom(password),
                    seg(salt), (long) salt.length, (long) keyLen, ops, memoryBytes));
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    /** One-shot HKDF: extract + expand to {@code outLen} bytes. */
    public byte[] hkdfDerive(byte[] ikm, byte[] salt, byte[] info, int outLen) {
        try {
            return consume((MemorySegment) hkdfDerive.invoke(arena, seg(ikm), (long) ikm.length,
                    seg(salt), (long) salt.length, seg(info), (long) info.length, (long) outLen));
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    private byte[] aead(MethodHandle mh, byte[] data, byte[] key, byte[] aad) {
        try {
            return consume((MemorySegment) mh.invoke(arena, seg(data), (long) data.length,
                    seg(key), (long) key.length, seg(aad), (long) aad.length));
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public byte[] xchacha20Encrypt(byte[] pt, byte[] key, byte[] aad) { return aead(xEnc, pt, key, aad); }
    public byte[] xchacha20Decrypt(byte[] ct, byte[] key, byte[] aad) { return aead(xDec, ct, key, aad); }
    public byte[] aes256gcmEncrypt(byte[] pt, byte[] key, byte[] aad) { return aead(aesEnc, pt, key, aad); }
    public byte[] aes256gcmDecrypt(byte[] ct, byte[] key, byte[] aad) { return aead(aesDec, ct, key, aad); }
    public byte[] committingEncrypt(byte[] pt, byte[] key, byte[] aad) { return aead(cmtEnc, pt, key, aad); }
    public byte[] committingDecrypt(byte[] ct, byte[] key, byte[] aad) { return aead(cmtDec, ct, key, aad); }
    public byte[] molecularSealWithKey(byte[] pt, byte[] key, byte[] aad) { return aead(molSeal, pt, key, aad); }
    public byte[] molecularOpenWithKey(byte[] ct, byte[] key, byte[] aad) { return aead(molOpen, ct, key, aad); }

    private KeyPair keypair(MemorySegment kp) {
        try {
            byte[] pub = readBuf(kp, 0), sec = readBuf(kp, B);
            kpFree.invoke(kp);
            return new KeyPair(pub, sec);
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    /** Ed25519 keypair from the OS CSPRNG. */
    public KeyPair ed25519Keygen() {
        try { return keypair((MemorySegment) edKg.invoke(arena)); }
        catch (Throwable t) { throw new RuntimeException(t); }
    }

    /** Ed25519 keypair derived deterministically from a 32-byte seed. */
    public KeyPair ed25519KeygenFromSeed(byte[] seed) {
        try { return keypair((MemorySegment) edKgSeed.invoke(arena, seg(seed), (long) seed.length)); }
        catch (Throwable t) { throw new RuntimeException(t); }
    }

    public byte[] ed25519Sign(byte[] msg, byte[] secretKey) {
        try {
            return consume((MemorySegment) edSign.invoke(arena, seg(msg), (long) msg.length,
                    seg(secretKey), (long) secretKey.length));
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public boolean ed25519Verify(byte[] msg, byte[] sig, byte[] publicKey) {
        try {
            return (int) edVerify.invoke(seg(msg), (long) msg.length, seg(sig), (long) sig.length,
                    seg(publicKey), (long) publicKey.length) == 1;
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    /** Ed25519 + ML-DSA-65 keypair: a forgery needs breaking both families. */
    public KeyPair hybridSigKeygen() {
        try { return keypair((MemorySegment) hySigKg.invoke(arena)); }
        catch (Throwable t) { throw new RuntimeException(t); }
    }

    public byte[] hybridSigSign(byte[] msg, byte[] secretKey) {
        try {
            return consume((MemorySegment) hySigSign.invoke(arena, seg(msg), (long) msg.length,
                    seg(secretKey), (long) secretKey.length));
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public boolean hybridSigVerify(byte[] msg, byte[] sig, byte[] publicKey) {
        try {
            return (int) hySigVerify.invoke(seg(msg), (long) msg.length, seg(sig), (long) sig.length,
                    seg(publicKey), (long) publicKey.length) == 1;
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    /**
     * Derive a 32-byte key deterministically from a media file — "the file is the
     * key". Reproducible on any machine; nothing is stored.
     *
     * <p>Uses the deterministic entropy path deliberately: {@code key_from_file}
     * mixes in fresh system entropy and so could never reopen its own envelope.
     */
    public byte[] keyFromFileDeterministic(String path) {
        try {
            MemorySegment err = arena.allocate(ADDRESS);
            MemorySegment h = (MemorySegment) entFromFileDet.invoke(arena.allocateFrom(path), err);
            MemorySegment e = err.get(ADDRESS, 0);
            if (e.address() != 0) {
                String msg = e.reinterpret(Long.MAX_VALUE).getString(0);
                strFree.invoke(e);
                throw new RuntimeException(msg);
            }
            if (h.address() == 0) throw new RuntimeException("cryptolib: entropy handle allocation failed");
            try { return consume((MemorySegment) entSymKey.invoke(arena, h)); }
            finally { entFree.invoke(h); }
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    /** Hide {@code payload} inside a media carrier. */
    public void stegoEmbed(String coverPath, byte[] payload, String outputPath) {
        try {
            MemorySegment r = (MemorySegment) stegoEmbed.invoke(arena, arena.allocateFrom(coverPath),
                    seg(payload), (long) payload.length, arena.allocateFrom(outputPath));
            if (r.get(JAVA_INT, 0) != 1) {
                MemorySegment e = r.get(ADDRESS, CRES.byteOffset(MemoryLayout.PathElement.groupElement("error")));
                String msg = e.address() != 0 ? e.reinterpret(Long.MAX_VALUE).getString(0) : "stego embed failed";
                if (e.address() != 0) strFree.invoke(e);
                throw new RuntimeException(msg);
            }
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    /** Recover a payload hidden by {@link #stegoEmbed}. */
    public byte[] stegoExtract(String stegoPath) {
        try { return consume((MemorySegment) stegoExtract.invoke(arena, arena.allocateFrom(stegoPath))); }
        catch (Throwable t) { throw new RuntimeException(t); }
    }

    /** Forward-error-correct {@code data} under a scheme id (see {@link FecScheme}). */
    public byte[] fecEncode(byte[] data, int scheme) {
        try { return consume((MemorySegment) fecEnc.invoke(arena, seg(data), (long) data.length, scheme)); }
        catch (Throwable t) { throw new RuntimeException(t); }
    }

    /** Reverse {@link #fecEncode}, recovering {@code originalLength} bytes. */
    public byte[] fecDecode(byte[] data, int scheme, int originalLength) {
        try {
            return consume((MemorySegment) fecDec.invoke(arena, seg(data), (long) data.length,
                    scheme, (long) originalLength));
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    /** Start a {@link Recipe} at the given profile's settings. */
    public Recipe recipe(SecurityProfile profile) { return new Recipe(this, profile); }

    /** A {@link Recipe} using the strongest option at every choice. */
    public Recipe maximumSecurity() { return new Recipe(this, SecurityProfile.MAXIMUM); }

    private MethodHandle h(String name, FunctionDescriptor fd) {
        return linker.downcallHandle(lib.find(name).orElseThrow(() ->
                new IllegalStateException("symbol not found: " + name)), fd);
    }

    private MemorySegment seg(byte[] b) {
        MemorySegment s = arena.allocate(b.length == 0 ? 1 : b.length);
        MemorySegment.copy(b, 0, s, JAVA_BYTE, 0, b.length);
        return s;
    }

    // Read a CryptoBuffer (at struct offset off) into a byte[].
    private byte[] readBuf(MemorySegment structByVal, long off) {
        MemorySegment data = structByVal.get(ADDRESS, off);
        long len = structByVal.get(JAVA_LONG, off + ADDRESS.byteSize());
        if (data.address() == 0 || len == 0) return new byte[0];
        return data.reinterpret(len).toArray(JAVA_BYTE);
    }

    // Consume a CryptoBufferResult: throw on error, else copy + free the buffer.
    private byte[] consume(MemorySegment res) {
        byte[] out = readBuf(res, 0);
        MemorySegment err = res.get(ADDRESS, RES.byteOffset(MemoryLayout.PathElement.groupElement("error")));
        if (out.length == 0 && err.address() != 0) {
            String msg = err.reinterpret(Long.MAX_VALUE).getString(0);
            try { strFree.invoke(err); } catch (Throwable ignored) {}
            throw new RuntimeException(msg);
        }
        try {
            MemorySegment bufCopy = arena.allocate(BUF);
            MemorySegment.copy(res, 0, bufCopy, 0, B);
            bufFree.invoke(bufCopy);
        } catch (Throwable t) { throw new RuntimeException(t); }
        return out;
    }

    public void init() {
        try { if ((int) init.invoke() != 0) throw new RuntimeException("cryptolib init failed"); }
        catch (Throwable t) { throw new RuntimeException(t); }
    }

    public String version() {
        try { return ((MemorySegment) version.invoke()).reinterpret(Long.MAX_VALUE).getString(0); }
        catch (Throwable t) { throw new RuntimeException(t); }
    }

    public byte[] randomBytes(long n) {
        try { return consume((MemorySegment) random.invoke(arena, n)); }
        catch (Throwable t) { throw new RuntimeException(t); }
    }

    public byte[] sha256(byte[] msg) {
        try { return consume((MemorySegment) sha256.invoke(arena, seg(msg), (long) msg.length)); }
        catch (Throwable t) { throw new RuntimeException(t); }
    }

    public record KeyPair(byte[] publicKey, byte[] secretKey) {}
    public record Encaps(byte[] ciphertext, byte[] sharedSecret) {}

    public KeyPair hybridKemKeygen() {
        try {
            MemorySegment kp = (MemorySegment) hyKg.invoke(arena);
            byte[] pub = readBuf(kp, 0), sec = readBuf(kp, B);
            kpFree.invoke(kp);
            return new KeyPair(pub, sec);
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public Encaps hybridKemEncapsulate(byte[] publicKey) {
        try {
            MemorySegment err = arena.allocate(ADDRESS);
            MemorySegment r = (MemorySegment) hyEn.invoke(arena, seg(publicKey), (long) publicKey.length, err);
            byte[] ct = readBuf(r, 0), ss = readBuf(r, B);
            kemFree.invoke(r);
            return new Encaps(ct, ss);
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public byte[] hybridKemDecapsulate(byte[] ciphertext, byte[] secretKey) {
        try {
            return consume((MemorySegment) hyDe.invoke(arena, seg(ciphertext), (long) ciphertext.length,
                    seg(secretKey), (long) secretKey.length));
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    @Override public void close() { arena.close(); }
}
