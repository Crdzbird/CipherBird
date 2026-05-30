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
    static final long B = BUF.byteSize();

    private final MethodHandle init, version, random, sha256, hyKg, hyEn, hyDe, bufFree, kpFree, kemFree, strFree;

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
    }

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
