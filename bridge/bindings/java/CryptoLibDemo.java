// CryptoLib Java demo using the Foreign Function & Memory API (JEP 454, final
// in Java 22). Pure Java — no JNI, no native glue to compile. The same approach
// works from Kotlin/JVM (Kotlin can call java.lang.foreign directly).
//
// Build/run (see Makefile target `java`):
//   javac CryptoLibDemo.java
//   java --enable-native-access=ALL-UNNAMED CryptoLibDemo <path-to-libcryptolib_c.dylib>

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;

import static java.lang.foreign.ValueLayout.*;

public final class CryptoLibDemo {

    // ── C struct layouts (all members 8-byte aligned → no padding) ────────────
    static final GroupLayout CRYPTO_BUFFER = MemoryLayout.structLayout(
            ADDRESS.withName("data"), JAVA_LONG.withName("len"));
    static final GroupLayout CRYPTO_BUFFER_RESULT = MemoryLayout.structLayout(
            CRYPTO_BUFFER.withName("buf"), ADDRESS.withName("error"));
    static final GroupLayout CRYPTO_PACKET = MemoryLayout.structLayout(
            CRYPTO_BUFFER.withName("ciphertext"),
            CRYPTO_BUFFER.withName("signature"),
            CRYPTO_BUFFER.withName("kdf_salt"));
    static final GroupLayout CRYPTO_KEYPAIR = MemoryLayout.structLayout(
            CRYPTO_BUFFER.withName("public_key"), CRYPTO_BUFFER.withName("secret_key"));

    final Arena arena = Arena.ofConfined();
    final MethodHandle init, version, randomBytes, sha256,
                       vaultCreate, vaultSeal, vaultOpen,
                       bufferFree, packetFree, vaultFree, strFree, keypairFree,
                       krCreate, krAddDev, krAddPw, krCount, krSer, krDeser,
                       krUnlockDev, krUnlockPw, krFree,
                       committingEnc, committingDec, hmac256, hmac256Verify,
                       hkdfExtract, hkdfExpand, hkdfDerive,
                       hybridSigKeygen, hybridSigSign, hybridSigVerify, blsKeygenFromIkm;

    CryptoLibDemo(String libPath) {
        Linker linker = Linker.nativeLinker();
        SymbolLookup lib = SymbolLookup.libraryLookup(Path.of(libPath), arena);
        init        = h(linker, lib, "cryptolib_init",        FunctionDescriptor.of(JAVA_INT));
        version     = h(linker, lib, "cryptolib_version",     FunctionDescriptor.of(ADDRESS));
        randomBytes = h(linker, lib, "cryptolib_random_bytes",FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, JAVA_LONG));
        sha256      = h(linker, lib, "cryptolib_sha256",      FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG));
        vaultCreate = h(linker, lib, "cryptolib_vault_create",FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT));
        vaultSeal   = h(linker, lib, "cryptolib_vault_seal",  FunctionDescriptor.of(CRYPTO_PACKET, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
        vaultOpen   = h(linker, lib, "cryptolib_vault_open",  FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, ADDRESS));
        bufferFree  = h(linker, lib, "cryptolib_buffer_free", FunctionDescriptor.ofVoid(ADDRESS));
        packetFree  = h(linker, lib, "cryptolib_packet_free", FunctionDescriptor.ofVoid(ADDRESS));
        vaultFree   = h(linker, lib, "cryptolib_vault_free",  FunctionDescriptor.ofVoid(ADDRESS));
        strFree     = h(linker, lib, "cryptolib_str_free",    FunctionDescriptor.ofVoid(ADDRESS));
        krCreate    = h(linker, lib, "cryptolib_keyring_create",   FunctionDescriptor.of(ADDRESS));
        krAddDev    = h(linker, lib, "cryptolib_keyring_add_device_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG));
        krAddPw     = h(linker, lib, "cryptolib_keyring_add_passphrase_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
        krCount     = h(linker, lib, "cryptolib_keyring_slot_count", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
        krSer       = h(linker, lib, "cryptolib_keyring_serialise", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS));
        krDeser     = h(linker, lib, "cryptolib_keyring_deserialise", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        krUnlockDev = h(linker, lib, "cryptolib_keyring_unlock_with_device", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, JAVA_LONG));
        krUnlockPw  = h(linker, lib, "cryptolib_keyring_unlock_with_passphrase", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS));
        krFree      = h(linker, lib, "cryptolib_keyring_free",     FunctionDescriptor.ofVoid(ADDRESS));
        keypairFree = h(linker, lib, "cryptolib_keypair_free",     FunctionDescriptor.ofVoid(ADDRESS));

        // Newly exposed feature functions.
        committingEnc = h(linker, lib, "cryptolib_committing_encrypt",
                FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        committingDec = h(linker, lib, "cryptolib_committing_decrypt",
                FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        hmac256       = h(linker, lib, "cryptolib_hmac_sha256",
                FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        hmac256Verify = h(linker, lib, "cryptolib_hmac_sha256_verify",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        hkdfExtract   = h(linker, lib, "cryptolib_hkdf_extract",
                FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        hkdfExpand    = h(linker, lib, "cryptolib_hkdf_expand",
                FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG));
        hkdfDerive    = h(linker, lib, "cryptolib_hkdf_derive",
                FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG));
        hybridSigKeygen = h(linker, lib, "cryptolib_hybrid_sig_keygen",
                FunctionDescriptor.of(CRYPTO_KEYPAIR));
        hybridSigSign = h(linker, lib, "cryptolib_hybrid_sig_sign",
                FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        hybridSigVerify = h(linker, lib, "cryptolib_hybrid_sig_verify",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        blsKeygenFromIkm = h(linker, lib, "cryptolib_bls_keygen_from_ikm",
                FunctionDescriptor.of(CRYPTO_KEYPAIR, ADDRESS, JAVA_LONG));
    }

    // Copy a returned CryptoKeyPair's public+secret bytes into Java, then free it.
    byte[][] consumeKeypair(MemorySegment kp) throws Throwable {
        long bufSz = CRYPTO_BUFFER.byteSize();
        MemorySegment pubData = kp.get(ADDRESS, 0);
        long pubLen = kp.get(JAVA_LONG, ADDRESS.byteSize());
        MemorySegment secData = kp.get(ADDRESS, bufSz);
        long secLen = kp.get(JAVA_LONG, bufSz + ADDRESS.byteSize());
        byte[] pub = pubData.equals(MemorySegment.NULL) ? new byte[0] : pubData.reinterpret(pubLen).toArray(JAVA_BYTE);
        byte[] sec = secData.equals(MemorySegment.NULL) ? new byte[0] : secData.reinterpret(secLen).toArray(JAVA_BYTE);
        keypairFree.invoke(kp);
        return new byte[][]{pub, sec};
    }

    static MethodHandle h(Linker l, SymbolLookup lib, String name, FunctionDescriptor fd) {
        return l.downcallHandle(lib.find(name).orElseThrow(
                () -> new RuntimeException("symbol not found: " + name)), fd);
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // Copy a returned CryptoBuffer's bytes into Java, then securely free it.
    // `result` is the CryptoBufferResult segment; its first 16 bytes are the buffer.
    byte[] consume(MemorySegment result) throws Throwable {
        MemorySegment data = result.get(ADDRESS, 0);
        long len = result.get(JAVA_LONG, ADDRESS.byteSize());
        if (data.equals(MemorySegment.NULL) || len == 0) {
            MemorySegment err = result.get(ADDRESS, CRYPTO_BUFFER.byteSize());
            if (!err.equals(MemorySegment.NULL)) {
                System.err.println("error: " + err.reinterpret(Long.MAX_VALUE).getString(0));
                strFree.invoke(err);
            }
            return new byte[0];
        }
        byte[] out = data.reinterpret(len).toArray(JAVA_BYTE);
        bufferFree.invoke(result); // first 16 bytes are the CryptoBuffer to free
        return out;
    }

    void run() throws Throwable {
        if ((int) init.invoke() != 0) throw new RuntimeException("init failed");
        MemorySegment ver = (MemorySegment) version.invoke();
        System.out.println("CryptoLib version: " + ver.reinterpret(Long.MAX_VALUE).getString(0));

        // random(32)
        byte[] rnd = consume((MemorySegment) randomBytes.invoke(arena, 32L));
        System.out.println("random(32):  " + hex(rnd));

        // sha256("abc")
        MemorySegment msg = arena.allocateFrom(JAVA_BYTE, "abc".getBytes());
        byte[] digest = consume((MemorySegment) sha256.invoke(arena, msg, 3L));
        System.out.println("sha256(abc): " + hex(digest));

        // vault seal/open
        MemorySegment key = arena.allocateFrom(JAVA_BYTE, consume((MemorySegment) randomBytes.invoke(arena, 32L)));
        MemorySegment vault = (MemorySegment) vaultCreate.invoke(key, key.byteSize(), 0);
        if (vault.equals(MemorySegment.NULL)) throw new RuntimeException("vault_create failed");

        byte[] pt = "hello from java".getBytes();
        MemorySegment ptSeg = arena.allocateFrom(JAVA_BYTE, pt);
        MemorySegment aad = arena.allocateFrom("ctx");
        MemorySegment errOut = arena.allocate(ADDRESS); // char**
        MemorySegment packet = (MemorySegment) vaultSeal.invoke(
                arena, vault, ptSeg, (long) pt.length, aad, errOut);
        MemorySegment sealErr = errOut.get(ADDRESS, 0);
        if (!sealErr.equals(MemorySegment.NULL))
            throw new RuntimeException("seal: " + sealErr.reinterpret(Long.MAX_VALUE).getString(0));

        byte[] opened = consume((MemorySegment) vaultOpen.invoke(arena, vault, packet, aad));
        System.out.println("vault roundtrip: \"" + new String(opened) + "\"");

        // Wrong AAD must fail.
        MemorySegment badAad = arena.allocateFrom("wrong");
        MemorySegment bad = (MemorySegment) vaultOpen.invoke(arena, vault, packet, badAad);
        if (!bad.get(ADDRESS, 0).equals(MemorySegment.NULL))
            throw new RuntimeException("wrong AAD should not decrypt");
        MemorySegment badErr = bad.get(ADDRESS, CRYPTO_BUFFER.byteSize());
        if (!badErr.equals(MemorySegment.NULL)) strFree.invoke(badErr);

        packetFree.invoke(packet);
        vaultFree.invoke(vault);

        // Keyring: default device slot + opt-in passphrase slot → cross-device.
        byte[] factor = consume((MemorySegment) randomBytes.invoke(arena, 32L));
        MemorySegment factorSeg = arena.allocateFrom(JAVA_BYTE, factor);
        MemorySegment kr = (MemorySegment) krCreate.invoke();
        krAddDev.invoke(kr, factorSeg, (long) factor.length);
        krAddPw.invoke(kr, arena.allocateFrom("cross-device pass"), 0);
        byte[] blob = consume((MemorySegment) krSer.invoke(arena, kr));
        MemorySegment blobSeg = arena.allocateFrom(JAVA_BYTE, blob);
        MemorySegment krErr = arena.allocate(ADDRESS);
        MemorySegment kr2 = (MemorySegment) krDeser.invoke(blobSeg, (long) blob.length, krErr);
        byte[] mDev  = consume((MemorySegment) krUnlockDev.invoke(arena, kr2, factorSeg, (long) factor.length));
        byte[] mPass = consume((MemorySegment) krUnlockPw.invoke(arena, kr2, arena.allocateFrom("cross-device pass")));
        System.out.println("keyring slots: " + (long) krCount.invoke(kr)
                + " · device==passphrase master: " + java.util.Arrays.equals(mDev, mPass));
        krFree.invoke(kr);
        krFree.invoke(kr2);

        // ── Newly exposed feature functions ──
        // Committing AEAD (UtC): ciphertext binds the key; wrong key must fail.
        byte[] caKey = consume((MemorySegment) randomBytes.invoke(arena, 32L));
        MemorySegment caKeySeg = arena.allocateFrom(JAVA_BYTE, caKey);
        byte[] caPt = "commit me".getBytes();
        MemorySegment caPtSeg = arena.allocateFrom(JAVA_BYTE, caPt);
        byte[] caAad = "ctx".getBytes();
        MemorySegment caAadSeg = arena.allocateFrom(JAVA_BYTE, caAad);
        byte[] caCt = consume((MemorySegment) committingEnc.invoke(arena,
                caPtSeg, (long) caPt.length, caKeySeg, (long) caKey.length, caAadSeg, (long) caAad.length));
        MemorySegment caCtSeg = arena.allocateFrom(JAVA_BYTE, caCt);
        byte[] caDec = consume((MemorySegment) committingDec.invoke(arena,
                caCtSeg, (long) caCt.length, caKeySeg, (long) caKey.length, caAadSeg, (long) caAad.length));
        byte[] wrongKey = consume((MemorySegment) randomBytes.invoke(arena, 32L));
        MemorySegment wrongKeySeg = arena.allocateFrom(JAVA_BYTE, wrongKey);
        MemorySegment caBad = (MemorySegment) committingDec.invoke(arena,
                caCtSeg, (long) caCt.length, wrongKeySeg, (long) wrongKey.length, caAadSeg, (long) caAad.length);
        boolean caReject = caBad.get(ADDRESS, 0).equals(MemorySegment.NULL);
        MemorySegment caBadErr = caBad.get(ADDRESS, CRYPTO_BUFFER.byteSize());
        if (!caBadErr.equals(MemorySegment.NULL)) strFree.invoke(caBadErr);
        System.out.println("committing AEAD: roundtrip=\"" + new String(caDec) + "\" reject-wrong-key=" + caReject);

        // HKDF-SHA256 + HMAC-SHA256.
        byte[] ikm = consume((MemorySegment) randomBytes.invoke(arena, 32L));
        MemorySegment ikmSeg = arena.allocateFrom(JAVA_BYTE, ikm);
        byte[] saltB = "salt".getBytes(), infoB = "app".getBytes();
        MemorySegment saltSeg = arena.allocateFrom(JAVA_BYTE, saltB);
        MemorySegment infoSeg = arena.allocateFrom(JAVA_BYTE, infoB);
        byte[] prk = consume((MemorySegment) hkdfExtract.invoke(arena, saltSeg, (long) saltB.length, ikmSeg, (long) ikm.length));
        MemorySegment prkSeg = arena.allocateFrom(JAVA_BYTE, prk);
        byte[] okm = consume((MemorySegment) hkdfExpand.invoke(arena, prkSeg, (long) prk.length, infoSeg, (long) infoB.length, 42L));
        byte[] okm1 = consume((MemorySegment) hkdfDerive.invoke(arena, ikmSeg, (long) ikm.length, saltSeg, (long) saltB.length, infoSeg, (long) infoB.length, 42L));
        byte[] macMsg = "mac me".getBytes();
        MemorySegment macMsgSeg = arena.allocateFrom(JAVA_BYTE, macMsg);
        byte[] mac256b = consume((MemorySegment) hmac256.invoke(arena, macMsgSeg, (long) macMsg.length, ikmSeg, (long) ikm.length));
        MemorySegment macSeg = arena.allocateFrom(JAVA_BYTE, mac256b);
        boolean macOk = (int) hmac256Verify.invoke(macMsgSeg, (long) macMsg.length, macSeg, (long) mac256b.length, ikmSeg, (long) ikm.length) == 1;
        System.out.println("hkdf len=" + okm.length + " consistent=" + java.util.Arrays.equals(okm, okm1) + " · hmac256 verify=" + macOk);

        // Hybrid signature (Ed25519 + ML-DSA-65).
        byte[][] hkp = consumeKeypair((MemorySegment) hybridSigKeygen.invoke(arena));
        MemorySegment hPubSeg = arena.allocateFrom(JAVA_BYTE, hkp[0]);
        MemorySegment hSecSeg = arena.allocateFrom(JAVA_BYTE, hkp[1]);
        byte[] sMsg = "sign me".getBytes();
        MemorySegment sMsgSeg = arena.allocateFrom(JAVA_BYTE, sMsg);
        byte[] hsig = consume((MemorySegment) hybridSigSign.invoke(arena, sMsgSeg, (long) sMsg.length, hSecSeg, (long) hkp[1].length));
        MemorySegment hsigSeg = arena.allocateFrom(JAVA_BYTE, hsig);
        boolean hsigOk = (int) hybridSigVerify.invoke(sMsgSeg, (long) sMsg.length, hsigSeg, (long) hsig.length, hPubSeg, (long) hkp[0].length) == 1;
        System.out.println("hybrid sig: len=" + hsig.length + " verify=" + hsigOk);

        // BLS deterministic keygen from IKM.
        byte[] blsIkm = consume((MemorySegment) randomBytes.invoke(arena, 32L));
        MemorySegment blsIkmSeg = arena.allocateFrom(JAVA_BYTE, blsIkm);
        byte[][] d1 = consumeKeypair((MemorySegment) blsKeygenFromIkm.invoke(arena, blsIkmSeg, (long) blsIkm.length));
        byte[][] d2 = consumeKeypair((MemorySegment) blsKeygenFromIkm.invoke(arena, blsIkmSeg, (long) blsIkm.length));
        System.out.println("bls keygen-from-ikm deterministic: " + java.util.Arrays.equals(d1[0], d2[0]));

        System.out.println("Java demo OK");
    }

    public static void main(String[] args) throws Throwable {
        String lib = args.length > 0 ? args[0] : "build/release/libcryptolib_c.dylib";
        new CryptoLibDemo(lib).run();
    }
}
