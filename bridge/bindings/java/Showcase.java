// CryptoLib Java — FULL showcase of every capability family via the FFM API.
//   javac Showcase.java && java --enable-native-access=ALL-UNNAMED Showcase <dylib>

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;
import java.util.Arrays;

import static java.lang.foreign.ValueLayout.*;

public final class Showcase {
    static final GroupLayout BUF  = MemoryLayout.structLayout(ADDRESS.withName("data"), JAVA_LONG.withName("len"));
    static final GroupLayout RES  = MemoryLayout.structLayout(BUF.withName("buf"), ADDRESS.withName("error"));
    static final GroupLayout KP   = MemoryLayout.structLayout(BUF.withName("pub"), BUF.withName("sec"));
    static final GroupLayout PKT  = MemoryLayout.structLayout(BUF.withName("ct"), BUF.withName("sig"), BUF.withName("salt"));
    static final GroupLayout BUND = MemoryLayout.structLayout(BUF.withName("bp"), BUF.withName("bs"), BUF.withName("sp"), BUF.withName("ss"));
    static final GroupLayout KEM  = MemoryLayout.structLayout(BUF.withName("ct"), BUF.withName("ss"));
    static final long B = BUF.byteSize(); // 16

    final Arena a = Arena.ofConfined();
    final Linker linker = Linker.nativeLinker();
    final SymbolLookup lib;
    Showcase(String p) { lib = SymbolLookup.libraryLookup(Path.of(p), a); }
    MethodHandle h(String n, FunctionDescriptor fd) {
        return linker.downcallHandle(lib.find(n).orElseThrow(() -> new RuntimeException("missing " + n)), fd);
    }
    MemorySegment seg(byte[] b) { return a.allocateFrom(JAVA_BYTE, b); }
    MemorySegment str(String s) { return a.allocateFrom(s); }
    byte[] readBuf(MemorySegment s, long off) {
        MemorySegment d = s.get(ADDRESS, off); long n = s.get(JAVA_LONG, off + ADDRESS.byteSize());
        return d.equals(MemorySegment.NULL) ? new byte[0] : d.reinterpret(n).toArray(JAVA_BYTE);
    }
    int pass = 0, fail = 0;
    void ck(String l, boolean ok) { System.out.println("  " + (ok ? "✓" : "✗") + " " + l); if (ok) pass++; else fail++; }
    static String hx(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }

    void run() throws Throwable {
        var init = h("cryptolib_init", FunctionDescriptor.of(JAVA_INT));
        var version = h("cryptolib_version", FunctionDescriptor.of(ADDRESS));
        var random = h("cryptolib_random_bytes", FunctionDescriptor.of(RES, JAVA_LONG));
        var sha256 = h("cryptolib_sha256", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG));
        var sha512 = h("cryptolib_sha512", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG));
        var blake2b = h("cryptolib_blake2b", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var blake3 = h("cryptolib_blake3", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, JAVA_LONG));
        var hmac256 = h("cryptolib_hmac_sha256", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var hmac256v = h("cryptolib_hmac_sha256_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var hkdf = h("cryptolib_hkdf_derive", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG));
        var argonH = h("cryptolib_argon2id_hash_str", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, JAVA_LONG));
        var argonV = h("cryptolib_argon2id_verify_str", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        var symKey = h("cryptolib_sym_keygen", FunctionDescriptor.of(RES));
        var xEnc = h("cryptolib_xchacha20_encrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var xDec = h("cryptolib_xchacha20_decrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var aesAvail = h("cryptolib_aes256gcm_available", FunctionDescriptor.of(JAVA_INT));
        var aesEnc = h("cryptolib_aes256gcm_encrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var aesDec = h("cryptolib_aes256gcm_decrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var edKg = h("cryptolib_ed25519_keygen", FunctionDescriptor.of(KP));
        var edSign = h("cryptolib_ed25519_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var edVer = h("cryptolib_ed25519_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var xKg = h("cryptolib_x25519_keygen", FunctionDescriptor.of(KP));
        var xSh = h("cryptolib_x25519_shared_secret", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var boxKg = h("cryptolib_box_keygen", FunctionDescriptor.of(KP));
        var boxEnc = h("cryptolib_box_encrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var boxDec = h("cryptolib_box_decrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var sealEnc = h("cryptolib_sealedbox_encrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var sealDec = h("cryptolib_sealedbox_decrypt", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var vCreate = h("cryptolib_vault_create", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT));
        var vSeal = h("cryptolib_vault_seal", FunctionDescriptor.of(PKT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
        var vOpen = h("cryptolib_vault_open", FunctionDescriptor.of(RES, ADDRESS, ADDRESS, ADDRESS));
        var vFree = h("cryptolib_vault_free", FunctionDescriptor.ofVoid(ADDRESS));
        var bundleGen = h("cryptolib_asym_bundle_generate", FunctionDescriptor.of(BUND));
        var avSeal = h("cryptolib_asym_vault_seal", FunctionDescriptor.of(PKT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
        var avOpen = h("cryptolib_asym_vault_open", FunctionDescriptor.of(RES, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        var kemKg = h("cryptolib_ml_kem_keygen", FunctionDescriptor.of(KP, JAVA_INT));
        var kemEn = h("cryptolib_ml_kem_encapsulate", FunctionDescriptor.of(KEM, ADDRESS, JAVA_LONG, JAVA_INT, ADDRESS));
        var kemDe = h("cryptolib_ml_kem_decapsulate", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT));
        var hyKg = h("cryptolib_hybrid_kem_keygen", FunctionDescriptor.of(KP));
        var hyEn = h("cryptolib_hybrid_kem_encapsulate", FunctionDescriptor.of(KEM, ADDRESS, JAVA_LONG, ADDRESS));
        var hyDe = h("cryptolib_hybrid_kem_decapsulate", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var dsaKg = h("cryptolib_ml_dsa_keygen", FunctionDescriptor.of(KP, JAVA_INT));
        var dsaSign = h("cryptolib_ml_dsa_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT));
        var dsaVer = h("cryptolib_ml_dsa_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT));
        var slhKg = h("cryptolib_slh_dsa_keygen", FunctionDescriptor.of(KP, JAVA_INT, JAVA_INT));
        var slhSign = h("cryptolib_slh_dsa_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT));
        var slhVer = h("cryptolib_slh_dsa_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT));
        var blsKg = h("cryptolib_bls_keygen", FunctionDescriptor.of(KP));
        var blsSign = h("cryptolib_bls_sign", FunctionDescriptor.of(RES, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var blsVer = h("cryptolib_bls_verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        var krCreate = h("cryptolib_keyring_create", FunctionDescriptor.of(ADDRESS));
        var krAddDev = h("cryptolib_keyring_add_device_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG));
        var krAddPw = h("cryptolib_keyring_add_passphrase_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
        var krCount = h("cryptolib_keyring_slot_count", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
        var krSer = h("cryptolib_keyring_serialise", FunctionDescriptor.of(RES, ADDRESS));
        var krDeser = h("cryptolib_keyring_deserialise", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        var krUnDev = h("cryptolib_keyring_unlock_with_device", FunctionDescriptor.of(RES, ADDRESS, ADDRESS, JAVA_LONG));
        var krUnPw = h("cryptolib_keyring_unlock_with_passphrase", FunctionDescriptor.of(RES, ADDRESS, ADDRESS));
        var krFree = h("cryptolib_keyring_free", FunctionDescriptor.ofVoid(ADDRESS));
        var bufFree = h("cryptolib_buffer_free", FunctionDescriptor.ofVoid(ADDRESS));
        var pktFree = h("cryptolib_packet_free", FunctionDescriptor.ofVoid(ADDRESS));
        var kpFree = h("cryptolib_keypair_free", FunctionDescriptor.ofVoid(ADDRESS));
        var bundleFree = h("cryptolib_bundle_free", FunctionDescriptor.ofVoid(ADDRESS));
        var kemFree = h("cryptolib_kem_encaps_free", FunctionDescriptor.ofVoid(ADDRESS));

        // helpers needing handles
        java.util.function.Function<MemorySegment, byte[]> consume = (res) -> {
            byte[] out = readBuf(res, 0);
            try { bufFree.invoke(res); } catch (Throwable t) { throw new RuntimeException(t); }
            return out;
        };

        if ((int) init.invoke() != 0) throw new RuntimeException("init");
        String ver = ((MemorySegment) version.invoke()).reinterpret(Long.MAX_VALUE).getString(0);
        System.out.println("CryptoLib " + ver + " — Java full showcase\n");
        byte[] abc = "abc".getBytes(), msg = "secret payload".getBytes();
        MemorySegment ABC = seg(abc), MSG = seg(msg);

        System.out.println("HASHING");
        ck("SHA-256(abc) KAT", hx(consume.apply((MemorySegment) sha256.invoke(a, ABC, 3L)))
            .equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        ck("SHA-512", consume.apply((MemorySegment) sha512.invoke(a, ABC, 3L)).length == 64);
        ck("BLAKE2b", consume.apply((MemorySegment) blake2b.invoke(a, ABC, 3L, MemorySegment.NULL, 0L)).length == 64);
        ck("BLAKE3", consume.apply((MemorySegment) blake3.invoke(a, ABC, 3L, 32L)).length == 32);
        byte[] hk = consume.apply((MemorySegment) symKey.invoke(a)); MemorySegment HK = seg(hk);
        byte[] mac = consume.apply((MemorySegment) hmac256.invoke(a, ABC, 3L, HK, (long) hk.length));
        ck("HMAC-SHA256 verify", (int) hmac256v.invoke(ABC, 3L, seg(mac), (long) mac.length, HK, (long) hk.length) == 1);
        ck("HKDF derive", consume.apply((MemorySegment) hkdf.invoke(a, HK, (long) hk.length, MemorySegment.NULL, 0L, MemorySegment.NULL, 0L, 32L)).length == 32);
        byte[] phc = consume.apply((MemorySegment) argonH.invoke(a, str("hunter2"), 2L, 67108864L));
        String phcStr = new String(phc).trim();
        ck("Argon2id PHC verify", (int) argonV.invoke(str("hunter2"), str(phcStr)) == 1);

        System.out.println("\nSYMMETRIC");
        byte[] sk = consume.apply((MemorySegment) symKey.invoke(a)); MemorySegment SK = seg(sk);
        byte[] xct = consume.apply((MemorySegment) xEnc.invoke(a, MSG, (long) msg.length, SK, (long) sk.length, MemorySegment.NULL, 0L));
        byte[] xpt = consume.apply((MemorySegment) xDec.invoke(a, seg(xct), (long) xct.length, SK, (long) sk.length, MemorySegment.NULL, 0L));
        ck("XChaCha20 round-trip", Arrays.equals(xpt, msg));
        if ((int) aesAvail.invoke() == 1) {
            byte[] act = consume.apply((MemorySegment) aesEnc.invoke(a, MSG, (long) msg.length, SK, (long) sk.length, MemorySegment.NULL, 0L));
            byte[] apt = consume.apply((MemorySegment) aesDec.invoke(a, seg(act), (long) act.length, SK, (long) sk.length, MemorySegment.NULL, 0L));
            ck("AES-256-GCM round-trip", Arrays.equals(apt, msg));
        } else System.out.println("    AES-256-GCM unavailable");

        System.out.println("\nASYMMETRIC");
        MemorySegment ed = (MemorySegment) edKg.invoke(a);
        byte[] edPub = readBuf(ed, 0), edSec = readBuf(ed, B); kpFree.invoke(ed);
        byte[] sig = consume.apply((MemorySegment) edSign.invoke(a, ABC, 3L, seg(edSec), (long) edSec.length));
        ck("Ed25519 sign/verify", (int) edVer.invoke(ABC, 3L, seg(sig), (long) sig.length, seg(edPub), (long) edPub.length) == 1);
        MemorySegment xaK = (MemorySegment) xKg.invoke(a); byte[] xaPub = readBuf(xaK, 0), xaSec = readBuf(xaK, B); kpFree.invoke(xaK);
        MemorySegment xbK = (MemorySegment) xKg.invoke(a); byte[] xbPub = readBuf(xbK, 0), xbSec = readBuf(xbK, B); kpFree.invoke(xbK);
        byte[] s1 = consume.apply((MemorySegment) xSh.invoke(a, seg(xaSec), (long) xaSec.length, seg(xbPub), (long) xbPub.length));
        byte[] s2 = consume.apply((MemorySegment) xSh.invoke(a, seg(xbSec), (long) xbSec.length, seg(xaPub), (long) xaPub.length));
        ck("X25519 ECDH", Arrays.equals(s1, s2));
        MemorySegment rK = (MemorySegment) boxKg.invoke(a); byte[] rPub = readBuf(rK, 0), rSec = readBuf(rK, B); kpFree.invoke(rK);
        MemorySegment sK = (MemorySegment) boxKg.invoke(a); byte[] sPub = readBuf(sK, 0), sSec = readBuf(sK, B); kpFree.invoke(sK);
        byte[] bct = consume.apply((MemorySegment) boxEnc.invoke(a, MSG, (long) msg.length, seg(rPub), (long) rPub.length, seg(sSec), (long) sSec.length));
        byte[] bpt = consume.apply((MemorySegment) boxDec.invoke(a, seg(bct), (long) bct.length, seg(sPub), (long) sPub.length, seg(rSec), (long) rSec.length));
        ck("Box round-trip", Arrays.equals(bpt, msg));
        byte[] sct = consume.apply((MemorySegment) sealEnc.invoke(a, MSG, (long) msg.length, seg(rPub), (long) rPub.length));
        byte[] spt = consume.apply((MemorySegment) sealDec.invoke(a, seg(sct), (long) sct.length, seg(rPub), (long) rPub.length, seg(rSec), (long) rSec.length));
        ck("SealedBox round-trip", Arrays.equals(spt, msg));

        System.out.println("\nVAULTS");
        byte[] vk = consume.apply((MemorySegment) random.invoke(a, 32L));
        MemorySegment vault = (MemorySegment) vCreate.invoke(seg(vk), (long) vk.length, 0);
        MemorySegment e1 = a.allocate(ADDRESS);
        MemorySegment pkt = (MemorySegment) vSeal.invoke(a, vault, MSG, (long) msg.length, str("ctx"), e1);
        ck("SecureVault round-trip", Arrays.equals(consume.apply((MemorySegment) vOpen.invoke(a, vault, pkt, str("ctx"))), msg));
        pktFree.invoke(pkt); vFree.invoke(vault);
        MemorySegment alice = (MemorySegment) bundleGen.invoke(a);
        MemorySegment bob = (MemorySegment) bundleGen.invoke(a);
        byte[] bobBoxPub = readBuf(bob, 0), aliceSignPub = readBuf(alice, 2 * B);
        MemorySegment e2 = a.allocate(ADDRESS);
        MemorySegment apkt = (MemorySegment) avSeal.invoke(a, alice, seg(bobBoxPub), (long) bobBoxPub.length, MSG, (long) msg.length, str("ctx"), e2);
        ck("AsymmetricVault round-trip", Arrays.equals(consume.apply((MemorySegment) avOpen.invoke(a, apkt, bob, seg(aliceSignPub), (long) aliceSignPub.length, str("ctx"))), msg));
        pktFree.invoke(apkt); bundleFree.invoke(alice); bundleFree.invoke(bob);

        System.out.println("\nPOST-QUANTUM");
        MemorySegment kemK = (MemorySegment) kemKg.invoke(a, 1); byte[] kemPub = readBuf(kemK, 0), kemSec = readBuf(kemK, B); kpFree.invoke(kemK);
        MemorySegment e3 = a.allocate(ADDRESS);
        MemorySegment enc = (MemorySegment) kemEn.invoke(a, seg(kemPub), (long) kemPub.length, 1, e3);
        byte[] ssE = readBuf(enc, 0 + B), kemCt = readBuf(enc, 0); // KEM struct: ciphertext@0, shared_secret@B
        byte[] ssD = consume.apply((MemorySegment) kemDe.invoke(a, seg(kemCt), (long) kemCt.length, seg(kemSec), (long) kemSec.length, 1));
        ck("ML-KEM-768 encaps/decaps", Arrays.equals(ssE, ssD) && ssE.length == 32);
        kemFree.invoke(enc);
        MemorySegment hKemK = (MemorySegment) hyKg.invoke(a); byte[] hPub = readBuf(hKemK, 0), hSec = readBuf(hKemK, B); kpFree.invoke(hKemK);
        MemorySegment eH = a.allocate(ADDRESS);
        MemorySegment hEnc = (MemorySegment) hyEn.invoke(a, seg(hPub), (long) hPub.length, eH);
        byte[] hSsE = readBuf(hEnc, 0 + B), hCt = readBuf(hEnc, 0);
        byte[] hSsD = consume.apply((MemorySegment) hyDe.invoke(a, seg(hCt), (long) hCt.length, seg(hSec), (long) hSec.length));
        ck("Hybrid X25519+ML-KEM-768 encaps/decaps", Arrays.equals(hSsE, hSsD) && hSsE.length == 32);
        kemFree.invoke(hEnc);
        MemorySegment dsaK = (MemorySegment) dsaKg.invoke(a, 1); byte[] dPub = readBuf(dsaK, 0), dSec = readBuf(dsaK, B); kpFree.invoke(dsaK);
        byte[] dsig = consume.apply((MemorySegment) dsaSign.invoke(a, ABC, 3L, seg(dSec), (long) dSec.length, 1));
        ck("ML-DSA-65 sign/verify", (int) dsaVer.invoke(ABC, 3L, seg(dsig), (long) dsig.length, seg(dPub), (long) dPub.length, 1) == 1);
        MemorySegment slhK = (MemorySegment) slhKg.invoke(a, 1, 0); byte[] slPub = readBuf(slhK, 0), slSec = readBuf(slhK, B); kpFree.invoke(slhK);
        byte[] ssig = consume.apply((MemorySegment) slhSign.invoke(a, ABC, 3L, seg(slSec), (long) slSec.length, 1, 0));
        ck("SLH-DSA-128f sign/verify", (int) slhVer.invoke(ABC, 3L, seg(ssig), (long) ssig.length, seg(slPub), (long) slPub.length, 1, 0) == 1);

        System.out.println("\nBLS12-381");
        MemorySegment blsK = (MemorySegment) blsKg.invoke(a); byte[] blsPub = readBuf(blsK, 0), blsSec = readBuf(blsK, B); kpFree.invoke(blsK);
        byte[] bsig = consume.apply((MemorySegment) blsSign.invoke(a, ABC, 3L, seg(blsSec), (long) blsSec.length));
        ck("BLS sign/verify", (int) blsVer.invoke(ABC, 3L, seg(bsig), (long) bsig.length, seg(blsPub), (long) blsPub.length) == 1);

        System.out.println("\nKEYRING");
        byte[] factor = consume.apply((MemorySegment) random.invoke(a, 32L)); MemorySegment FACTOR = seg(factor);
        MemorySegment kr = (MemorySegment) krCreate.invoke();
        krAddDev.invoke(kr, FACTOR, (long) factor.length);
        krAddPw.invoke(kr, str("cross-device pass"), 0);
        byte[] blob = consume.apply((MemorySegment) krSer.invoke(a, kr));
        MemorySegment e4 = a.allocate(ADDRESS);
        MemorySegment kr2 = (MemorySegment) krDeser.invoke(seg(blob), (long) blob.length, e4);
        byte[] mDev = consume.apply((MemorySegment) krUnDev.invoke(a, kr2, FACTOR, (long) factor.length));
        byte[] mPass = consume.apply((MemorySegment) krUnPw.invoke(a, kr2, str("cross-device pass")));
        ck("Keyring device==passphrase master (" + (long) krCount.invoke(kr) + " slots)", Arrays.equals(mDev, mPass) && mDev.length == 32);
        krFree.invoke(kr); krFree.invoke(kr2);

        System.out.println("\nJava showcase " + (fail == 0 ? "OK" : "FAILED") + " (" + pass + " passed, " + fail + " failed)");
        if (fail != 0) System.exit(1);
    }

    public static void main(String[] args) throws Throwable {
        new Showcase(args.length > 0 ? args[0] : "build/release/libcryptolib_c.dylib").run();
    }
}
