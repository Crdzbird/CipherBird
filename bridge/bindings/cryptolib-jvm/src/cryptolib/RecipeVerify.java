package cryptolib;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Verifies SecurityProfile + Recipe, and doubles as the Java end of the
 * cross-language interop harness.
 *
 *   java ... cryptolib.RecipeVerify                 # run the checks
 *   java ... cryptolib.RecipeVerify seal|open <dir> # interop mode
 */
public final class RecipeVerify {
    // Fixed inputs so every language derives identical keys.
    private static final String KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private static final String SK_HEX = "d463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6";
    private static final String PASSPHRASE = "interop passphrase";
    private static final String PLAINTEXT = "cross-language recipe envelope";

    private static int pass = 0, fail = 0;

    private static void ck(String label, boolean ok) {
        System.out.println((ok ? "  ok   " : " FAIL  ") + label);
        if (ok) pass++; else fail++;
    }

    private static boolean throwsErr(Runnable r) {
        try { r.run(); return false; } catch (Throwable t) { return true; }
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static byte[] noisePpm(int w, int h, int seed) {
        byte[] head = ("P6\n" + w + " " + h + "\n255\n").getBytes(StandardCharsets.US_ASCII);
        byte[] body = new byte[w * h * 3];
        int s = seed == 0 ? 1 : seed;
        for (int i = 0; i < body.length; i++) {
            s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
            body[i] = (byte) s;
        }
        byte[] out = new byte[head.length + body.length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(body, 0, out, head.length, body.length);
        return out;
    }

    private static Recipe cheap(Recipe r) { return r.argon2Cost(1, 8L * 1024 * 1024); }

    private static java.util.LinkedHashMap<String, Recipe> interopConfigs(CryptoLib lib, byte[] pk, byte[] sk) {
        var m = new java.util.LinkedHashMap<String, Recipe>();
        m.put("balanced", lib.recipe(SecurityProfile.BALANCED).withKey(hex(KEY_HEX)));
        m.put("maximum", lib.recipe(SecurityProfile.MAXIMUM).withKey(hex(KEY_HEX)));
        m.put("signed", lib.recipe(SecurityProfile.HIGH).withKey(hex(KEY_HEX))
                .signedBy(sk, SignatureAlgorithm.ED25519).verifiedBy(pk));
        m.put("passphrase", cheap(lib.recipe(SecurityProfile.BALANCED).withPassphrase(PASSPHRASE)));
        m.put("fec", lib.recipe(SecurityProfile.BALANCED).withKey(hex(KEY_HEX)).withFec(FecScheme.REPETITION3));
        return m;
    }

    public static void main(String[] args) throws Exception {
        try (var lib = new CryptoLib()) {
            lib.init();

            if (args.length >= 2 && (args[0].equals("seal") || args[0].equals("open"))) {
                var kp = lib.ed25519KeygenFromSeed(hex(SK_HEX));
                var cfgs = interopConfigs(lib, kp.publicKey(), kp.secretKey());
                int failures = 0;
                for (var e : cfgs.entrySet()) {
                    Path p = Path.of(args[1], e.getKey() + ".bin");
                    if (args[0].equals("seal")) {
                        Files.write(p, e.getValue().seal(PLAINTEXT.getBytes(StandardCharsets.UTF_8)));
                    } else {
                        try {
                            String got = new String(e.getValue().open(Files.readAllBytes(p)), StandardCharsets.UTF_8);
                            boolean ok = got.equals(PLAINTEXT);
                            System.out.println((ok ? "  ok   " : " FAIL  ") + "java opens " + e.getKey());
                            if (!ok) failures++;
                        } catch (Throwable t) {
                            System.out.println(" FAIL  java opens " + e.getKey() + ": " + t.getMessage());
                            failures++;
                        }
                    }
                }
                if (args[0].equals("seal")) System.out.println("  java sealed " + cfgs.size() + " envelopes");
                System.exit(failures == 0 ? 0 : 1);
            }

            System.out.println("CryptoLib " + lib.version() + " — security profiles + recipes (Java)");
            Path dir = Files.createTempDirectory("cl_sec_");
            byte[] secret = "the treaty text nobody may read".getBytes(StandardCharsets.UTF_8);

            // Profiles
            var max = SecurityProfile.MAXIMUM;
            ck("maximum picks the strongest options",
                    max.mlKemLevel() == 2 && max.mlDsaLevel() == 2 && max.slhDsaHash() == 1
                            && max.sealedTier() == 1 && max.kdfPreset() == 1);
            ck("maximum cascade ends key-committing",
                    max.cascade().size() == 3
                            && max.cascade().get(2) == ProtectionLayer.COMMITTING);
            ck("profiles are ordered",
                    SecurityProfile.BALANCED.argon2Memory() < max.argon2Memory());

            // Round-trips
            byte[] key = lib.randomBytes(32);
            Recipe r = lib.recipe(SecurityProfile.HIGH).withKey(key);
            ck("raw key round-trip", Arrays_equals(r.open(r.seal(secret)), secret));

            Recipe pr = cheap(lib.maximumSecurity().withPassphrase("correct horse battery staple"));
            ck("maximum + passphrase round-trip", Arrays_equals(pr.open(pr.seal(secret)), secret));

            Path keyFile = dir.resolve("key.ppm");
            Files.write(keyFile, noisePpm(96, 96, 0x5EED));
            byte[] byFile = lib.recipe(SecurityProfile.BALANCED).withKeyFile(keyFile.toString()).seal(secret);
            ck("key file reproducible across recipe objects", Arrays_equals(
                    lib.recipe(SecurityProfile.BALANCED).withKeyFile(keyFile.toString()).open(byFile), secret));

            // Composition
            Recipe mol = lib.recipe(SecurityProfile.BALANCED).withKey(key)
                    .withLayers(List.of(ProtectionLayer.MOLECULAR));
            ck("MolecularVault as one layer", Arrays_equals(mol.open(mol.seal(secret)), secret));

            byte[] one = lib.recipe(SecurityProfile.BALANCED).withKey(key)
                    .withLayers(List.of(ProtectionLayer.XCHACHA20_POLY1305)).seal(secret);
            byte[] three = lib.recipe(SecurityProfile.BALANCED).withKey(key)
                    .withLayers(List.of(ProtectionLayer.XCHACHA20_POLY1305, ProtectionLayer.AES256_GCM))
                    .addLayer(ProtectionLayer.COMMITTING).seal(secret);
            ck("each layer adds overhead", three.length > one.length);

            var id = lib.ed25519Keygen();
            Recipe signed = lib.recipe(SecurityProfile.HIGH).withKey(key)
                    .signedBy(id.secretKey(), SignatureAlgorithm.ED25519).verifiedBy(id.publicKey());
            byte[] senv = signed.seal(secret);
            ck("signed round-trip", Arrays_equals(signed.open(senv), secret));

            var hid = lib.hybridSigKeygen();
            Recipe hy = lib.recipe(SecurityProfile.BALANCED).withKey(key)
                    .signedBy(hid.secretKey(), SignatureAlgorithm.HYBRID).verifiedBy(hid.publicKey());
            ck("hybrid PQ signed round-trip", Arrays_equals(hy.open(hy.seal(secret)), secret));

            var impostor = lib.ed25519Keygen();
            ck("wrong signer rejected", throwsErr(() ->
                    lib.recipe(SecurityProfile.HIGH).withKey(key).verifiedBy(impostor.publicKey()).open(senv)));
            ck("signed envelope refuses to open unverified", throwsErr(() ->
                    lib.recipe(SecurityProfile.HIGH).withKey(key).open(senv)));

            // FEC + carrier
            Recipe fr = lib.recipe(SecurityProfile.BALANCED).withKey(key).withFec(FecScheme.REPETITION3);
            byte[] fenv = fr.seal(secret);
            fenv[fenv.length / 2] ^= 1;
            ck("FEC corrects a flipped bit", Arrays_equals(fr.open(fenv), secret));

            Path cover = dir.resolve("cover.ppm"), carrier = dir.resolve("carrier.ppm");
            Files.write(cover, noisePpm(256, 256, 0x0FF1CE));
            Recipe cr = cheap(lib.maximumSecurity().withPassphrase("a long passphrase here"));
            cr.sealIntoCarrier(secret, cover.toString(), carrier.toString());
            ck("pipeline hides itself in a carrier",
                    Arrays_equals(cr.openFromCarrier(carrier.toString()), secret));

            // Fails closed
            byte[] tenv = r.seal(secret); tenv[tenv.length - 1] ^= 1;
            ck("flipped ciphertext byte rejected", throwsErr(() -> r.open(tenv)));
            byte[] henv = r.seal(secret); henv[7] = 1;
            ck("tampered header rejected (descriptor is AAD)", throwsErr(() -> r.open(henv)));
            byte[] senv2 = r.seal(secret); senv2[10] ^= (byte) 0xFF;
            ck("tampered salt rejected", throwsErr(() -> r.open(senv2)));
            byte[] other = lib.randomBytes(32);
            ck("wrong key rejected", throwsErr(() ->
                    lib.recipe(SecurityProfile.HIGH).withKey(other).open(r.seal(secret))));
            ck("foreign bytes rejected", throwsErr(() ->
                    r.open("not an envelope at all".getBytes(StandardCharsets.UTF_8))));
            ck("short key refused", throwsErr(() ->
                    lib.recipe(SecurityProfile.BALANCED).withKey(new byte[31])));
            ck("empty layer list refused", throwsErr(() ->
                    lib.recipe(SecurityProfile.BALANCED).withLayers(List.of())));

            deleteTree(dir);
            System.out.println("\n" + pass + " passed, " + fail + " failed — recipes "
                    + (fail == 0 ? "OK" : "FAILED"));
            System.exit(fail == 0 ? 0 : 1);
        }
    }

    private static boolean Arrays_equals(byte[] a, byte[] b) { return java.util.Arrays.equals(a, b); }

    private static void deleteTree(Path p) throws Exception {
        try (var s = Files.walk(p)) {
            s.sorted(java.util.Comparator.reverseOrder()).forEach(x -> { try { Files.delete(x); } catch (Exception ignored) {} });
        }
    }
}
