package cryptolib;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

/** Smoke test: load the bundled native lib (no path) and round-trip. */
public final class Main {
    static int pass = 0, fail = 0;
    static void ck(String label, boolean ok) {
        System.out.println("  " + (ok ? "✓" : "✗") + " " + label);
        if (ok) pass++; else fail++;
    }

    public static void main(String[] args) {
        try (CryptoLib c = new CryptoLib()) {
            c.init();
            ck("version == 3.0.0", c.version().equals("3.0.0"));

            String sha = HexFormat.of().formatHex(c.sha256("abc".getBytes(StandardCharsets.US_ASCII)));
            ck("SHA-256(\"abc\") KAT",
               sha.equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

            var kp = c.hybridKemKeygen();
            var enc = c.hybridKemEncapsulate(kp.publicKey());
            byte[] dec = c.hybridKemDecapsulate(enc.ciphertext(), kp.secretKey());
            ck("Hybrid X25519+ML-KEM-768 round-trip",
               Arrays.equals(enc.sharedSecret(), dec) && enc.sharedSecret().length == 32);
        }
        System.out.println("\ncryptolib JVM smoke: " + (fail == 0 ? "OK" : "FAILED")
                + " (" + pass + " passed, " + fail + " failed)");
        System.exit(fail == 0 ? 0 : 1);
    }
}
