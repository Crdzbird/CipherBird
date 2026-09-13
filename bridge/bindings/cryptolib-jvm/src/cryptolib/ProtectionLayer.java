package cryptolib;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * One authenticated-encryption layer in a {@link Recipe} cascade.
 *
 * <p>Implement it to add your own layer, then {@link #register} it (on the
 * opening side too — the envelope stores only the id). Contract: {@link #seal}
 * must be authenticated encryption that binds {@code aad}, and {@link #open}
 * must throw on any modification. The key is fresh per layer per envelope —
 * never reuse it. To compose several ciphers into one layer, extend
 * {@link CascadeLayer}.
 *
 * <pre>{@code
 * final class MyLayer implements ProtectionLayer {
 *     public int id() { return 200; }
 *     public String wireName() { return "my-xchacha"; }
 *     public byte[] seal(CryptoLib lib, byte[] key, byte[] aad, byte[] pt) { return lib.xchacha20Encrypt(pt, key, aad); }
 *     public byte[] open(CryptoLib lib, byte[] key, byte[] aad, byte[] ct) { return lib.xchacha20Decrypt(ct, key, aad); }
 * }
 * ProtectionLayer.register(new MyLayer());
 * }</pre>
 *
 * <p>Ids 0–127 are reserved for the library; custom layers must use 128–255.
 * Since {@link #wireName} feeds the key derivation, an implementation that
 * disagrees with the sealer fails the AEAD tag rather than yielding garbage.
 */
public interface ProtectionLayer {
    /** XChaCha20-Poly1305. Large nonce, no timing-sensitive tables. */
    ProtectionLayer XCHACHA20_POLY1305 = new BuiltinLayer(1, "xchacha20Poly1305") {
        public byte[] seal(CryptoLib l, byte[] k, byte[] a, byte[] p) { return l.xchacha20Encrypt(p, k, a); }
        public byte[] open(CryptoLib l, byte[] k, byte[] a, byte[] c) { return l.xchacha20Decrypt(c, k, a); }
    };
    /** AES-256-GCM. A different cipher family from ChaCha. */
    ProtectionLayer AES256_GCM = new BuiltinLayer(2, "aes256Gcm") {
        public byte[] seal(CryptoLib l, byte[] k, byte[] a, byte[] p) { return l.aes256gcmEncrypt(p, k, a); }
        public byte[] open(CryptoLib l, byte[] k, byte[] a, byte[] c) { return l.aes256gcmDecrypt(c, k, a); }
    };
    /** Key-committing AEAD (UtC). Binds the ciphertext to exactly one key. */
    ProtectionLayer COMMITTING = new BuiltinLayer(3, "committing") {
        public byte[] seal(CryptoLib l, byte[] k, byte[] a, byte[] p) { return l.committingEncrypt(p, k, a); }
        public byte[] open(CryptoLib l, byte[] k, byte[] a, byte[] c) { return l.committingDecrypt(c, k, a); }
    };
    /** A full MolecularVault (cascade + committing) nested as one layer. */
    ProtectionLayer MOLECULAR = new BuiltinLayer(4, "molecular") {
        public byte[] seal(CryptoLib l, byte[] k, byte[] a, byte[] p) { return l.molecularSealWithKey(p, k, a); }
        public byte[] open(CryptoLib l, byte[] k, byte[] a, byte[] c) { return l.molecularOpenWithKey(c, k, a); }
    };

    /** Identifier recorded in the envelope header. Built-ins use 1–4; custom 128–255. */
    int id();

    /**
     * Name used in this layer's HKDF info string. Part of the wire format, so
     * it must never drift between the sealing and the opening side.
     */
    String wireName();

    /** Authenticated encryption of {@code plaintext} under a fresh 32-byte key, binding {@code aad}. */
    byte[] seal(CryptoLib lib, byte[] key, byte[] aad, byte[] plaintext);

    /** The inverse of {@link #seal}; must throw on any modification. */
    byte[] open(CryptoLib lib, byte[] key, byte[] aad, byte[] ciphertext);

    /**
     * Make a custom layer resolvable by id when opening envelopes. Required on
     * both the sealing and the opening side. Re-registering an id under a
     * different wire name is refused.
     */
    static void register(ProtectionLayer layer) {
        Builtin.requireValidId(layer, layer.id(), "layer");
        ProtectionLayer existing = Registry.LAYERS.get(layer.id());
        if (existing != null && !existing.wireName().equals(layer.wireName())) {
            throw new IllegalStateException("cryptolib: layer id " + layer.id()
                    + " is already registered as '" + existing.wireName() + "'");
        }
        Registry.LAYERS.put(layer.id(), layer);
    }

    static ProtectionLayer fromId(int id) {
        ProtectionLayer l = Registry.LAYERS.get(id);
        if (l == null) {
            throw new IllegalArgumentException("cryptolib: unknown protection layer id " + id
                    + " — ProtectionLayer.register() it before opening");
        }
        return l;
    }

    /** Holder so the interface's constant initialisation and the registry do not race. */
    final class Registry {
        static final Map<Integer, ProtectionLayer> LAYERS = new ConcurrentHashMap<>();
        static {
            for (ProtectionLayer l : new ProtectionLayer[]{XCHACHA20_POLY1305, AES256_GCM, COMMITTING, MOLECULAR}) {
                LAYERS.put(l.id(), l);
            }
        }
        private Registry() {}
    }

    /** Base of the four library layers; carries the package-private {@link Builtin} marker. */
    abstract class BuiltinLayer implements ProtectionLayer, Builtin {
        private final int id;
        private final String wireName;
        BuiltinLayer(int id, String wireName) { this.id = id; this.wireName = wireName; }
        public final int id() { return id; }
        public final String wireName() { return wireName; }
        @Override public String toString() { return wireName; }
    }
}
