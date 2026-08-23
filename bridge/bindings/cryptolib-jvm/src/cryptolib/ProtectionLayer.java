package cryptolib;

/** One authenticated-encryption layer in a {@link Recipe} cascade. */
public enum ProtectionLayer {
    /** XChaCha20-Poly1305. Large nonce, no timing-sensitive tables. */
    XCHACHA20_POLY1305(1, "xchacha20Poly1305"),
    /** AES-256-GCM. A different cipher family from ChaCha. */
    AES256_GCM(2, "aes256Gcm"),
    /** Key-committing AEAD (UtC). Binds the ciphertext to exactly one key. */
    COMMITTING(3, "committing"),
    /** A full MolecularVault (cascade + committing) nested as one layer. */
    MOLECULAR(4, "molecular");

    private final int id;
    private final String wireName;

    ProtectionLayer(int id, String wireName) { this.id = id; this.wireName = wireName; }

    /** Identifier recorded in the envelope header. */
    public int id() { return id; }

    /**
     * Name used in this layer's HKDF info string.
     *
     * <p>Pinned explicitly rather than derived from the enum constant: it is part
     * of the wire format, so renaming must not silently change how keys are
     * derived — envelopes are opened by other language bindings too.
     */
    public String wireName() { return wireName; }

    static ProtectionLayer fromId(int id) {
        for (ProtectionLayer l : values()) if (l.id == id) return l;
        throw new IllegalArgumentException("cryptolib: unknown protection layer id " + id);
    }
}
