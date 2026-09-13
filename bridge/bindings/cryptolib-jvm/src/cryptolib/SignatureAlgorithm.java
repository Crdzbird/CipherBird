package cryptolib;

/**
 * Built-in scheme selector for the {@link Recipe#signedBy} shorthand. For a
 * custom algorithm implement {@link SignatureScheme} and use
 * {@link Recipe#signedWith} / {@link Recipe#verifiedWith}.
 */
public enum SignatureAlgorithm {
    /** No signature. The AEAD still guarantees integrity, but not who sent it. */
    NONE(0),
    /** Ed25519. */
    ED25519(1),
    /** Ed25519 + ML-DSA-65. A forgery needs breaking both families. */
    HYBRID(2);

    private final int id;

    SignatureAlgorithm(int id) { this.id = id; }

    /** Identifier recorded in the envelope header. */
    public int id() { return id; }

    static SignatureAlgorithm fromId(int id) {
        for (SignatureAlgorithm s : values()) if (s.id == id) return s;
        throw new IllegalArgumentException("cryptolib: unknown signature id " + id);
    }
}
