package cryptolib;

import java.util.List;

/**
 * A coherent set of algorithm parameters, from ordinary to maximal.
 *
 * <p>Every field moves together, so you cannot accidentally pair a maximal KEM
 * with an interactive-cost KDF. Reach for {@link #MAXIMUM} when the data
 * outlives the threat model you can predict.
 */
public enum SecurityProfile {
    /** Sound modern defaults. Fast enough for interactive use. */
    BALANCED,
    /** Stronger parameters and a two-cipher cascade. */
    HIGH,
    /**
     * The strongest option the library offers at every choice: category-5
     * post-quantum parameter sets, the triple-family sealed tier, a three-layer
     * cascade ending in a key-committing AEAD, and a memory-hard KDF tuned well
     * past interactive comfort.
     */
    MAXIMUM;

    /** ML-KEM parameter set (0 = 512, 1 = 768, 2 = 1024). */
    public int mlKemLevel() { return this == MAXIMUM ? 2 : 1; }

    /** ML-DSA parameter set (0 = 44, 1 = 65, 2 = 87). */
    public int mlDsaLevel() { return this == MAXIMUM ? 2 : 1; }

    /**
     * SLH-DSA parameter set. {@link #MAXIMUM} takes the small-signature variant:
     * it signs more slowly but keeps signatures compact, and hash-based security
     * is the point of using it at all.
     */
    public int slhDsaLevel() {
        return switch (this) { case MAXIMUM -> 4; case HIGH -> 3; case BALANCED -> 1; };
    }

    /** SLH-DSA hash family (0 = SHA-2, 1 = SHAKE). */
    public int slhDsaHash() { return this == MAXIMUM ? 1 : 0; }

    /** Sealed-messaging tier (0 = Flagship, 1 = Fortress). */
    public int sealedTier() { return this == MAXIMUM ? 1 : 0; }

    /** Argon2id preset for vault and keyring slots (0 = interactive, 1 = sensitive). */
    public int kdfPreset() { return this == BALANCED ? 0 : 1; }

    /** Argon2id iteration count used by {@link Recipe}. */
    public long argon2Ops() {
        return switch (this) { case MAXIMUM -> 4L; case HIGH -> 3L; case BALANCED -> 2L; };
    }

    /**
     * Argon2id memory cost in bytes used by {@link Recipe}. Memory is what
     * actually costs an attacker; raise it as far as the slowest device you must
     * support can bear.
     */
    public long argon2Memory() {
        return switch (this) {
            case MAXIMUM -> 512L * 1024 * 1024;
            case HIGH -> 256L * 1024 * 1024;
            case BALANCED -> 64L * 1024 * 1024;
        };
    }

    /**
     * The AEAD cascade this profile applies, innermost first.
     *
     * <p>Independent cipher families mean a break of one does not open the
     * envelope, and the key-committing outer layer closes partitioning-oracle and
     * Invisible-Salamanders style attacks.
     */
    public List<ProtectionLayer> cascade() {
        return switch (this) {
            case MAXIMUM -> List.of(ProtectionLayer.XCHACHA20_POLY1305,
                                    ProtectionLayer.AES256_GCM,
                                    ProtectionLayer.COMMITTING);
            case HIGH -> List.of(ProtectionLayer.XCHACHA20_POLY1305, ProtectionLayer.AES256_GCM);
            case BALANCED -> List.of(ProtectionLayer.XCHACHA20_POLY1305);
        };
    }

    /** Lower-case name used in {@link Recipe#describe()}. */
    public String label() { return name().toLowerCase(); }
}
