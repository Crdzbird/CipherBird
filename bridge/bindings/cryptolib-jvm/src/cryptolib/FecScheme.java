package cryptolib;

/**
 * Forward-error-correction scheme applied to a finished envelope.
 *
 * <p>Trades carrier capacity for tolerance of bounded bit errors — useful when a
 * carrier may be recompressed or resampled in transit. Classic codes, no new
 * cryptography.
 */
public enum FecScheme {
    /** No redundancy. Full capacity, no error tolerance. */
    NONE(0),
    /** Each bit repeated 3x; corrects 1 error per triple. */
    REPETITION3(1),
    /** Each bit repeated 5x; corrects 2 errors per group. */
    REPETITION5(2),
    /** Hamming(7,4): corrects 1 error per 7-bit block. */
    HAMMING74(3);

    private final int id;

    FecScheme(int id) { this.id = id; }

    /** Wire value passed to the C ABI. */
    public int id() { return id; }

    static FecScheme fromId(int id) {
        for (FecScheme s : values()) if (s.id == id) return s;
        throw new IllegalArgumentException("cryptolib: unknown FEC scheme " + id);
    }
}
