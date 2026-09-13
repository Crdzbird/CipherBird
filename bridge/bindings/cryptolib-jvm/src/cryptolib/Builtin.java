package cryptolib;

/**
 * Package-private marker carried by the library's own recipe parts.
 *
 * <p>Only types in this package can implement it, so a custom {@link
 * ProtectionLayer}, {@link KeySource} or {@link SignatureScheme} can never claim
 * a reserved identifier by pretending to be built in.
 */
interface Builtin {
    int CUSTOM_ID_MIN = 128;
    int CUSTOM_ID_MAX = 255;

    static void requireValidId(Object part, int id, String what) {
        if (part instanceof Builtin) return;
        if (id < CUSTOM_ID_MIN || id > CUSTOM_ID_MAX) {
            throw new IllegalArgumentException("cryptolib: custom " + what + " ids must be in "
                    + CUSTOM_ID_MIN + ".." + CUSTOM_ID_MAX + " (0–127 are reserved), got " + id);
        }
    }
}
