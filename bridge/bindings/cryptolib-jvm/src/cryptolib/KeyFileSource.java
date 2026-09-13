package cryptolib;

/**
 * The key derived deterministically from a media file — "the file is the key".
 *
 * <p>Uses the reproducible entropy path: {@code keyFromFile} mixes in fresh
 * system entropy and so could never reopen its own envelope.
 */
public final class KeyFileSource implements KeySource, Builtin {
    private final String path;

    public KeyFileSource(String path) { this.path = path; }

    @Override public int id() { return 2; }
    @Override public String label() { return "keyFile"; }
    @Override public byte[] deriveRoot(CryptoLib lib, byte[] salt, long ops, long memory) {
        return lib.keyFromFileDeterministic(path);
    }
}
