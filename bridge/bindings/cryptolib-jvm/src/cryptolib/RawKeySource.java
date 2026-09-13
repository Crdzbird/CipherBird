package cryptolib;

/** A 32-byte full-entropy key used as-is (KEM shared secret, keyring unlock, token). */
public final class RawKeySource implements KeySource, Builtin {
    private final byte[] key;

    public RawKeySource(byte[] key) {
        if (key.length != 32) throw new IllegalArgumentException("cryptolib: root key must be exactly 32 bytes, got " + key.length);
        this.key = key.clone();
    }

    @Override public int id() { return 0; }
    @Override public String label() { return "raw"; }
    @Override public byte[] deriveRoot(CryptoLib lib, byte[] salt, long ops, long memory) { return key; }
}
