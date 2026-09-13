package cryptolib;

/** A passphrase stretched with Argon2id at the recipe's cost. */
public final class PassphraseKeySource implements KeySource, Builtin {
    private final String passphrase;

    public PassphraseKeySource(String passphrase) { this.passphrase = passphrase; }

    @Override public int id() { return 1; }
    @Override public String label() { return "passphrase"; }
    @Override public byte[] deriveRoot(CryptoLib lib, byte[] salt, long ops, long memory) {
        return lib.argon2idDerive(passphrase, salt, 32, ops, memory);
    }
}
