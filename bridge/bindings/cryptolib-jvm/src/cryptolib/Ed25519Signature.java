package cryptolib;

/** Ed25519. Pass the secret key to sign, the public key to verify, or both. */
public final class Ed25519Signature implements SignatureScheme, Builtin {
    private final byte[] secretKey, publicKey;

    public Ed25519Signature(byte[] secretKey, byte[] publicKey) {
        this.secretKey = secretKey == null ? null : secretKey.clone();
        this.publicKey = publicKey == null ? null : publicKey.clone();
    }

    public static Ed25519Signature signer(byte[] secretKey) { return new Ed25519Signature(secretKey, null); }
    public static Ed25519Signature verifier(byte[] publicKey) { return new Ed25519Signature(null, publicKey); }

    @Override public int id() { return 1; }
    @Override public String label() { return "ed25519"; }
    @Override public byte[] sign(CryptoLib lib, byte[] m) {
        if (secretKey == null) throw new IllegalStateException("cryptolib: Ed25519Signature has no secret key");
        return lib.ed25519Sign(m, secretKey);
    }
    @Override public boolean verify(CryptoLib lib, byte[] m, byte[] sig) {
        return publicKey != null && lib.ed25519Verify(m, sig, publicKey);
    }
}
