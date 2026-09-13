package cryptolib;

/** Ed25519 + ML-DSA-65. A forgery needs breaking both families. */
public final class HybridSignature implements SignatureScheme, Builtin {
    private final byte[] secretKey, publicKey;

    public HybridSignature(byte[] secretKey, byte[] publicKey) {
        this.secretKey = secretKey == null ? null : secretKey.clone();
        this.publicKey = publicKey == null ? null : publicKey.clone();
    }

    public static HybridSignature signer(byte[] secretKey) { return new HybridSignature(secretKey, null); }
    public static HybridSignature verifier(byte[] publicKey) { return new HybridSignature(null, publicKey); }

    @Override public int id() { return 2; }
    @Override public String label() { return "hybrid"; }
    @Override public byte[] sign(CryptoLib lib, byte[] m) {
        if (secretKey == null) throw new IllegalStateException("cryptolib: HybridSignature has no secret key");
        return lib.hybridSigSign(m, secretKey);
    }
    @Override public boolean verify(CryptoLib lib, byte[] m, byte[] sig) {
        return publicKey != null && lib.hybridSigVerify(m, sig, publicKey);
    }
}
