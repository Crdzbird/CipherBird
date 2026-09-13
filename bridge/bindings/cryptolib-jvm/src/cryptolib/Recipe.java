package cryptolib;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A composable protection pipeline.
 *
 * <p>Describe what you want once, then {@link #seal} and {@link #open} with the
 * same recipe. The envelope carries its own descriptor, so opening does not
 * depend on remembering which layers were used — only on holding the key.
 *
 * <pre>{@code
 * var recipe = lib.maximumSecurity()
 *         .withPassphrase("correct horse battery staple")
 *         .signedBy(id.secretKey(), SignatureAlgorithm.HYBRID)
 *         .verifiedBy(id.publicKey());
 *
 * byte[] envelope = recipe.seal(secret);
 * byte[] back = recipe.open(envelope);
 * }</pre>
 *
 * <p>Composition only — every step is an existing, vetted operation. What the
 * recipe adds is the plumbing that is easy to get wrong by hand:
 *
 * <ul>
 *   <li>Every layer gets its <b>own</b> key, via HKDF with a distinct info
 *       string. A key is never reused across two layers.
 *   <li>The header describing the recipe is authenticated as AAD by <b>every</b>
 *       layer, so the descriptor cannot be altered without every layer failing.
 *   <li>Order is fixed and not caller-selectable: sign → encrypt (inner to
 *       outer) → error-correct → conceal. Opening reverses it exactly.
 *   <li>Everything fails closed.
 * </ul>
 *
 * <p>The envelope is a library-native format, and is identical across every
 * CryptoLib binding: an envelope sealed here opens in Dart, Go, Node or Swift.
 *
 * <p>Builder methods return {@code this} so calls chain. Not thread-safe.
 */
public final class Recipe {
    private static final byte[] MAGIC = {'C', 'L', 'R', 'C'};
    private static final byte[] FEC_MAGIC = {'C', 'L', 'F', 'C'};
    private static final int VERSION = 1;
    private static final int SALT_LEN = 16;

    private final CryptoLib lib;
    private final SecurityProfile profile;
    private final SecureRandom rng = new SecureRandom();

    private List<ProtectionLayer> layers;
    private KeySource source;
    private SignatureScheme signer;
    private SignatureScheme verifier;
    private byte[] verifierKey;
    private FecScheme fec = FecScheme.NONE;
    private long argonOps;
    private long argonMemory;

    Recipe(CryptoLib lib, SecurityProfile profile) {
        this.lib = lib;
        this.profile = profile;
        this.layers = new ArrayList<>(profile.cascade());
        this.argonOps = profile.argon2Ops();
        this.argonMemory = profile.argon2Memory();
    }

    // ── Key source (exactly one) ─────────────────────────────────────────────

    /** Use any {@link KeySource} — a built-in or your own implementation. */
    public Recipe withKeySource(KeySource source) {
        Builtin.requireValidId(source, source.id(), "key source");
        this.source = source;
        return this;
    }

    /** Derive the root key from a passphrase with Argon2id at this profile's cost. */
    public Recipe withPassphrase(String passphrase) { return withKeySource(new PassphraseKeySource(passphrase)); }

    /**
     * Use a 32-byte key directly — from a KEM shared secret, a keyring unlock, a
     * hardware token, anywhere. Nothing is stretched; the key must already be
     * full-entropy.
     */
    public Recipe withKey(byte[] key) { return withKeySource(new RawKeySource(key)); }

    /**
     * Derive the root key deterministically from a media file — "the file is the
     * key". The same file always yields the same key on any machine.
     */
    public Recipe withKeyFile(String path) { return withKeySource(new KeyFileSource(path)); }

    // ── Layers ───────────────────────────────────────────────────────────────

    /** Replace the cascade with exactly these layers, innermost first. */
    public Recipe withLayers(List<ProtectionLayer> layers) {
        if (layers.isEmpty()) throw new IllegalArgumentException("cryptolib: a recipe needs at least one layer");
        for (ProtectionLayer l : layers) Builtin.requireValidId(l, l.id(), "layer");
        this.layers = new ArrayList<>(layers);
        return this;
    }

    /** Append one more layer on the outside of the current cascade. */
    public Recipe addLayer(ProtectionLayer layer) {
        Builtin.requireValidId(layer, layer.id(), "layer");
        this.layers.add(layer);
        return this;
    }

    /** Override the Argon2id cost. Only meaningful with {@link #withPassphrase}. */
    public Recipe argon2Cost(long ops, long memoryBytes) {
        this.argonOps = ops;
        this.argonMemory = memoryBytes;
        return this;
    }

    // ── Authenticity ─────────────────────────────────────────────────────────

    /** Sign with any {@link SignatureScheme} — a built-in or your own implementation. */
    public Recipe signedWith(SignatureScheme scheme) {
        Builtin.requireValidId(scheme, scheme.id(), "signature scheme");
        this.signer = scheme;
        return this;
    }

    /** Verify with any {@link SignatureScheme}. Required for a custom scheme. */
    public Recipe verifiedWith(SignatureScheme scheme) {
        Builtin.requireValidId(scheme, scheme.id(), "signature scheme");
        this.verifier = scheme;
        this.verifierKey = null;
        return this;
    }

    /**
     * Sign the plaintext before it is encrypted with a built-in scheme, proving
     * who produced it. The signature travels inside the encryption, so it
     * reveals nothing about the sender to an observer.
     */
    public Recipe signedBy(byte[] secretKey, SignatureAlgorithm algorithm) {
        return switch (algorithm) {
            case ED25519 -> signedWith(Ed25519Signature.signer(secretKey));
            case HYBRID -> signedWith(HybridSignature.signer(secretKey));
            case NONE -> throw new IllegalArgumentException("cryptolib: signedBy needs a real algorithm");
        };
    }

    /**
     * The public key {@link #open} must verify the embedded signature against.
     * Works for either built-in scheme — the envelope records which one. A
     * custom {@link SignatureScheme} must be supplied through {@link #verifiedWith}.
     *
     * <p>Required whenever the envelope is signed: without it there would be a
     * signature but nobody checking it, so {@link #open} fails rather than
     * silently accepting.
     */
    public Recipe verifiedBy(byte[] publicKey) {
        this.verifier = null;
        this.verifierKey = publicKey.clone();
        return this;
    }

    /** Apply forward error correction to the finished envelope. */
    public Recipe withFec(FecScheme scheme) {
        this.fec = scheme;
        return this;
    }

    // ── Seal / open ──────────────────────────────────────────────────────────

    /** Protect {@code plaintext} and return the envelope. */
    public byte[] seal(byte[] plaintext) {
        KeySource src = requireSource();
        byte[] salt = new byte[SALT_LEN];
        rng.nextBytes(salt);
        byte[] header = buildHeader(src, salt);
        byte[] root = rootKey(src, salt, argonOps, argonMemory);

        byte[] body = plaintext;
        if (signer != null) body = prefixLengthed(signer.sign(lib, plaintext), plaintext);
        for (int i = 0; i < layers.size(); i++) {
            body = applyLayer(layers.get(i), i, root, salt, header, body, true);
        }
        byte[] envelope = concat(header, body);
        return fec == FecScheme.NONE ? envelope : wrapFec(envelope);
    }

    /**
     * Recover the plaintext. Throws if the key is wrong, a byte was altered, or a
     * signature is present but does not verify.
     */
    public byte[] open(byte[] envelope) {
        KeySource src = requireSource();
        byte[] inner = unwrapFec(envelope);
        Parsed h = parseHeader(inner, src);
        byte[] root = rootKey(src, h.salt, h.ops, h.memory);

        byte[] body = Arrays.copyOfRange(inner, h.header.length, inner.length);
        for (int i = h.layers.size() - 1; i >= 0; i--) {
            body = applyLayer(h.layers.get(i), i, root, h.salt, h.header, body, false);
        }
        if (h.signatureId == 0) return body;

        byte[][] parts = splitLengthed(body);
        SignatureScheme v = verifier != null ? verifier : builtinVerifier(h.signatureId);
        if (v == null) {
            if (verifierKey != null) {
                throw new IllegalStateException("cryptolib: envelope was signed with scheme id " + h.signatureId
                        + ", which is not a built-in — supply that SignatureScheme with verifiedWith()");
            }
            throw new IllegalStateException(
                    "cryptolib: envelope is signed but no verifier was supplied — "
                    + "call verifiedBy/verifiedWith so the signature is actually checked");
        }
        if (v.id() != h.signatureId) {
            throw new IllegalStateException("cryptolib: envelope was signed with scheme id " + h.signatureId
                    + ", but the verifier is '" + v.label() + "' (id " + v.id() + ")");
        }
        if (!v.verify(lib, parts[1], parts[0])) throw new RuntimeException("cryptolib: signature verification failed");
        return parts[1];
    }

    /**
     * Seal {@code plaintext} and hide the envelope inside {@code coverPath}.
     *
     * <p>Concealment is defence-in-depth, never the confidentiality boundary —
     * the envelope is already authenticated-encrypted before it is embedded.
     */
    public void sealIntoCarrier(byte[] plaintext, String coverPath, String outputPath) {
        lib.stegoEmbed(coverPath, seal(plaintext), outputPath);
    }

    /** Extract and open an envelope written by {@link #sealIntoCarrier}. */
    public byte[] openFromCarrier(String stegoPath) { return open(lib.stegoExtract(stegoPath)); }

    /**
     * A human-readable summary of what this recipe will do — handy in logs and
     * code review, where a silently-weak configuration is the thing to catch.
     */
    public String describe() {
        StringBuilder b = new StringBuilder("Recipe(").append(profile.label()).append(")\n");
        b.append("  key      : ").append(source == null ? "(unset)" : source.label()).append('\n');
        StringBuilder names = new StringBuilder();
        for (int i = 0; i < layers.size(); i++) {
            if (i > 0) names.append(" → ");
            names.append(layers.get(i).wireName());
        }
        b.append("  layers   : ").append(names).append('\n');
        b.append("  signature: ").append(signer == null ? "none" : signer.label()).append('\n');
        b.append("  fec      : ").append(fec.id()).append('\n');
        if (source instanceof PassphraseKeySource) {
            b.append("  argon2id : ops=").append(argonOps)
             .append(", mem=").append(argonMemory / (1024 * 1024)).append("MiB\n");
        }
        return b.toString();
    }

    // ── Internals ────────────────────────────────────────────────────────────

    private KeySource requireSource() {
        if (source == null) {
            throw new IllegalStateException("cryptolib: no key set — call withKey/withPassphrase/withKeyFile/withKeySource");
        }
        return source;
    }

    private SignatureScheme builtinVerifier(int id) {
        if (verifierKey == null) return null;
        return switch (id) {
            case 1 -> Ed25519Signature.verifier(verifierKey);
            case 2 -> HybridSignature.verifier(verifierKey);
            default -> null;
        };
    }

    private byte[] rootKey(KeySource src, byte[] salt, long ops, long memory) {
        byte[] root = src.deriveRoot(lib, salt, ops, memory);
        if (root == null || root.length != 32) {
            throw new IllegalStateException("cryptolib: key source '" + src.label() + "' produced "
                    + (root == null ? 0 : root.length) + " bytes; the root key must be exactly 32");
        }
        return root;
    }

    /** HKDF under a distinct info string, so no two layers share key material. */
    private byte[] layerKey(byte[] root, byte[] salt, int index, ProtectionLayer layer) {
        byte[] info = ("cryptolib/recipe/v1/layer" + index + "/" + layer.wireName())
                .getBytes(StandardCharsets.UTF_8);
        return lib.hkdfDerive(root, salt, info, 32);
    }

    private byte[] applyLayer(ProtectionLayer layer, int index, byte[] root, byte[] salt,
                              byte[] header, byte[] data, boolean seal) {
        byte[] key = layerKey(root, salt, index, layer);
        return seal ? layer.seal(lib, key, header, data) : layer.open(lib, key, header, data);
    }

    private byte[] buildHeader(KeySource src, byte[] salt) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(MAGIC);
        out.write(VERSION);
        out.write(src.id());
        out.write(signer == null ? 0 : signer.id());
        out.write(layers.size());
        for (ProtectionLayer l : layers) out.write(l.id());
        out.writeBytes(salt);
        out.writeBytes(ByteBuffer.allocate(8).putInt((int) argonOps).putInt((int) argonMemory).array());
        return out.toByteArray();
    }

    private record Parsed(byte[] header, List<ProtectionLayer> layers, byte[] salt,
                          int signatureId, long ops, long memory) {}

    private Parsed parseHeader(byte[] env, KeySource src) {
        if (env.length < 8 + SALT_LEN + 8) throw new RuntimeException("cryptolib: envelope too short");
        for (int i = 0; i < 4; i++) {
            if (env[i] != MAGIC[i]) throw new RuntimeException("cryptolib: not a CryptoRecipe envelope");
        }
        if (env[4] != VERSION) throw new RuntimeException("cryptolib: unsupported envelope version " + env[4]);
        int srcId = env[5] & 0xFF;
        if (srcId != src.id()) {
            throw new RuntimeException("cryptolib: envelope was sealed with key source id " + srcId
                    + ", but this recipe is configured for '" + src.label() + "' (id " + src.id() + ")");
        }
        int sa = env[6] & 0xFF;
        int count = env[7] & 0xFF;
        int headerLen = 8 + count + SALT_LEN + 8;
        if (env.length < headerLen) throw new RuntimeException("cryptolib: truncated envelope header");
        List<ProtectionLayer> ls = new ArrayList<>(count);
        for (int i = 0; i < count; i++) ls.add(ProtectionLayer.fromId(env[8 + i] & 0xFF));
        byte[] salt = Arrays.copyOfRange(env, 8 + count, 8 + count + SALT_LEN);
        ByteBuffer costs = ByteBuffer.wrap(env, 8 + count + SALT_LEN, 8);
        long ops = Integer.toUnsignedLong(costs.getInt());
        long mem = Integer.toUnsignedLong(costs.getInt());
        return new Parsed(Arrays.copyOfRange(env, 0, headerLen), ls, salt, sa, ops, mem);
    }

    private byte[] wrapFec(byte[] envelope) {
        byte[] encoded = lib.fecEncode(envelope, fec.id());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(FEC_MAGIC);
        out.write(fec.id());
        out.writeBytes(ByteBuffer.allocate(4).putInt(envelope.length).array());
        out.writeBytes(encoded);
        return out.toByteArray();
    }

    private byte[] unwrapFec(byte[] data) {
        if (data.length < 9) return data;
        for (int i = 0; i < 4; i++) if (data[i] != FEC_MAGIC[i]) return data;
        FecScheme scheme = FecScheme.fromId(data[4] & 0xFF);
        int originalLen = ByteBuffer.wrap(data, 5, 4).getInt();
        return lib.fecDecode(Arrays.copyOfRange(data, 9, data.length), scheme.id(), originalLen);
    }

    private static byte[] prefixLengthed(byte[] prefix, byte[] rest) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(ByteBuffer.allocate(4).putInt(prefix.length).array());
        out.writeBytes(prefix);
        out.writeBytes(rest);
        return out.toByteArray();
    }

    private static byte[][] splitLengthed(byte[] data) {
        if (data.length < 4) throw new RuntimeException("cryptolib: malformed signed payload");
        int n = ByteBuffer.wrap(data, 0, 4).getInt();
        if (n < 0 || data.length < 4 + n) throw new RuntimeException("cryptolib: malformed signed payload");
        return new byte[][]{Arrays.copyOfRange(data, 4, 4 + n), Arrays.copyOfRange(data, 4 + n, data.length)};
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
