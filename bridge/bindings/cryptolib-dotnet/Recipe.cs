using System.Buffers.Binary;
using System.Text;

namespace CryptoLibNet;

/// <summary>
/// A coherent set of algorithm parameters, from ordinary to maximal.
/// </summary>
/// <remarks>
/// Every field moves together, so you cannot accidentally pair a maximal KEM
/// with an interactive-cost KDF.
/// </remarks>
public enum SecurityProfile
{
    /// <summary>Sound modern defaults. Fast enough for interactive use.</summary>
    Balanced,
    /// <summary>Stronger parameters and a two-cipher cascade.</summary>
    High,
    /// <summary>
    /// The strongest option at every choice: category-5 post-quantum parameter
    /// sets, the triple-family sealed tier, a three-layer cascade ending in a
    /// key-committing AEAD, and a memory-hard KDF past interactive comfort.
    /// </summary>
    Maximum,
}

// ── Extension points ─────────────────────────────────────────────────────────
//
// Three abstract classes can be subclassed and plugged into a Recipe:
//   ProtectionLayer  — one authenticated-encryption layer in the cascade.
//   KeySource        — where the 32-byte root key comes from.
//   SignatureScheme  — how the plaintext is signed and verified.
// The library's own implementations subclass the same bases, so a custom one is
// a first-class citizen. To compose several ciphers into ONE layer, subclass
// CascadeLayer.
//
// What the recipe keeps for itself, whatever you plug in: a layer never chooses
// its key (it receives a fresh 32-byte key per layer per envelope, HKDF-derived
// under salt + WireName); a layer cannot opt out of the AAD; the order is fixed
// (sign → encrypt → correct → conceal); a KeySource must return exactly 32
// bytes; ids 0–127 are reserved — custom parts must use 128–255, enforced so a
// custom part can never shadow a built-in.
//
// Cross-language: built-in ids open in every CryptoLib binding. A custom part
// opens only where the same id + WireName + algorithm is registered — and since
// WireName feeds the key derivation, a mismatched implementation fails the AEAD
// tag rather than yielding garbage.

/// <summary>
/// Assembly-internal marker carried by the built-in parts, so a subclass from
/// another assembly can never claim a reserved id by pretending to be built in.
/// </summary>
internal interface IBuiltin { }

internal static class PartIds
{
    public const int CustomMin = 128, CustomMax = 255;

    public static void RequireValid(object part, int id, string what)
    {
        if (part is IBuiltin) return;
        if (id < CustomMin || id > CustomMax)
            throw new ArgumentException(
                $"cryptolib: custom {what} ids must be in {CustomMin}..{CustomMax} (0–127 are reserved), got {id}");
    }
}

/// <summary>One authenticated-encryption layer in a <see cref="Recipe"/> cascade.</summary>
/// <remarks>
/// <para>Subclass it to add your own layer, then <see cref="Register"/> it (on the
/// opening side too — the envelope stores only the id). Contract: <see cref="Seal"/>
/// must be authenticated encryption that binds <c>aad</c>, and <see cref="Open"/>
/// must throw on any modification. The key is fresh per layer per envelope — never
/// reuse it. To compose several ciphers into one layer, subclass <see cref="CascadeLayer"/>.</para>
/// <code>
/// sealed class MyLayer : ProtectionLayer
/// {
///     public override int Id => 200;
///     public override string WireName => "my-xchacha";
///     public override byte[] Seal(byte[] key, byte[] aad, byte[] pt) => CryptoLib.XChaCha20Encrypt(pt, key, aad);
///     public override byte[] Open(byte[] key, byte[] aad, byte[] ct) => CryptoLib.XChaCha20Decrypt(ct, key, aad);
/// }
/// ProtectionLayer.Register(new MyLayer());
/// </code>
/// </remarks>
public abstract class ProtectionLayer
{
    /// <summary>Recorded in the envelope header. Built-ins use 1–4; custom 128–255.</summary>
    public abstract int Id { get; }
    /// <summary>Feeds this layer's HKDF info string. Part of the wire format.</summary>
    public abstract string WireName { get; }
    /// <summary>Authenticated encryption under a fresh 32-byte key, binding <paramref name="aad"/>.</summary>
    public abstract byte[] Seal(byte[] key, byte[] aad, byte[] plaintext);
    /// <summary>The inverse of <see cref="Seal"/>; must throw on any modification.</summary>
    public abstract byte[] Open(byte[] key, byte[] aad, byte[] ciphertext);

    /// <summary>XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.</summary>
    public static readonly ProtectionLayer XChaCha20Poly1305 =
        new BuiltinLayer(1, "xchacha20Poly1305", CryptoLib.XChaCha20Encrypt, CryptoLib.XChaCha20Decrypt);
    /// <summary>AES-256-GCM. A different cipher family from ChaCha.</summary>
    public static readonly ProtectionLayer Aes256Gcm =
        new BuiltinLayer(2, "aes256Gcm", CryptoLib.Aes256GcmEncrypt, CryptoLib.Aes256GcmDecrypt);
    /// <summary>Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.</summary>
    public static readonly ProtectionLayer Committing =
        new BuiltinLayer(3, "committing", CryptoLib.CommittingEncrypt, CryptoLib.CommittingDecrypt);
    /// <summary>A full MolecularVault (cascade + committing) nested as one layer.</summary>
    public static readonly ProtectionLayer Molecular =
        new BuiltinLayer(4, "molecular", CryptoLib.MolecularSealWithKey, CryptoLib.MolecularOpenWithKey);

    private static readonly Dictionary<int, ProtectionLayer> Registry = new()
    {
        [1] = XChaCha20Poly1305, [2] = Aes256Gcm, [3] = Committing, [4] = Molecular,
    };

    /// <summary>
    /// Make a custom layer resolvable by id when opening. Required on both the
    /// sealing and the opening side. Re-registering an id under a different
    /// <see cref="WireName"/> is refused.
    /// </summary>
    public static void Register(ProtectionLayer layer)
    {
        PartIds.RequireValid(layer, layer.Id, "layer");
        lock (Registry)
        {
            if (Registry.TryGetValue(layer.Id, out var existing) && existing.WireName != layer.WireName)
                throw new InvalidOperationException(
                    $"cryptolib: layer id {layer.Id} is already registered as '{existing.WireName}'");
            Registry[layer.Id] = layer;
        }
    }

    internal static ProtectionLayer FromId(int id)
    {
        lock (Registry)
        {
            return Registry.TryGetValue(id, out var l) ? l : throw new CryptoLibException(
                $"cryptolib: unknown protection layer id {id} — ProtectionLayer.Register it before opening");
        }
    }

    /// <inheritdoc/>
    public override string ToString() => WireName;

    private sealed class BuiltinLayer : ProtectionLayer, IBuiltin
    {
        private readonly Func<byte[], byte[], byte[], byte[]> _enc, _dec;
        public BuiltinLayer(int id, string wireName, Func<byte[], byte[], byte[], byte[]> enc,
                            Func<byte[], byte[], byte[], byte[]> dec)
        { Id = id; WireName = wireName; _enc = enc; _dec = dec; }
        public override int Id { get; }
        public override string WireName { get; }
        public override byte[] Seal(byte[] key, byte[] aad, byte[] pt) => _enc(pt, key, aad);
        public override byte[] Open(byte[] key, byte[] aad, byte[] ct) => _dec(ct, key, aad);
    }
}

/// <summary>
/// A layer that is itself a mixture of layers — the way to compose several
/// encryptions into one custom type. Subclass it, or instantiate it directly.
/// </summary>
/// <remarks>
/// <code>
/// sealed class BeltAndBraces : CascadeLayer
/// {
///     public BeltAndBraces() : base(201, "belt-and-braces",
///         new[] { ProtectionLayer.XChaCha20Poly1305, new MyLayer() }) { }
/// }
/// </code>
/// Each inner layer receives its own sub-key, HKDF-derived from this layer's key
/// under the inner index and <see cref="ProtectionLayer.WireName"/>, so nesting
/// never collapses two ciphers onto one key. The AAD is bound by every inner
/// layer. Cascades nest.
/// </remarks>
public class CascadeLayer : ProtectionLayer
{
    private readonly int _id;
    private readonly string _wireName;

    /// <summary>The inner layers, innermost first.</summary>
    public IReadOnlyList<ProtectionLayer> Layers { get; }

    public CascadeLayer(int id, string wireName, IEnumerable<ProtectionLayer> layers)
    {
        var list = new List<ProtectionLayer>(layers);
        if (list.Count == 0) throw new ArgumentException($"cryptolib: CascadeLayer '{wireName}' has no layers", nameof(layers));
        _id = id; _wireName = wireName; Layers = list;
    }

    public sealed override int Id => _id;
    public sealed override string WireName => _wireName;

    private byte[] SubKey(byte[] key, int i)
        => CryptoLib.HkdfDerive(key, Array.Empty<byte>(),
                                Encoding.UTF8.GetBytes($"{_wireName}/{i}/{Layers[i].WireName}"), 32);

    public override byte[] Seal(byte[] key, byte[] aad, byte[] plaintext)
    {
        var body = plaintext;
        for (var i = 0; i < Layers.Count; i++) body = Layers[i].Seal(SubKey(key, i), aad, body);
        return body;
    }

    public override byte[] Open(byte[] key, byte[] aad, byte[] ciphertext)
    {
        var body = ciphertext;
        for (var i = Layers.Count - 1; i >= 0; i--) body = Layers[i].Open(SubKey(key, i), aad, body);
        return body;
    }
}

/// <summary>Where a <see cref="Recipe"/>'s 32-byte root key comes from.</summary>
/// <remarks>
/// Subclass it for a hardware token, a KMS, a keyring unlock — anything that can
/// produce the same 32 bytes again when opening. The recipe refuses any other
/// length. Ids 0–127 are reserved; custom sources must use 128–255.
/// </remarks>
public abstract class KeySource
{
    /// <summary>Recorded in the envelope header. Built-ins use 0–2; custom 128–255.</summary>
    public abstract int Id { get; }
    /// <summary>Human-readable name, used by <see cref="Recipe.Describe"/>.</summary>
    public abstract string Label { get; }
    /// <summary>
    /// Produce the root key. <paramref name="salt"/> is fresh per envelope; the
    /// Argon2id cost is the recipe's, for sources that stretch a weak input.
    /// </summary>
    public abstract byte[] DeriveRoot(byte[] salt, ulong argon2Ops, ulong argon2Memory);
}

/// <summary>A 32-byte full-entropy key used as-is (KEM secret, keyring unlock, token).</summary>
public sealed class RawKeySource : KeySource, IBuiltin
{
    private readonly byte[] _key;
    public RawKeySource(byte[] key)
    {
        if (key.Length != 32)
            throw new ArgumentException($"cryptolib: root key must be exactly 32 bytes, got {key.Length}", nameof(key));
        _key = (byte[])key.Clone();
    }
    public override int Id => 0;
    public override string Label => "raw";
    public override byte[] DeriveRoot(byte[] salt, ulong ops, ulong memory) => _key;
}

/// <summary>A passphrase stretched with Argon2id at the recipe's cost.</summary>
public sealed class PassphraseKeySource : KeySource, IBuiltin
{
    private readonly string _passphrase;
    public PassphraseKeySource(string passphrase) => _passphrase = passphrase;
    public override int Id => 1;
    public override string Label => "passphrase";
    public override byte[] DeriveRoot(byte[] salt, ulong ops, ulong memory)
        => CryptoLib.Argon2idDerive(_passphrase, salt, 32, ops, memory);
}

/// <summary>
/// The key derived deterministically from a media file — "the file is the key".
/// Uses the reproducible entropy path; KeyFromFile mixes in fresh system entropy
/// and so could never reopen its own envelope.
/// </summary>
public sealed class KeyFileSource : KeySource, IBuiltin
{
    private readonly string _path;
    public KeyFileSource(string path) => _path = path;
    public override int Id => 2;
    public override string Label => "keyFile";
    public override byte[] DeriveRoot(byte[] salt, ulong ops, ulong memory) => CryptoLib.KeyFromFileDeterministic(_path);
}

/// <summary>How a <see cref="Recipe"/> signs and verifies the plaintext.</summary>
/// <remarks>
/// Subclass it for another algorithm; a scheme holding only a public key should
/// throw from <see cref="Sign"/>. The signature is applied before encryption, so
/// it stays confidential. Custom schemes are verified only through
/// <see cref="Recipe.VerifiedWith"/>.
/// </remarks>
public abstract class SignatureScheme
{
    /// <summary>Recorded in the envelope header. Built-ins use 1–2; custom 128–255.</summary>
    public abstract int Id { get; }
    /// <summary>Human-readable name, used by <see cref="Recipe.Describe"/>.</summary>
    public abstract string Label { get; }
    public abstract byte[] Sign(byte[] message);
    public abstract bool Verify(byte[] message, byte[] signature);
}

/// <summary>Ed25519. Pass the secret key to sign, the public key to verify, or both.</summary>
public sealed class Ed25519Signature : SignatureScheme, IBuiltin
{
    private readonly byte[]? _sk, _pk;
    public Ed25519Signature(byte[]? secretKey = null, byte[]? publicKey = null)
    { _sk = (byte[]?)secretKey?.Clone(); _pk = (byte[]?)publicKey?.Clone(); }
    public override int Id => 1;
    public override string Label => "ed25519";
    public override byte[] Sign(byte[] m)
        => CryptoLib.Ed25519Sign(m, _sk ?? throw new CryptoLibException("cryptolib: Ed25519Signature has no secret key"));
    public override bool Verify(byte[] m, byte[] sig) => _pk is not null && CryptoLib.Ed25519Verify(m, sig, _pk);
}

/// <summary>Ed25519 + ML-DSA-65. A forgery needs breaking both families.</summary>
public sealed class HybridSignature : SignatureScheme, IBuiltin
{
    private readonly byte[]? _sk, _pk;
    public HybridSignature(byte[]? secretKey = null, byte[]? publicKey = null)
    { _sk = (byte[]?)secretKey?.Clone(); _pk = (byte[]?)publicKey?.Clone(); }
    public override int Id => 2;
    public override string Label => "hybrid";
    public override byte[] Sign(byte[] m)
        => CryptoLib.HybridSigSign(m, _sk ?? throw new CryptoLibException("cryptolib: HybridSignature has no secret key"));
    public override bool Verify(byte[] m, byte[] sig) => _pk is not null && CryptoLib.HybridSigVerify(m, sig, _pk);
}

/// <summary>Built-in scheme selector for the <see cref="Recipe.SignedBy"/> shorthand.</summary>
public enum SignatureAlgorithm
{
    /// <summary>No signature. The AEAD still guarantees integrity, but not who sent it.</summary>
    None = 0,
    /// <summary>Ed25519.</summary>
    Ed25519 = 1,
    /// <summary>Ed25519 + ML-DSA-65. A forgery needs breaking both families.</summary>
    Hybrid = 2,
}

/// <summary>Forward-error-correction scheme applied to a finished envelope.</summary>
public enum FecScheme
{
    /// <summary>No redundancy. Full capacity, no error tolerance.</summary>
    None = 0,
    /// <summary>Each bit repeated 3x; corrects 1 error per triple.</summary>
    Repetition3 = 1,
    /// <summary>Each bit repeated 5x; corrects 2 errors per group.</summary>
    Repetition5 = 2,
    /// <summary>Hamming(7,4): corrects 1 error per 7-bit block.</summary>
    Hamming74 = 3,
}

/// <summary>Per-profile algorithm parameters.</summary>
public static class SecurityProfileExtensions
{
    /// <summary>ML-KEM parameter set (0 = 512, 1 = 768, 2 = 1024).</summary>
    public static int MlKemLevel(this SecurityProfile p) => p == SecurityProfile.Maximum ? 2 : 1;
    /// <summary>ML-DSA parameter set (0 = 44, 1 = 65, 2 = 87).</summary>
    public static int MlDsaLevel(this SecurityProfile p) => p == SecurityProfile.Maximum ? 2 : 1;
    /// <summary>SLH-DSA parameter set; Maximum takes the small-signature 256-bit variant.</summary>
    public static int SlhDsaLevel(this SecurityProfile p) => p switch
    {
        SecurityProfile.Maximum => 4, SecurityProfile.High => 3, _ => 1,
    };
    /// <summary>SLH-DSA hash family (0 = SHA-2, 1 = SHAKE).</summary>
    public static int SlhDsaHash(this SecurityProfile p) => p == SecurityProfile.Maximum ? 1 : 0;
    /// <summary>Sealed-messaging tier (0 = Flagship, 1 = Fortress).</summary>
    public static int SealedTier(this SecurityProfile p) => p == SecurityProfile.Maximum ? 1 : 0;
    /// <summary>Argon2id preset for vault and keyring slots (0 = interactive, 1 = sensitive).</summary>
    public static int KdfPreset(this SecurityProfile p) => p == SecurityProfile.Balanced ? 0 : 1;
    /// <summary>Argon2id iteration count used by <see cref="Recipe"/>.</summary>
    public static ulong Argon2Ops(this SecurityProfile p) => p switch
    {
        SecurityProfile.Maximum => 4UL, SecurityProfile.High => 3UL, _ => 2UL,
    };
    /// <summary>
    /// Argon2id memory cost in bytes. Memory is what actually costs an attacker;
    /// raise it as far as the slowest device you must support can bear.
    /// </summary>
    public static ulong Argon2Memory(this SecurityProfile p) => p switch
    {
        SecurityProfile.Maximum => 512UL * 1024 * 1024,
        SecurityProfile.High => 256UL * 1024 * 1024,
        _ => 64UL * 1024 * 1024,
    };
    /// <summary>The AEAD layers this profile applies, innermost first.</summary>
    public static ProtectionLayer[] Cascade(this SecurityProfile p) => p switch
    {
        SecurityProfile.Maximum => new[]
        {
            ProtectionLayer.XChaCha20Poly1305, ProtectionLayer.Aes256Gcm, ProtectionLayer.Committing,
        },
        SecurityProfile.High => new[] { ProtectionLayer.XChaCha20Poly1305, ProtectionLayer.Aes256Gcm },
        _ => new[] { ProtectionLayer.XChaCha20Poly1305 },
    };
}

/// <summary>
/// A composable protection pipeline.
/// </summary>
/// <remarks>
/// <para>Describe what you want once, then <see cref="Seal"/> and <see cref="Open"/>
/// with the same recipe. The envelope carries its own descriptor, so opening does
/// not depend on remembering which layers were used — only on holding the key.</para>
/// <para>Composition only — every step is an existing, vetted operation. What the
/// recipe adds is the plumbing that is easy to get wrong by hand: every layer is
/// keyed by HKDF under a distinct info string so no key is reused, the header is
/// authenticated as AAD by every layer, the order (sign → encrypt → correct →
/// conceal) is fixed, and everything fails closed.</para>
/// <para>The envelope is a library-native format, identical across every CryptoLib
/// binding: one sealed here opens in Dart, Go, Node, Swift, Java, Python, Ruby or
/// Rust.</para>
/// </remarks>
public sealed class Recipe
{
    private static readonly byte[] Magic = "CLRC"u8.ToArray();
    private static readonly byte[] FecMagic = "CLFC"u8.ToArray();
    private const byte Version = 1;
    private const int SaltLen = 16;

    private readonly SecurityProfile _profile;
    private List<ProtectionLayer> _layers;
    private KeySource? _source;
    private SignatureScheme? _signer;
    private SignatureScheme? _verifier;
    private byte[]? _verifierKey;
    private FecScheme _fec = FecScheme.None;
    private ulong _argonOps;
    private ulong _argonMemory;

    internal Recipe(SecurityProfile profile)
    {
        _profile = profile;
        _layers = new List<ProtectionLayer>(profile.Cascade());
        _argonOps = profile.Argon2Ops();
        _argonMemory = profile.Argon2Memory();
    }

    /// <summary>Use any <see cref="KeySource"/> — a built-in or your own subclass.</summary>
    public Recipe WithKeySource(KeySource source)
    {
        PartIds.RequireValid(source, source.Id, "key source");
        _source = source; return this;
    }

    /// <summary>Derive the root key from a passphrase with Argon2id.</summary>
    public Recipe WithPassphrase(string passphrase) => WithKeySource(new PassphraseKeySource(passphrase));

    /// <summary>
    /// Use a 32-byte full-entropy key directly (KEM secret, keyring unlock, token).
    /// Nothing is stretched.
    /// </summary>
    public Recipe WithKey(byte[] key) => WithKeySource(new RawKeySource(key));

    /// <summary>
    /// Derive the root key deterministically from a media file — "the file is the
    /// key". The same file always yields the same key on any machine.
    /// </summary>
    public Recipe WithKeyFile(string path) => WithKeySource(new KeyFileSource(path));

    /// <summary>Replace the cascade with exactly these layers, innermost first.</summary>
    public Recipe WithLayers(IEnumerable<ProtectionLayer> layers)
    {
        var list = new List<ProtectionLayer>(layers);
        if (list.Count == 0) throw new ArgumentException("cryptolib: a recipe needs at least one layer", nameof(layers));
        foreach (var l in list) PartIds.RequireValid(l, l.Id, "layer");
        _layers = list; return this;
    }

    /// <summary>Append one more layer on the outside of the current cascade.</summary>
    public Recipe AddLayer(ProtectionLayer layer)
    {
        PartIds.RequireValid(layer, layer.Id, "layer");
        _layers.Add(layer); return this;
    }

    /// <summary>Override the Argon2id cost. Only meaningful with <see cref="WithPassphrase"/>.</summary>
    public Recipe Argon2Cost(ulong ops, ulong memoryBytes) { _argonOps = ops; _argonMemory = memoryBytes; return this; }

    /// <summary>Sign with any <see cref="SignatureScheme"/> — a built-in or your own subclass.</summary>
    public Recipe SignedWith(SignatureScheme scheme)
    {
        PartIds.RequireValid(scheme, scheme.Id, "signature scheme");
        _signer = scheme; return this;
    }

    /// <summary>Verify with any <see cref="SignatureScheme"/>. Required for a custom scheme.</summary>
    public Recipe VerifiedWith(SignatureScheme scheme)
    {
        PartIds.RequireValid(scheme, scheme.Id, "signature scheme");
        _verifier = scheme; _verifierKey = null; return this;
    }

    /// <summary>
    /// Sign the plaintext before it is encrypted with a built-in scheme, so the
    /// signature stays confidential and proves who produced it.
    /// </summary>
    public Recipe SignedBy(byte[] secretKey, SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519) => algorithm switch
    {
        SignatureAlgorithm.Ed25519 => SignedWith(new Ed25519Signature(secretKey: secretKey)),
        SignatureAlgorithm.Hybrid => SignedWith(new HybridSignature(secretKey: secretKey)),
        _ => throw new ArgumentException("cryptolib: SignedBy needs a real algorithm", nameof(algorithm)),
    };

    /// <summary>
    /// The public key <see cref="Open"/> must verify against. Works for either
    /// built-in scheme — the envelope records which one. A custom
    /// <see cref="SignatureScheme"/> must be supplied through <see cref="VerifiedWith"/>.
    /// </summary>
    public Recipe VerifiedBy(byte[] publicKey) { _verifier = null; _verifierKey = (byte[])publicKey.Clone(); return this; }

    /// <summary>Apply forward error correction to the finished envelope.</summary>
    public Recipe WithFec(FecScheme scheme) { _fec = scheme; return this; }

    /// <summary>A human-readable summary — handy in logs and code review.</summary>
    public string Describe()
    {
        var names = string.Join(" -> ", _layers.ConvertAll(l => l.WireName));
        var sb = new StringBuilder()
            .Append($"Recipe({_profile.ToString().ToLowerInvariant()})\n")
            .Append($"  key      : {_source?.Label ?? "(unset)"}\n")
            .Append($"  layers   : {names}\n")
            .Append($"  signature: {_signer?.Label ?? "none"}\n")
            .Append($"  fec      : {(int)_fec}\n");
        if (_source is PassphraseKeySource) sb.Append($"  argon2id : ops={_argonOps}, mem={_argonMemory / (1024 * 1024)}MiB\n");
        return sb.ToString();
    }

    /// <summary>Protect <paramref name="plaintext"/> and return the envelope.</summary>
    public byte[] Seal(byte[] plaintext)
    {
        var source = RequireSource();
        var salt = CryptoLib.RandomBytes(SaltLen);
        var header = BuildHeader(source, salt);
        var root = RootKey(source, salt, _argonOps, _argonMemory);

        var body = plaintext;
        if (_signer is not null) body = PrefixLengthed(_signer.Sign(plaintext), plaintext);
        for (var i = 0; i < _layers.Count; i++)
            body = ApplyLayer(_layers[i], i, root, salt, header, body, seal: true);

        var envelope = new byte[header.Length + body.Length];
        header.CopyTo(envelope, 0);
        body.CopyTo(envelope, header.Length);
        return _fec == FecScheme.None ? envelope : WrapFec(envelope);
    }

    /// <summary>
    /// Recover the plaintext. Throws if the key is wrong, a byte was altered, or a
    /// signature is present but does not verify.
    /// </summary>
    public byte[] Open(byte[] envelope)
    {
        var source = RequireSource();
        var inner = UnwrapFec(envelope);
        var (header, layers, salt, signatureId, ops, memory) = ParseHeader(inner, source);
        var root = RootKey(source, salt, ops, memory);

        var body = inner[header.Length..];
        for (var i = layers.Count - 1; i >= 0; i--)
            body = ApplyLayer(layers[i], i, root, salt, header, body, seal: false);

        if (signatureId == 0) return body;

        if (body.Length < 4) throw new CryptoLibException("cryptolib: malformed signed payload");
        var n = (int)BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(0, 4));
        if (n < 0 || body.Length < 4 + n) throw new CryptoLibException("cryptolib: malformed signed payload");
        var sig = body[4..(4 + n)];
        var plaintext = body[(4 + n)..];
        var verifier = _verifier ?? BuiltinVerifier(signatureId);
        if (verifier is null)
        {
            if (_verifierKey is not null)
                throw new CryptoLibException(
                    $"cryptolib: envelope was signed with scheme id {signatureId}, which is not a built-in — "
                    + "supply that SignatureScheme with VerifiedWith");
            throw new CryptoLibException(
                "cryptolib: envelope is signed but no verifier was supplied — "
                + "call VerifiedBy/VerifiedWith so the signature is actually checked");
        }
        if (verifier.Id != signatureId)
            throw new CryptoLibException(
                $"cryptolib: envelope was signed with scheme id {signatureId}, but the verifier is '{verifier.Label}' (id {verifier.Id})");
        if (!verifier.Verify(plaintext, sig)) throw new CryptoLibException("cryptolib: signature verification failed");
        return plaintext;
    }

    /// <summary>
    /// Seal and hide the envelope inside a carrier. Defence-in-depth, never the
    /// confidentiality boundary — the envelope is already authenticated-encrypted.
    /// </summary>
    public void SealIntoCarrier(byte[] plaintext, string coverPath, string outputPath)
        => CryptoLib.StegoEmbed(coverPath, Seal(plaintext), outputPath);

    /// <summary>Extract and open an envelope written by <see cref="SealIntoCarrier"/>.</summary>
    public byte[] OpenFromCarrier(string stegoPath) => Open(CryptoLib.StegoExtract(stegoPath));

    // ── internals ────────────────────────────────────────────────────────────

    private KeySource RequireSource()
        => _source ?? throw new CryptoLibException("cryptolib: no key set — call WithKey/WithPassphrase/WithKeyFile/WithKeySource");

    private SignatureScheme? BuiltinVerifier(int id) => _verifierKey is null ? null : id switch
    {
        1 => new Ed25519Signature(publicKey: _verifierKey),
        2 => new HybridSignature(publicKey: _verifierKey),
        _ => null,
    };

    private static byte[] RootKey(KeySource source, byte[] salt, ulong ops, ulong memory)
    {
        var root = source.DeriveRoot(salt, ops, memory);
        if (root is null || root.Length != 32)
            throw new CryptoLibException(
                $"cryptolib: key source '{source.Label}' produced {root?.Length ?? 0} bytes; the root key must be exactly 32");
        return root;
    }

    /// <summary>HKDF under a distinct info string, so no two layers share key material.</summary>
    private static byte[] LayerKey(byte[] root, byte[] salt, int index, ProtectionLayer layer)
        => CryptoLib.HkdfDerive(root, salt,
                                Encoding.UTF8.GetBytes($"cryptolib/recipe/v1/layer{index}/{layer.WireName}"), 32);

    private static byte[] ApplyLayer(ProtectionLayer layer, int index, byte[] root, byte[] salt,
                                     byte[] header, byte[] data, bool seal)
    {
        var key = LayerKey(root, salt, index, layer);
        return seal ? layer.Seal(key, header, data) : layer.Open(key, header, data);
    }

    private byte[] BuildHeader(KeySource source, byte[] salt)
    {
        var outBytes = new List<byte>(8 + _layers.Count + SaltLen + 8);
        outBytes.AddRange(Magic);
        outBytes.Add(Version);
        outBytes.Add((byte)source.Id);
        outBytes.Add((byte)(_signer?.Id ?? 0));
        outBytes.Add((byte)_layers.Count);
        foreach (var l in _layers) outBytes.Add((byte)l.Id);
        outBytes.AddRange(salt);
        var costs = new byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(costs.AsSpan(0, 4), (uint)_argonOps);
        BinaryPrimitives.WriteUInt32BigEndian(costs.AsSpan(4, 4), (uint)_argonMemory);
        outBytes.AddRange(costs);
        return outBytes.ToArray();
    }

    private static (byte[] header, List<ProtectionLayer> layers, byte[] salt,
                    int signatureId, ulong ops, ulong memory) ParseHeader(byte[] env, KeySource source)
    {
        if (env.Length < 8 + SaltLen + 8) throw new CryptoLibException("cryptolib: envelope too short");
        for (var i = 0; i < 4; i++)
            if (env[i] != Magic[i]) throw new CryptoLibException("cryptolib: not a CryptoRecipe envelope");
        if (env[4] != Version) throw new CryptoLibException($"cryptolib: unsupported envelope version {env[4]}");
        int src = env[5];
        if (src != source.Id)
            throw new CryptoLibException(
                $"cryptolib: envelope was sealed with key source id {src}, "
                + $"but this recipe is configured for '{source.Label}' (id {source.Id})");
        int signatureId = env[6];
        int count = env[7];
        var headerLen = 8 + count + SaltLen + 8;
        if (env.Length < headerLen) throw new CryptoLibException("cryptolib: truncated envelope header");
        var layers = new List<ProtectionLayer>(count);
        for (var i = 0; i < count; i++) layers.Add(ProtectionLayer.FromId(env[8 + i]));
        var salt = env[(8 + count)..(8 + count + SaltLen)];
        var costs = env.AsSpan(8 + count + SaltLen, 8);
        return (env[..headerLen], layers, salt, signatureId,
                BinaryPrimitives.ReadUInt32BigEndian(costs[..4]),
                BinaryPrimitives.ReadUInt32BigEndian(costs[4..]));
    }

    private byte[] WrapFec(byte[] envelope)
    {
        var encoded = CryptoLib.FecEncode(envelope, (int)_fec);
        var outBytes = new List<byte>(9 + encoded.Length);
        outBytes.AddRange(FecMagic);
        outBytes.Add((byte)_fec);
        var len = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)envelope.Length);
        outBytes.AddRange(len);
        outBytes.AddRange(encoded);
        return outBytes.ToArray();
    }

    private static byte[] UnwrapFec(byte[] data)
    {
        if (data.Length < 9) return data;
        for (var i = 0; i < 4; i++) if (data[i] != FecMagic[i]) return data;
        var scheme = (int)data[4];
        var originalLen = (int)BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(5, 4));
        return CryptoLib.FecDecode(data[9..], scheme, originalLen);
    }

    private static byte[] PrefixLengthed(byte[] prefix, byte[] rest)
    {
        var outBytes = new byte[4 + prefix.Length + rest.Length];
        BinaryPrimitives.WriteUInt32BigEndian(outBytes.AsSpan(0, 4), (uint)prefix.Length);
        prefix.CopyTo(outBytes, 4);
        rest.CopyTo(outBytes, 4 + prefix.Length);
        return outBytes;
    }
}
