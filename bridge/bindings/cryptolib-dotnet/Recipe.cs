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

/// <summary>One authenticated-encryption layer in a <see cref="Recipe"/> cascade.</summary>
public enum ProtectionLayer
{
    /// <summary>XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.</summary>
    XChaCha20Poly1305 = 1,
    /// <summary>AES-256-GCM. A different cipher family from ChaCha.</summary>
    Aes256Gcm = 2,
    /// <summary>Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.</summary>
    Committing = 3,
    /// <summary>A full MolecularVault (cascade + committing) nested as one layer.</summary>
    Molecular = 4,
}

/// <summary>Origin-authentication algorithm for a <see cref="Recipe"/>.</summary>
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

    /// <summary>
    /// Name used in a layer's HKDF info string. Pinned explicitly rather than
    /// derived from the enum member: it is part of the wire format, so renaming
    /// must not change how keys are derived — envelopes are opened by other
    /// language bindings too.
    /// </summary>
    public static string WireName(this ProtectionLayer l) => l switch
    {
        ProtectionLayer.XChaCha20Poly1305 => "xchacha20Poly1305",
        ProtectionLayer.Aes256Gcm => "aes256Gcm",
        ProtectionLayer.Committing => "committing",
        ProtectionLayer.Molecular => "molecular",
        _ => throw new CryptoLibException($"cryptolib: unknown protection layer {(int)l}"),
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
    private static readonly string[] SourceName = { "raw", "passphrase", "keyFile" };

    private readonly SecurityProfile _profile;
    private List<ProtectionLayer> _layers;
    private byte _source;
    private byte[]? _rawKey;
    private string? _passphrase;
    private string? _keyFile;
    private SignatureAlgorithm _signAlgorithm = SignatureAlgorithm.None;
    private byte[]? _signSecret;
    private byte[]? _signPublic;
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

    /// <summary>Derive the root key from a passphrase with Argon2id.</summary>
    public Recipe WithPassphrase(string passphrase) { _source = 1; _passphrase = passphrase; return this; }

    /// <summary>
    /// Use a 32-byte full-entropy key directly (KEM secret, keyring unlock, token).
    /// Nothing is stretched.
    /// </summary>
    public Recipe WithKey(byte[] key)
    {
        if (key.Length != 32)
            throw new ArgumentException($"cryptolib: root key must be exactly 32 bytes, got {key.Length}", nameof(key));
        _source = 0; _rawKey = (byte[])key.Clone(); return this;
    }

    /// <summary>
    /// Derive the root key deterministically from a media file — "the file is the
    /// key". The same file always yields the same key on any machine.
    /// </summary>
    public Recipe WithKeyFile(string path) { _source = 2; _keyFile = path; return this; }

    /// <summary>Replace the cascade with exactly these layers, innermost first.</summary>
    public Recipe WithLayers(IEnumerable<ProtectionLayer> layers)
    {
        var list = new List<ProtectionLayer>(layers);
        if (list.Count == 0) throw new ArgumentException("cryptolib: a recipe needs at least one layer", nameof(layers));
        _layers = list; return this;
    }

    /// <summary>Append one more layer on the outside of the current cascade.</summary>
    public Recipe AddLayer(ProtectionLayer layer) { _layers.Add(layer); return this; }

    /// <summary>Override the Argon2id cost. Only meaningful with <see cref="WithPassphrase"/>.</summary>
    public Recipe Argon2Cost(ulong ops, ulong memoryBytes) { _argonOps = ops; _argonMemory = memoryBytes; return this; }

    /// <summary>
    /// Sign the plaintext before it is encrypted, so the signature stays
    /// confidential and proves who produced it.
    /// </summary>
    public Recipe SignedBy(byte[] secretKey, SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519)
    {
        if (algorithm == SignatureAlgorithm.None)
            throw new ArgumentException("cryptolib: SignedBy needs a real algorithm", nameof(algorithm));
        _signAlgorithm = algorithm; _signSecret = (byte[])secretKey.Clone(); return this;
    }

    /// <summary>
    /// The public key <see cref="Open"/> must verify against. Required whenever the
    /// envelope is signed: otherwise there would be a signature and nobody checking it.
    /// </summary>
    public Recipe VerifiedBy(byte[] publicKey) { _signPublic = (byte[])publicKey.Clone(); return this; }

    /// <summary>Apply forward error correction to the finished envelope.</summary>
    public Recipe WithFec(FecScheme scheme) { _fec = scheme; return this; }

    /// <summary>A human-readable summary — handy in logs and code review.</summary>
    public string Describe()
    {
        var names = string.Join(" -> ", _layers.ConvertAll(l => l.WireName()));
        var sb = new StringBuilder()
            .Append($"Recipe({_profile.ToString().ToLowerInvariant()})\n")
            .Append($"  key      : {SourceName[_source]}\n")
            .Append($"  layers   : {names}\n")
            .Append($"  signature: {_signAlgorithm.ToString().ToLowerInvariant()}\n")
            .Append($"  fec      : {(int)_fec}\n");
        if (_source == 1) sb.Append($"  argon2id : ops={_argonOps}, mem={_argonMemory / (1024 * 1024)}MiB\n");
        return sb.ToString();
    }

    /// <summary>Protect <paramref name="plaintext"/> and return the envelope.</summary>
    public byte[] Seal(byte[] plaintext)
    {
        var salt = CryptoLib.RandomBytes(SaltLen);
        var header = BuildHeader(salt);
        var root = RootKey(salt, _argonOps, _argonMemory);

        var body = plaintext;
        if (_signAlgorithm != SignatureAlgorithm.None)
        {
            if (_signSecret is null) throw new CryptoLibException("cryptolib: signing requested without a secret key");
            var sig = _signAlgorithm == SignatureAlgorithm.Ed25519
                ? CryptoLib.Ed25519Sign(plaintext, _signSecret)
                : CryptoLib.HybridSigSign(plaintext, _signSecret);
            body = PrefixLengthed(sig, plaintext);
        }
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
        var inner = UnwrapFec(envelope);
        var (header, layers, salt, signAlgorithm, ops, memory) = ParseHeader(inner);
        var root = RootKey(salt, ops, memory);

        var body = inner[header.Length..];
        for (var i = layers.Count - 1; i >= 0; i--)
            body = ApplyLayer(layers[i], i, root, salt, header, body, seal: false);

        if (signAlgorithm == SignatureAlgorithm.None) return body;

        if (body.Length < 4) throw new CryptoLibException("cryptolib: malformed signed payload");
        var n = (int)BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(0, 4));
        if (n < 0 || body.Length < 4 + n) throw new CryptoLibException("cryptolib: malformed signed payload");
        var sig = body[4..(4 + n)];
        var plaintext = body[(4 + n)..];
        if (_signPublic is null)
            throw new CryptoLibException(
                "cryptolib: envelope is signed but no public key was supplied — "
                + "call VerifiedBy so the signature is actually checked");
        var ok = signAlgorithm == SignatureAlgorithm.Ed25519
            ? CryptoLib.Ed25519Verify(plaintext, sig, _signPublic)
            : CryptoLib.HybridSigVerify(plaintext, sig, _signPublic);
        if (!ok) throw new CryptoLibException("cryptolib: signature verification failed");
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

    private byte[] RootKey(byte[] salt, ulong ops, ulong memory) => _source switch
    {
        1 => CryptoLib.Argon2idDerive(_passphrase ?? throw new CryptoLibException("cryptolib: no passphrase set"),
                                      salt, 32, ops, memory),
        2 => CryptoLib.KeyFromFileDeterministic(_keyFile ?? throw new CryptoLibException("cryptolib: no key file set")),
        _ => _rawKey ?? throw new CryptoLibException(
                 "cryptolib: no key set — call WithKey/WithPassphrase/WithKeyFile"),
    };

    /// <summary>HKDF under a distinct info string, so no two layers share key material.</summary>
    private static byte[] LayerKey(byte[] root, byte[] salt, int index, ProtectionLayer layer)
        => CryptoLib.HkdfDerive(root, salt,
                                Encoding.UTF8.GetBytes($"cryptolib/recipe/v1/layer{index}/{layer.WireName()}"), 32);

    private static byte[] ApplyLayer(ProtectionLayer layer, int index, byte[] root, byte[] salt,
                                     byte[] header, byte[] data, bool seal)
    {
        var key = LayerKey(root, salt, index, layer);
        return layer switch
        {
            ProtectionLayer.XChaCha20Poly1305 => seal ? CryptoLib.XChaCha20Encrypt(data, key, header)
                                                      : CryptoLib.XChaCha20Decrypt(data, key, header),
            ProtectionLayer.Aes256Gcm => seal ? CryptoLib.Aes256GcmEncrypt(data, key, header)
                                              : CryptoLib.Aes256GcmDecrypt(data, key, header),
            ProtectionLayer.Committing => seal ? CryptoLib.CommittingEncrypt(data, key, header)
                                               : CryptoLib.CommittingDecrypt(data, key, header),
            ProtectionLayer.Molecular => seal ? CryptoLib.MolecularSealWithKey(data, key, header)
                                              : CryptoLib.MolecularOpenWithKey(data, key, header),
            _ => throw new CryptoLibException($"cryptolib: unknown protection layer {(int)layer}"),
        };
    }

    private byte[] BuildHeader(byte[] salt)
    {
        var outBytes = new List<byte>(8 + _layers.Count + SaltLen + 8);
        outBytes.AddRange(Magic);
        outBytes.Add(Version);
        outBytes.Add(_source);
        outBytes.Add((byte)_signAlgorithm);
        outBytes.Add((byte)_layers.Count);
        foreach (var l in _layers) outBytes.Add((byte)l);
        outBytes.AddRange(salt);
        var costs = new byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(costs.AsSpan(0, 4), (uint)_argonOps);
        BinaryPrimitives.WriteUInt32BigEndian(costs.AsSpan(4, 4), (uint)_argonMemory);
        outBytes.AddRange(costs);
        return outBytes.ToArray();
    }

    private (byte[] header, List<ProtectionLayer> layers, byte[] salt,
             SignatureAlgorithm sign, ulong ops, ulong memory) ParseHeader(byte[] env)
    {
        if (env.Length < 8 + SaltLen + 8) throw new CryptoLibException("cryptolib: envelope too short");
        for (var i = 0; i < 4; i++)
            if (env[i] != Magic[i]) throw new CryptoLibException("cryptolib: not a CryptoRecipe envelope");
        if (env[4] != Version) throw new CryptoLibException($"cryptolib: unsupported envelope version {env[4]}");
        var src = env[5];
        if (src != _source)
            throw new CryptoLibException(
                $"cryptolib: envelope was sealed with the {SourceName[src]} key source, "
                + $"but this recipe is configured for {SourceName[_source]}");
        var sign = (SignatureAlgorithm)env[6];
        int count = env[7];
        var headerLen = 8 + count + SaltLen + 8;
        if (env.Length < headerLen) throw new CryptoLibException("cryptolib: truncated envelope header");
        var layers = new List<ProtectionLayer>(count);
        for (var i = 0; i < count; i++)
        {
            var l = (ProtectionLayer)env[8 + i];
            _ = l.WireName(); // validates the id
            layers.Add(l);
        }
        var salt = env[(8 + count)..(8 + count + SaltLen)];
        var costs = env.AsSpan(8 + count + SaltLen, 8);
        return (env[..headerLen], layers, salt, sign,
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
