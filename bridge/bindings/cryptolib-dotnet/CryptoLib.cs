using System.Runtime.InteropServices;

namespace CryptoLibNet;

[StructLayout(LayoutKind.Sequential)]
internal struct CryptoBuffer { public IntPtr data; public nuint len; }

[StructLayout(LayoutKind.Sequential)]
internal struct CryptoKeyPair { public CryptoBuffer public_key; public CryptoBuffer secret_key; }

[StructLayout(LayoutKind.Sequential)]
internal struct CryptoKemEncapsResult { public CryptoBuffer ciphertext; public CryptoBuffer shared_secret; }

[StructLayout(LayoutKind.Sequential)]
internal struct CryptoBufferResult { public CryptoBuffer buf; public IntPtr error; }

[StructLayout(LayoutKind.Sequential)]
internal struct CryptoResult { public int ok; public IntPtr error; }

/// <summary>
/// CryptoLib P/Invoke binding. The native library is bundled per-RID under
/// runtimes/&lt;rid&gt;/native/ and resolved automatically — NuGet probes that
/// layout, and the resolver below mirrors it when used from a project.
/// </summary>
public static class CryptoLib
{
    private const string Lib = "cryptolib_c";

    static CryptoLib()
    {
        NativeLibrary.SetDllImportResolver(typeof(CryptoLib).Assembly, (name, asm, search) =>
        {
            if (name != Lib) return IntPtr.Zero;
            string rid = RuntimeInformation.RuntimeIdentifier; // e.g. osx-arm64
            string ext = RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "dylib"
                       : RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "dll" : "so";
            string p = Path.Combine(AppContext.BaseDirectory, "runtimes", rid, "native", $"libcryptolib_c.{ext}");
            return File.Exists(p) ? NativeLibrary.Load(p) : IntPtr.Zero;
        });
    }

    [DllImport(Lib)] private static extern int cryptolib_init();
    [DllImport(Lib)] private static extern IntPtr cryptolib_version();
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_sha256(byte[] msg, nuint len);
    [DllImport(Lib)] private static extern CryptoKeyPair cryptolib_hybrid_kem_keygen();
    [DllImport(Lib)] private static extern CryptoKemEncapsResult cryptolib_hybrid_kem_encapsulate(byte[] pk, nuint len, out IntPtr err);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_hybrid_kem_decapsulate(byte[] ct, nuint ctLen, byte[] sk, nuint skLen);
    [DllImport(Lib)] private static extern void cryptolib_buffer_free(ref CryptoBuffer buf);
    [DllImport(Lib)] private static extern void cryptolib_keypair_free(ref CryptoKeyPair kp);
    [DllImport(Lib)] private static extern void cryptolib_kem_encaps_free(ref CryptoKemEncapsResult r);
    [DllImport(Lib)] private static extern void cryptolib_str_free(IntPtr s);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_random_bytes(nuint n);

    // Primitives the composable Recipe pipeline is built from.
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_argon2id_derive(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string password, byte[] salt, nuint saltLen,
        nuint keyLen, ulong ops, nuint mem);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_hkdf_derive(
        byte[] ikm, nuint ikmLen, byte[] salt, nuint saltLen, byte[] info, nuint infoLen, nuint outLen);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_xchacha20_encrypt(byte[] pt, nuint ptLen, byte[] k, nuint kLen, byte[] aad, nuint aadLen);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_xchacha20_decrypt(byte[] ct, nuint ctLen, byte[] k, nuint kLen, byte[] aad, nuint aadLen);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_aes256gcm_encrypt(byte[] pt, nuint ptLen, byte[] k, nuint kLen, byte[] aad, nuint aadLen);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_aes256gcm_decrypt(byte[] ct, nuint ctLen, byte[] k, nuint kLen, byte[] aad, nuint aadLen);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_committing_encrypt(byte[] pt, nuint ptLen, byte[] k, nuint kLen, byte[] aad, nuint aadLen);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_committing_decrypt(byte[] ct, nuint ctLen, byte[] k, nuint kLen, byte[] aad, nuint aadLen);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_molecular_seal_with_key(byte[] pt, nuint ptLen, byte[] k, nuint kLen, byte[] aad, nuint aadLen);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_molecular_open_with_key(byte[] ct, nuint ctLen, byte[] k, nuint kLen, byte[] aad, nuint aadLen);
    [DllImport(Lib)] private static extern CryptoKeyPair cryptolib_ed25519_keygen();
    [DllImport(Lib)] private static extern CryptoKeyPair cryptolib_ed25519_keygen_from_seed(byte[] seed, nuint len);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_ed25519_sign(byte[] msg, nuint msgLen, byte[] sk, nuint skLen);
    [DllImport(Lib)] private static extern int cryptolib_ed25519_verify(byte[] msg, nuint msgLen, byte[] sig, nuint sigLen, byte[] pk, nuint pkLen);
    [DllImport(Lib)] private static extern CryptoKeyPair cryptolib_hybrid_sig_keygen();
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_hybrid_sig_sign(byte[] msg, nuint msgLen, byte[] sk, nuint skLen);
    [DllImport(Lib)] private static extern int cryptolib_hybrid_sig_verify(byte[] msg, nuint msgLen, byte[] sig, nuint sigLen, byte[] pk, nuint pkLen);
    [DllImport(Lib)] private static extern IntPtr cryptolib_entropy_from_file_deterministic(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_entropy_symmetric_key(IntPtr h);
    [DllImport(Lib)] private static extern void cryptolib_entropy_free(IntPtr h);
    [DllImport(Lib)] private static extern CryptoResult cryptolib_stego_embed(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cover, byte[] payload, nuint len,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outPath);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_stego_extract(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_fec_encode(byte[] data, nuint len, int scheme);
    [DllImport(Lib)] private static extern CryptoBufferResult cryptolib_fec_decode(byte[] data, nuint len, int scheme, nuint originalLen);

    private static byte[] Read(CryptoBuffer b)
    {
        if (b.data == IntPtr.Zero || b.len == 0) return Array.Empty<byte>();
        var outBytes = new byte[(int)b.len];
        Marshal.Copy(b.data, outBytes, 0, (int)b.len);
        return outBytes;
    }
    private static byte[] Consume(CryptoBufferResult r)
    {
        // An error is reported alongside an empty buffer; surface it rather than
        // silently returning nothing.
        if ((r.buf.data == IntPtr.Zero || r.buf.len == 0) && r.error != IntPtr.Zero)
        {
            var msg = Marshal.PtrToStringUTF8(r.error) ?? "cryptolib: unknown error";
            cryptolib_str_free(r.error);
            throw new CryptoLibException(msg);
        }
        var outBytes = Read(r.buf);
        var buf = r.buf; cryptolib_buffer_free(ref buf);
        return outBytes;
    }

    private static (byte[] pub, byte[] sec) Keypair(CryptoKeyPair kp)
    {
        var pub = Read(kp.public_key); var sec = Read(kp.secret_key);
        cryptolib_keypair_free(ref kp);
        return (pub, sec);
    }

    public static void Init() { if (cryptolib_init() != 0) throw new Exception("cryptolib init failed"); }
    public static string Version() => Marshal.PtrToStringUTF8(cryptolib_version()) ?? "";
    public static byte[] Sha256(byte[] msg) => Consume(cryptolib_sha256(msg, (nuint)msg.Length));

    public static (byte[] pub, byte[] sec) HybridKemKeygen()
    {
        var kp = cryptolib_hybrid_kem_keygen();
        var pub = Read(kp.public_key); var sec = Read(kp.secret_key);
        cryptolib_keypair_free(ref kp);
        return (pub, sec);
    }
    public static (byte[] ct, byte[] ss) HybridKemEncapsulate(byte[] pk)
    {
        var r = cryptolib_hybrid_kem_encapsulate(pk, (nuint)pk.Length, out _);
        var ct = Read(r.ciphertext); var ss = Read(r.shared_secret);
        cryptolib_kem_encaps_free(ref r);
        return (ct, ss);
    }
    public static byte[] HybridKemDecapsulate(byte[] ct, byte[] sk)
        => Consume(cryptolib_hybrid_kem_decapsulate(ct, (nuint)ct.Length, sk, (nuint)sk.Length));

    // ── Primitives used by Recipe ─────────────────────────────────────────────

    /// <summary><paramref name="n"/> cryptographically secure random bytes.</summary>
    public static byte[] RandomBytes(int n) => Consume(cryptolib_random_bytes((nuint)n));

    /// <summary>Stretch a passphrase into a key with Argon2id.</summary>
    public static byte[] Argon2idDerive(string password, byte[] salt, int keyLen, ulong ops, ulong memoryBytes)
        => Consume(cryptolib_argon2id_derive(password, salt, (nuint)salt.Length, (nuint)keyLen, ops, (nuint)memoryBytes));

    /// <summary>One-shot HKDF: extract + expand to <paramref name="outLen"/> bytes.</summary>
    public static byte[] HkdfDerive(byte[] ikm, byte[] salt, byte[] info, int outLen)
        => Consume(cryptolib_hkdf_derive(ikm, (nuint)ikm.Length, salt, (nuint)salt.Length,
                                         info, (nuint)info.Length, (nuint)outLen));

    /// <summary>XChaCha20-Poly1305 AEAD encryption.</summary>
    public static byte[] XChaCha20Encrypt(byte[] pt, byte[] key, byte[] aad)
        => Consume(cryptolib_xchacha20_encrypt(pt, (nuint)pt.Length, key, (nuint)key.Length, aad, (nuint)aad.Length));
    /// <summary>XChaCha20-Poly1305 AEAD decryption. Fails closed.</summary>
    public static byte[] XChaCha20Decrypt(byte[] ct, byte[] key, byte[] aad)
        => Consume(cryptolib_xchacha20_decrypt(ct, (nuint)ct.Length, key, (nuint)key.Length, aad, (nuint)aad.Length));
    /// <summary>AES-256-GCM AEAD encryption.</summary>
    public static byte[] Aes256GcmEncrypt(byte[] pt, byte[] key, byte[] aad)
        => Consume(cryptolib_aes256gcm_encrypt(pt, (nuint)pt.Length, key, (nuint)key.Length, aad, (nuint)aad.Length));
    /// <summary>AES-256-GCM AEAD decryption. Fails closed.</summary>
    public static byte[] Aes256GcmDecrypt(byte[] ct, byte[] key, byte[] aad)
        => Consume(cryptolib_aes256gcm_decrypt(ct, (nuint)ct.Length, key, (nuint)key.Length, aad, (nuint)aad.Length));
    /// <summary>Key-committing AEAD (UtC): binds the ciphertext to exactly one key.</summary>
    public static byte[] CommittingEncrypt(byte[] pt, byte[] key, byte[] aad)
        => Consume(cryptolib_committing_encrypt(pt, (nuint)pt.Length, key, (nuint)key.Length, aad, (nuint)aad.Length));
    /// <summary>Key-committing AEAD decryption. Fails closed.</summary>
    public static byte[] CommittingDecrypt(byte[] ct, byte[] key, byte[] aad)
        => Consume(cryptolib_committing_decrypt(ct, (nuint)ct.Length, key, (nuint)key.Length, aad, (nuint)aad.Length));
    /// <summary>MolecularVault cascade under a raw 32-byte master key.</summary>
    public static byte[] MolecularSealWithKey(byte[] pt, byte[] key, byte[] aad)
        => Consume(cryptolib_molecular_seal_with_key(pt, (nuint)pt.Length, key, (nuint)key.Length, aad, (nuint)aad.Length));
    /// <summary>Open a MolecularVault envelope. Fails closed.</summary>
    public static byte[] MolecularOpenWithKey(byte[] ct, byte[] key, byte[] aad)
        => Consume(cryptolib_molecular_open_with_key(ct, (nuint)ct.Length, key, (nuint)key.Length, aad, (nuint)aad.Length));

    /// <summary>Ed25519 keypair from the OS CSPRNG.</summary>
    public static (byte[] pub, byte[] sec) Ed25519Keygen() => Keypair(cryptolib_ed25519_keygen());
    /// <summary>Ed25519 keypair derived deterministically from a 32-byte seed.</summary>
    public static (byte[] pub, byte[] sec) Ed25519KeygenFromSeed(byte[] seed)
        => Keypair(cryptolib_ed25519_keygen_from_seed(seed, (nuint)seed.Length));
    /// <summary>Ed25519 signature. <paramref name="sk"/> is the 64-byte secret, not the seed.</summary>
    public static byte[] Ed25519Sign(byte[] msg, byte[] sk)
        => Consume(cryptolib_ed25519_sign(msg, (nuint)msg.Length, sk, (nuint)sk.Length));
    /// <summary>Verify an Ed25519 signature.</summary>
    public static bool Ed25519Verify(byte[] msg, byte[] sig, byte[] pk)
        => cryptolib_ed25519_verify(msg, (nuint)msg.Length, sig, (nuint)sig.Length, pk, (nuint)pk.Length) == 1;

    /// <summary>Ed25519 + ML-DSA-65 keypair: a forgery needs breaking both families.</summary>
    public static (byte[] pub, byte[] sec) HybridSigKeygen() => Keypair(cryptolib_hybrid_sig_keygen());
    /// <summary>Hybrid Ed25519 + ML-DSA-65 signature.</summary>
    public static byte[] HybridSigSign(byte[] msg, byte[] sk)
        => Consume(cryptolib_hybrid_sig_sign(msg, (nuint)msg.Length, sk, (nuint)sk.Length));
    /// <summary>Verify a hybrid signature; both legs must hold.</summary>
    public static bool HybridSigVerify(byte[] msg, byte[] sig, byte[] pk)
        => cryptolib_hybrid_sig_verify(msg, (nuint)msg.Length, sig, (nuint)sig.Length, pk, (nuint)pk.Length) == 1;

    /// <summary>
    /// Derive a 32-byte key deterministically from a media file — "the file is the key".
    /// Reproducible on any machine; nothing is stored.
    /// </summary>
    /// <remarks>
    /// Uses the deterministic entropy path deliberately: key_from_file mixes in fresh
    /// system entropy and so could never reopen its own envelope.
    /// </remarks>
    public static byte[] KeyFromFileDeterministic(string path)
    {
        var h = cryptolib_entropy_from_file_deterministic(path, out var err);
        if (err != IntPtr.Zero)
        {
            var msg = Marshal.PtrToStringUTF8(err) ?? "cryptolib: entropy error";
            cryptolib_str_free(err);
            throw new CryptoLibException(msg);
        }
        if (h == IntPtr.Zero) throw new CryptoLibException("cryptolib: entropy handle allocation failed");
        try { return Consume(cryptolib_entropy_symmetric_key(h)); }
        finally { cryptolib_entropy_free(h); }
    }

    /// <summary>Hide <paramref name="payload"/> inside a media carrier.</summary>
    public static void StegoEmbed(string coverPath, byte[] payload, string outputPath)
    {
        var r = cryptolib_stego_embed(coverPath, payload, (nuint)payload.Length, outputPath);
        if (r.ok == 1) return;
        var msg = r.error != IntPtr.Zero ? Marshal.PtrToStringUTF8(r.error) ?? "stego embed failed" : "stego embed failed";
        if (r.error != IntPtr.Zero) cryptolib_str_free(r.error);
        throw new CryptoLibException(msg);
    }

    /// <summary>Recover a payload hidden by <see cref="StegoEmbed"/>.</summary>
    public static byte[] StegoExtract(string stegoPath) => Consume(cryptolib_stego_extract(stegoPath));

    /// <summary>Forward-error-correct <paramref name="data"/> under a <see cref="FecScheme"/>.</summary>
    public static byte[] FecEncode(byte[] data, int scheme)
        => Consume(cryptolib_fec_encode(data, (nuint)data.Length, scheme));
    /// <summary>Reverse <see cref="FecEncode"/>, recovering <paramref name="originalLength"/> bytes.</summary>
    public static byte[] FecDecode(byte[] data, int scheme, int originalLength)
        => Consume(cryptolib_fec_decode(data, (nuint)data.Length, scheme, (nuint)originalLength));

    /// <summary>Start a <see cref="Recipe"/> at the given profile's settings.</summary>
    public static Recipe NewRecipe(SecurityProfile profile = SecurityProfile.Balanced) => new(profile);

    /// <summary>A <see cref="Recipe"/> using the strongest option at every choice.</summary>
    public static Recipe MaximumSecurity() => new(SecurityProfile.Maximum);
}

/// <summary>An error reported by the native library or by recipe validation.</summary>
public sealed class CryptoLibException : Exception
{
    /// <summary>Create an exception with the given message.</summary>
    public CryptoLibException(string message) : base(message) { }
}
