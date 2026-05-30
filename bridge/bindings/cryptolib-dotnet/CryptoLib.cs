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

    private static byte[] Read(CryptoBuffer b)
    {
        if (b.data == IntPtr.Zero || b.len == 0) return Array.Empty<byte>();
        var outBytes = new byte[(int)b.len];
        Marshal.Copy(b.data, outBytes, 0, (int)b.len);
        return outBytes;
    }
    private static byte[] Consume(CryptoBufferResult r)
    {
        var outBytes = Read(r.buf);
        var buf = r.buf; cryptolib_buffer_free(ref buf);
        return outBytes;
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
}
