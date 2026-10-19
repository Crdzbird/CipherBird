using System;
using System.Security.Cryptography;

namespace CryptoLibNet;

/// <summary>
/// Secret material with a definite end of life: Dispose or Wipe clears the
/// bytes and every later access throws, so a key copy cannot linger on the
/// heap unnoticed. Use it in a using block.
/// </summary>
public sealed class SecretBytes : IDisposable
{
    private readonly byte[] _bytes;
    private bool _wiped;

    private SecretBytes(byte[] bytes) => _bytes = bytes;

    /// <summary>Takes ownership of <paramref name="bytes"/> without copying.</summary>
    public static SecretBytes Take(byte[] bytes) => new(bytes);

    /// <summary>A private copy; the caller still owns the original.</summary>
    public static SecretBytes Copy(ReadOnlySpan<byte> bytes) => new(bytes.ToArray());

    /// <summary>The live bytes, not a copy.</summary>
    public byte[] Bytes => _wiped ? throw new InvalidOperationException("cryptolib: this secret was wiped") : _bytes;

    public int Length => _bytes.Length;

    public bool IsWiped => _wiped;

    /// <summary>Clears the bytes. Idempotent.</summary>
    public void Wipe()
    {
        if (_wiped) return;
        _wiped = true;
        CryptographicOperations.ZeroMemory(_bytes);
    }

    public void Dispose() => Wipe();
}
