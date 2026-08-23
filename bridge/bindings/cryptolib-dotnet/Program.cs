using CryptoLibNet;

// Smoke checks plus the .NET end of the cross-language interop harness.
//   dotnet run                  # smoke + recipe checks
//   dotnet run -- seal|open DIR # interop mode

// Fixed inputs so every language derives identical keys.
const string KeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const string SkHex = "d463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6";
const string Passphrase = "interop passphrase";
byte[] plaintextBytes = "cross-language recipe envelope"u8.ToArray();

int pass = 0, fail = 0;
void Ck(string label, bool ok) { Console.WriteLine($"  {(ok ? "✓" : "✗")} {label}"); if (ok) pass++; else fail++; }
bool Throws(Action a) { try { a(); return false; } catch { return true; } }
Recipe Cheap(Recipe r) => r.Argon2Cost(1, 8UL * 1024 * 1024);

byte[] NoisePpm(int w, int h, uint seed)
{
    var head = System.Text.Encoding.ASCII.GetBytes($"P6\n{w} {h}\n255\n");
    var body = new byte[w * h * 3];
    var s = seed == 0 ? 1u : seed;
    for (var i = 0; i < body.Length; i++)
    {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        body[i] = (byte)s;
    }
    return head.Concat(body).ToArray();
}

CryptoLib.Init();

List<(string Name, Recipe R)> InteropConfigs(byte[] pk, byte[] sk)
{
    var key = Convert.FromHexString(KeyHex);
    return new List<(string, Recipe)>
    {
        ("balanced", CryptoLib.NewRecipe().WithKey(key)),
        ("maximum", CryptoLib.NewRecipe(SecurityProfile.Maximum).WithKey(key)),
        ("signed", CryptoLib.NewRecipe(SecurityProfile.High).WithKey(key)
            .SignedBy(sk, SignatureAlgorithm.Ed25519).VerifiedBy(pk)),
        ("passphrase", Cheap(CryptoLib.NewRecipe().WithPassphrase(Passphrase))),
        ("fec", CryptoLib.NewRecipe().WithKey(key).WithFec(FecScheme.Repetition3)),
    };
}

if (args.Length >= 2 && (args[0] == "seal" || args[0] == "open"))
{
    var (ipk, isk) = CryptoLib.Ed25519KeygenFromSeed(Convert.FromHexString(SkHex));
    var failures = 0;
    var cfgs = InteropConfigs(ipk, isk);
    foreach (var (name, cfg) in cfgs)
    {
        var path = Path.Combine(args[1], $"{name}.bin");
        if (args[0] == "seal") File.WriteAllBytes(path, cfg.Seal(plaintextBytes));
        else
        {
            try
            {
                var ok = cfg.Open(File.ReadAllBytes(path)).AsSpan().SequenceEqual(plaintextBytes);
                Console.WriteLine($"{(ok ? "  ok  " : " FAIL ")} dotnet opens {name}");
                if (!ok) failures++;
            }
            catch (Exception e) { Console.WriteLine($" FAIL  dotnet opens {name}: {e.Message}"); failures++; }
        }
    }
    if (args[0] == "seal") Console.WriteLine($"  dotnet sealed {cfgs.Count} envelopes");
    Environment.Exit(failures == 0 ? 0 : 1);
}

Ck("version == 3.0.0", CryptoLib.Version() == "3.0.0");
Ck("SHA-256(\"abc\") KAT",
   Convert.ToHexString(CryptoLib.Sha256("abc"u8.ToArray())).ToLowerInvariant() ==
   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

var (kemPub, kemSec) = CryptoLib.HybridKemKeygen();
var (kemCt, kemSs) = CryptoLib.HybridKemEncapsulate(kemPub);
Ck("Hybrid X25519+ML-KEM-768 round-trip",
   kemSs.AsSpan().SequenceEqual(CryptoLib.HybridKemDecapsulate(kemCt, kemSec)) && kemSs.Length == 32);

// ── Security profiles + recipes ──────────────────────────────────────────────
var tmp = Directory.CreateTempSubdirectory("cl_sec_net_");
var secret = "the treaty text nobody may read"u8.ToArray();

const SecurityProfile Mx = SecurityProfile.Maximum;
Ck("maximum picks the strongest options",
   Mx.MlKemLevel() == 2 && Mx.MlDsaLevel() == 2 && Mx.SlhDsaHash() == 1
   && Mx.SealedTier() == 1 && Mx.KdfPreset() == 1);
Ck("maximum cascade ends key-committing",
   Mx.Cascade().Length == 3 && Mx.Cascade()[^1] == ProtectionLayer.Committing);
Ck("profiles are ordered", SecurityProfile.Balanced.Argon2Memory() < Mx.Argon2Memory());

var key = CryptoLib.RandomBytes(32);
var r = CryptoLib.NewRecipe(SecurityProfile.High).WithKey(key);
Ck("raw key round-trip", r.Open(r.Seal(secret)).AsSpan().SequenceEqual(secret));

var pr = Cheap(CryptoLib.MaximumSecurity().WithPassphrase("correct horse battery staple"));
Ck("maximum + passphrase round-trip", pr.Open(pr.Seal(secret)).AsSpan().SequenceEqual(secret));

var keyFile = Path.Combine(tmp.FullName, "key.ppm");
File.WriteAllBytes(keyFile, NoisePpm(96, 96, 0x5EED));
var byFile = CryptoLib.NewRecipe().WithKeyFile(keyFile).Seal(secret);
Ck("key file reproducible across recipe objects",
   CryptoLib.NewRecipe().WithKeyFile(keyFile).Open(byFile).AsSpan().SequenceEqual(secret));

var mol = CryptoLib.NewRecipe().WithKey(key).WithLayers(new[] { ProtectionLayer.Molecular });
Ck("MolecularVault as one layer", mol.Open(mol.Seal(secret)).AsSpan().SequenceEqual(secret));

var one = CryptoLib.NewRecipe().WithKey(key)
    .WithLayers(new[] { ProtectionLayer.XChaCha20Poly1305 }).Seal(secret);
var three = CryptoLib.NewRecipe().WithKey(key)
    .WithLayers(new[] { ProtectionLayer.XChaCha20Poly1305, ProtectionLayer.Aes256Gcm })
    .AddLayer(ProtectionLayer.Committing).Seal(secret);
Ck("each layer adds overhead", three.Length > one.Length);

var (idPub, idSec) = CryptoLib.Ed25519Keygen();
var signed = CryptoLib.NewRecipe(SecurityProfile.High).WithKey(key).SignedBy(idSec).VerifiedBy(idPub);
var senv = signed.Seal(secret);
Ck("signed round-trip", signed.Open(senv).AsSpan().SequenceEqual(secret));

var (hPub, hSec) = CryptoLib.HybridSigKeygen();
var hy = CryptoLib.NewRecipe().WithKey(key).SignedBy(hSec, SignatureAlgorithm.Hybrid).VerifiedBy(hPub);
Ck("hybrid PQ signed round-trip", hy.Open(hy.Seal(secret)).AsSpan().SequenceEqual(secret));

var (impPub, _) = CryptoLib.Ed25519Keygen();
Ck("wrong signer rejected",
   Throws(() => CryptoLib.NewRecipe(SecurityProfile.High).WithKey(key).VerifiedBy(impPub).Open(senv)));
Ck("signed envelope refuses to open unverified",
   Throws(() => CryptoLib.NewRecipe(SecurityProfile.High).WithKey(key).Open(senv)));

var fr = CryptoLib.NewRecipe().WithKey(key).WithFec(FecScheme.Repetition3);
var fenv = fr.Seal(secret);
fenv[fenv.Length / 2] ^= 1;
Ck("FEC corrects a flipped bit", fr.Open(fenv).AsSpan().SequenceEqual(secret));

var cover = Path.Combine(tmp.FullName, "cover.ppm");
var carrier = Path.Combine(tmp.FullName, "carrier.ppm");
File.WriteAllBytes(cover, NoisePpm(256, 256, 0x0FF1CE));
var cr = Cheap(CryptoLib.MaximumSecurity().WithPassphrase("a long passphrase here"));
cr.SealIntoCarrier(secret, cover, carrier);
Ck("pipeline hides itself in a carrier", cr.OpenFromCarrier(carrier).AsSpan().SequenceEqual(secret));

var tenv = r.Seal(secret); tenv[^1] ^= 1;
Ck("flipped ciphertext byte rejected", Throws(() => r.Open(tenv)));
var henv = r.Seal(secret); henv[7] = 1;
Ck("tampered header rejected (descriptor is AAD)", Throws(() => r.Open(henv)));
var senv2 = r.Seal(secret); senv2[10] ^= 0xFF;
Ck("tampered salt rejected", Throws(() => r.Open(senv2)));
Ck("wrong key rejected",
   Throws(() => CryptoLib.NewRecipe(SecurityProfile.High).WithKey(CryptoLib.RandomBytes(32)).Open(r.Seal(secret))));
Ck("foreign bytes rejected", Throws(() => r.Open("not an envelope at all"u8.ToArray())));
Ck("short key refused", Throws(() => CryptoLib.NewRecipe().WithKey(new byte[31])));
Ck("empty layer list refused", Throws(() => CryptoLib.NewRecipe().WithLayers(Array.Empty<ProtectionLayer>())));

tmp.Delete(true);
Console.WriteLine($"\ncryptolib .NET: {(fail == 0 ? "OK" : "FAILED")} ({pass} passed, {fail} failed)");
Environment.Exit(fail == 0 ? 0 : 1);
