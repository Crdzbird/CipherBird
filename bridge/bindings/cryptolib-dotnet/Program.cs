using CryptoLibNet;

int pass = 0, fail = 0;
void Ck(string label, bool ok) { Console.WriteLine($"  {(ok ? "✓" : "✗")} {label}"); if (ok) pass++; else fail++; }

CryptoLib.Init();
Ck("version == 3.0.0", CryptoLib.Version() == "3.0.0");
Ck("SHA-256(\"abc\") KAT",
   Convert.ToHexString(CryptoLib.Sha256("abc"u8.ToArray())).ToLowerInvariant() ==
   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

var (pub, sec) = CryptoLib.HybridKemKeygen();
var (ct, ss) = CryptoLib.HybridKemEncapsulate(pub);
var dec = CryptoLib.HybridKemDecapsulate(ct, sec);
Ck("Hybrid X25519+ML-KEM-768 round-trip", ss.AsSpan().SequenceEqual(dec) && ss.Length == 32);

Console.WriteLine($"\ncryptolib .NET smoke: {(fail == 0 ? "OK" : "FAILED")} ({pass} passed, {fail} failed)");
Environment.Exit(fail == 0 ? 0 : 1);
