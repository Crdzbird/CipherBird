"""
SecurityProfile + Recipe checks, and the Python end of the cross-language
interop harness.

    python3 tests/test_recipe.py                 # run the checks
    python3 tests/test_recipe.py seal|open DIR   # interop mode
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import cryptolib  # noqa: E402
from cryptolib import (  # noqa: E402
    CascadeLayer, Ed25519Signature, FecScheme, KeySource, ProtectionLayer, SecurityProfile,
    SignatureAlgorithm, SignatureScheme,
)

# Fixed inputs so every language derives identical keys.
KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SK_HEX = "d463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6"
PASSPHRASE = "interop passphrase"
PLAINTEXT = b"cross-language recipe envelope"

_pass = _fail = 0


# ── custom parts used by the extension-point checks ─────────────────────────

class MyLayer(ProtectionLayer):
    id, wire_name = 200, "my-xchacha"
    def seal(self, key, aad, pt): return cryptolib.xchacha20_encrypt(pt, key, aad)
    def open(self, key, aad, ct): return cryptolib.xchacha20_decrypt(ct, key, aad)


class BeltAndBraces(CascadeLayer):
    def __init__(self):
        super().__init__(201, "belt-and-braces",
                         [ProtectionLayer.XCHACHA20_POLY1305, ProtectionLayer.AES256_GCM, MyLayer()])


class Impostor(ProtectionLayer):
    id, wire_name = 3, "committing"
    def seal(self, key, aad, pt): return pt
    def open(self, key, aad, ct): return ct


class TokenSource(KeySource):
    id, label = 210, "token"
    def __init__(self, token): self.token = token
    def derive_root(self, salt, ops, mem): return self.token


class WeakSource(KeySource):
    id, label = 211, "weak"
    def derive_root(self, salt, ops, mem): return b"\x00" * 16


class PrefixedEd25519(SignatureScheme):
    id, label = 220, "prefixed-ed25519"
    def __init__(self, sk=None, pk=None): self.sk, self.pk = sk, pk
    def sign(self, m): return cryptolib.ed25519_sign(b"custom:" + m, self.sk)
    def verify(self, m, sig): return cryptolib.ed25519_verify(b"custom:" + m, sig, self.pk)


class FakeEd25519(SignatureScheme):
    id, label = 1, "fake"
    def sign(self, m): return b"\x00" * 64
    def verify(self, m, sig): return True


def ck(label, ok):
    global _pass, _fail
    print(("  ok   " if ok else " FAIL  ") + label)
    if ok:
        _pass += 1
    else:
        _fail += 1


def throws(fn):
    try:
        fn()
        return False
    except Exception:
        return True


def noise_ppm(w, h, seed):
    head = f"P6\n{w} {h}\n255\n".encode()
    body = bytearray(w * h * 3)
    s = seed or 1
    for i in range(len(body)):
        s ^= (s << 13) & 0xFFFFFFFF
        s ^= s >> 17
        s ^= (s << 5) & 0xFFFFFFFF
        body[i] = s & 0xFF
    return head + bytes(body)


def cheap(r):
    return r.argon2_cost(ops=1, memory_bytes=8 * 1024 * 1024)


def interop_configs(pk, sk):
    key = bytes.fromhex(KEY_HEX)
    return [
        ("balanced", cryptolib.recipe().with_key(key)),
        ("maximum", cryptolib.recipe(SecurityProfile.MAXIMUM).with_key(key)),
        ("signed", cryptolib.recipe(SecurityProfile.HIGH).with_key(key)
            .signed_by(sk, SignatureAlgorithm.ED25519).verified_by(pk)),
        ("passphrase", cheap(cryptolib.recipe().with_passphrase(PASSPHRASE))),
        ("fec", cryptolib.recipe().with_key(key).with_fec(FecScheme.REPETITION3)),
    ]


def main():
    cryptolib.init()

    if len(sys.argv) >= 3 and sys.argv[1] in ("seal", "open"):
        mode, directory = sys.argv[1], sys.argv[2]
        pk, sk = cryptolib.ed25519_keygen_from_seed(bytes.fromhex(SK_HEX))
        failures = 0
        configs = interop_configs(pk, sk)
        for name, r in configs:
            path = os.path.join(directory, f"{name}.bin")
            if mode == "seal":
                with open(path, "wb") as fh:
                    fh.write(r.seal(PLAINTEXT))
            else:
                try:
                    with open(path, "rb") as fh:
                        ok = r.open(fh.read()) == PLAINTEXT
                    print(("  ok   " if ok else " FAIL  ") + f"python opens {name}")
                    if not ok:
                        failures += 1
                except Exception as exc:  # noqa: BLE001
                    print(f" FAIL  python opens {name}: {exc}")
                    failures += 1
        if mode == "seal":
            print(f"  python sealed {len(configs)} envelopes")
        sys.exit(0 if failures == 0 else 1)

    print(f"CryptoLib {cryptolib.version()} — security profiles + recipes (Python)")
    tmp = tempfile.mkdtemp(prefix="cl_sec_py_")
    secret = b"the treaty text nobody may read"

    mx = SecurityProfile.MAXIMUM
    ck("maximum picks the strongest options",
       mx.ml_kem_level == 2 and mx.ml_dsa_level == 2 and mx.slh_dsa_hash == 1
       and mx.sealed_tier == 1 and mx.kdf_preset == 1)
    ck("maximum cascade ends key-committing",
       len(mx.cascade) == 3 and mx.cascade[-1] is ProtectionLayer.COMMITTING)
    ck("profiles are ordered",
       SecurityProfile.BALANCED.argon2_memory < mx.argon2_memory)

    key = cryptolib.random_bytes(32)
    r = cryptolib.recipe(SecurityProfile.HIGH).with_key(key)
    ck("raw key round-trip", r.open(r.seal(secret)) == secret)

    pr = cheap(cryptolib.maximum_security().with_passphrase("correct horse battery staple"))
    ck("maximum + passphrase round-trip", pr.open(pr.seal(secret)) == secret)

    key_file = os.path.join(tmp, "key.ppm")
    with open(key_file, "wb") as fh:
        fh.write(noise_ppm(96, 96, 0x5EED))
    by_file = cryptolib.recipe().with_key_file(key_file).seal(secret)
    ck("key file reproducible across recipe objects",
       cryptolib.recipe().with_key_file(key_file).open(by_file) == secret)

    mol = cryptolib.recipe().with_key(key).with_layers([ProtectionLayer.MOLECULAR])
    ck("MolecularVault as one layer", mol.open(mol.seal(secret)) == secret)

    one = cryptolib.recipe().with_key(key).with_layers([ProtectionLayer.XCHACHA20_POLY1305]).seal(secret)
    three = (cryptolib.recipe().with_key(key)
             .with_layers([ProtectionLayer.XCHACHA20_POLY1305, ProtectionLayer.AES256_GCM])
             .add_layer(ProtectionLayer.COMMITTING).seal(secret))
    ck("each layer adds overhead", len(three) > len(one))

    pk, sk = cryptolib.ed25519_keygen()
    signed = cryptolib.recipe(SecurityProfile.HIGH).with_key(key).signed_by(sk).verified_by(pk)
    senv = signed.seal(secret)
    ck("signed round-trip", signed.open(senv) == secret)

    hpk, hsk = cryptolib.hybrid_sig_keygen()
    hy = cryptolib.recipe().with_key(key).signed_by(hsk, SignatureAlgorithm.HYBRID).verified_by(hpk)
    ck("hybrid PQ signed round-trip", hy.open(hy.seal(secret)) == secret)

    ipk, _isk = cryptolib.ed25519_keygen()
    ck("wrong signer rejected",
       throws(lambda: cryptolib.recipe(SecurityProfile.HIGH).with_key(key).verified_by(ipk).open(senv)))
    ck("signed envelope refuses to open unverified",
       throws(lambda: cryptolib.recipe(SecurityProfile.HIGH).with_key(key).open(senv)))

    fr = cryptolib.recipe().with_key(key).with_fec(FecScheme.REPETITION3)
    fenv = bytearray(fr.seal(secret))
    fenv[len(fenv) // 2] ^= 1
    ck("FEC corrects a flipped bit", fr.open(bytes(fenv)) == secret)

    cover, carrier = os.path.join(tmp, "cover.ppm"), os.path.join(tmp, "carrier.ppm")
    with open(cover, "wb") as fh:
        fh.write(noise_ppm(256, 256, 0x0FF1CE))
    cr = cheap(cryptolib.maximum_security().with_passphrase("a long passphrase here"))
    cr.seal_into_carrier(secret, cover, carrier)
    ck("pipeline hides itself in a carrier", cr.open_from_carrier(carrier) == secret)

    tenv = bytearray(r.seal(secret)); tenv[-1] ^= 1
    ck("flipped ciphertext byte rejected", throws(lambda: r.open(bytes(tenv))))
    henv = bytearray(r.seal(secret)); henv[7] = 1
    ck("tampered header rejected (descriptor is AAD)", throws(lambda: r.open(bytes(henv))))
    senv2 = bytearray(r.seal(secret)); senv2[10] ^= 0xFF
    ck("tampered salt rejected", throws(lambda: r.open(bytes(senv2))))
    ck("wrong key rejected",
       throws(lambda: cryptolib.recipe(SecurityProfile.HIGH)
              .with_key(cryptolib.random_bytes(32)).open(r.seal(secret))))
    ck("foreign bytes rejected", throws(lambda: r.open(b"not an envelope at all")))
    ck("short key refused", throws(lambda: cryptolib.recipe().with_key(b"\x00" * 31)))
    ck("empty layer list refused", throws(lambda: cryptolib.recipe().with_layers([])))

    # Extension points
    ck("built-in ids pinned",
       [l.id for l in (ProtectionLayer.XCHACHA20_POLY1305, ProtectionLayer.AES256_GCM,
                       ProtectionLayer.COMMITTING, ProtectionLayer.MOLECULAR)] == [1, 2, 3, 4]
       and cryptolib.PassphraseKeySource("x").id == 1 and Ed25519Signature().id == 1
       and cryptolib.HybridSignature().id == 2)

    ProtectionLayer.register(MyLayer())
    cenv = cryptolib.recipe().with_key(key).with_layers([MyLayer()]).seal(secret)
    ck("custom layer round-trips via the registry", cryptolib.recipe().with_key(key).open(cenv) == secret)

    ProtectionLayer.register(BeltAndBraces())
    br = cryptolib.recipe().with_key(key).with_layers([BeltAndBraces()])
    benv = br.seal(secret)
    ck("cascade subclass mixes three ciphers as one layer", cryptolib.recipe().with_key(key).open(benv) == secret)
    bbad = bytearray(benv); bbad[-1] ^= 1
    ck("cascade fails closed on tamper", throws(lambda: br.open(bytes(bbad))))

    nested = CascadeLayer(202, "nested", [BeltAndBraces(), ProtectionLayer.COMMITTING])
    ProtectionLayer.register(nested)
    nenv = cryptolib.recipe().with_key(key).with_layers([ProtectionLayer.XCHACHA20_POLY1305, nested]).seal(secret)
    ck("cascades nest, mixed with built-ins", cryptolib.recipe().with_key(key).open(nenv) == secret)

    ck("reserved layer id refused at register", throws(lambda: ProtectionLayer.register(Impostor())))
    ck("reserved layer id refused at add_layer", throws(lambda: cryptolib.recipe().with_key(key).add_layer(Impostor())))
    ck("reserved scheme id refused", throws(lambda: cryptolib.recipe().with_key(key).signed_with(FakeEd25519())))
    ProtectionLayer.register(MyLayer())
    ck("re-registering an id under another wire_name refused",
       throws(lambda: ProtectionLayer.register(CascadeLayer(200, "other", [ProtectionLayer.XCHACHA20_POLY1305]))))

    e1 = cryptolib.recipe().with_key(key).with_layers([MyLayer()]).seal(secret)
    e2 = cryptolib.recipe().with_key(key).with_layers(
        [CascadeLayer(203, "renamed", [ProtectionLayer.XCHACHA20_POLY1305])]).seal(secret)
    ck("wire_name feeds the key derivation", len(e1) == len(e2) and e1 != e2)

    token = cryptolib.random_bytes(32)
    tenv2 = cryptolib.recipe(SecurityProfile.HIGH).with_key_source(TokenSource(token)).seal(secret)
    ck("custom key source round-trips",
       cryptolib.recipe(SecurityProfile.HIGH).with_key_source(TokenSource(token)).open(tenv2) == secret)
    ck("wrong token rejected", throws(lambda: cryptolib.recipe(SecurityProfile.HIGH)
                                      .with_key_source(TokenSource(cryptolib.random_bytes(32))).open(tenv2)))
    ck("header pins the source id", throws(lambda: cryptolib.recipe(SecurityProfile.HIGH).with_key(key).open(tenv2)))
    ck("narrowing key source refused", throws(lambda: cryptolib.recipe().with_key_source(WeakSource()).seal(secret)))

    spk, ssk = cryptolib.ed25519_keygen()
    senv3 = cryptolib.recipe().with_key(key).signed_with(PrefixedEd25519(sk=ssk)).seal(secret)
    ck("custom signature scheme round-trips",
       cryptolib.recipe().with_key(key).verified_with(PrefixedEd25519(pk=spk)).open(senv3) == secret)
    ck("key-only verifier cannot serve a custom scheme",
       throws(lambda: cryptolib.recipe().with_key(key).verified_by(spk).open(senv3)))
    ck("unverified custom-signed envelope refused", throws(lambda: cryptolib.recipe().with_key(key).open(senv3)))
    ck("verifier with the wrong scheme id refused",
       throws(lambda: cryptolib.recipe().with_key(key).verified_with(Ed25519Signature(public_key=spk)).open(senv3)))

    hr = cryptolib.recipe().with_key(key).signed_by(hsk, SignatureAlgorithm.HYBRID).verified_by(hpk)
    ck("built-in shorthand with key-only verifier", hr.open(hr.seal(secret)) == secret)

    d = cryptolib.recipe().with_key_source(TokenSource(token)).with_layers([BeltAndBraces()]).describe()
    ck("describe names custom parts", "token" in d and "belt-and-braces" in d)

    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{_pass} passed, {_fail} failed — recipes {'OK' if _fail == 0 else 'FAILED'}")
    sys.exit(0 if _fail == 0 else 1)


if __name__ == "__main__":
    main()
