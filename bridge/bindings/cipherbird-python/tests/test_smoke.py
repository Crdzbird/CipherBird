"""Smoke test: import the package (no path) and round-trip across the boundary."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cipherbird

p = lambda label, ok: print(f"  {'✓' if ok else '✗'} {label}")
n_pass = n_fail = 0
def ck(label, ok):
    global n_pass, n_fail
    p(label, ok)
    if ok: n_pass += 1
    else:  n_fail += 1

cipherbird.init()
ck("version == 3.0.0", cipherbird.version() == "3.0.0")
ck("SHA-256(b'abc') KAT",
   cipherbird.sha256(b"abc").hex() ==
   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

pub, sec = cipherbird.hybrid_kem_keygen()
ct, ss   = cipherbird.hybrid_kem_encapsulate(pub)
ss2      = cipherbird.hybrid_kem_decapsulate(ct, sec)
ck("Hybrid X25519+ML-KEM-768 round-trip", ss == ss2 and len(ss) == 32)

print(f"\ncipherbird Python smoke: {'OK' if n_fail == 0 else 'FAILED'} ({n_pass} passed, {n_fail} failed)")
sys.exit(0 if n_fail == 0 else 1)
