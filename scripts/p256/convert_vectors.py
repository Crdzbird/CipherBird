#!/usr/bin/env python3
"""Writes tests/vectors/p256/ecdsa_p256_sha256.json from the NIST CAVP
ECDSA example files and RFC 6979.

Source of the CAVP files: the archive 186-4ecdsatestvectors.zip published
by NIST on the CAVP Digital Signatures page,

  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip
  SHA-256 fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752

Only the P-256 cases are taken, and of the signature files only the
SHA-256 ones:

  KeyPair.rsp  [P-256]          d and its public point
  PKV.rsp      [P-256]          public points, valid and invalid
  SigVer.rsp   [P-256,SHA-256]  signatures, valid and invalid
  SigGen.txt   [P-256,SHA-256]  signatures made with a recorded nonce

The two RFC 6979 cases are appendix A.2.5 of the RFC, SHA-256, messages
"sample" and "test"; a deterministic signer reproduces them exactly.

Unpack the archive and pass its directory:

  python3 scripts/p256/convert_vectors.py path/to/186-4ecdsatestvectors

The C++, Go and Dart suites read the JSON; none of them needs the archive.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "tests", "vectors", "p256", "ecdsa_p256_sha256.json")

RFC6979 = {
    "d": "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    "qx": "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    "qy": "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    "cases": [
        {"message": "sample",
         "r": "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
         "s": "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"},
        {"message": "test",
         "r": "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
         "s": "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"},
    ],
}


def section(path, header):
    """The records of one bracketed section: a list of {name: value}."""
    records, current, inside = [], {}, False
    with open(path, encoding="ascii", errors="strict") as f:
        for raw in f:
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                if line == header:
                    inside = True
                elif inside and line[1:3] in ("P-", "K-", "B-"):
                    break
                continue
            if not inside:
                continue
            if not line or line.startswith("#"):
                if current:
                    records.append(current)
                    current = {}
                continue
            if " = " in line:
                name, value = line.split(" = ", 1)
                current[name.strip()] = value.strip()
    if current:
        records.append(current)
    return [r for r in records if "N" not in r or len(r) > 1]


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    src = sys.argv[1]
    keypair = [{"d": r["d"], "qx": r["Qx"], "qy": r["Qy"]}
               for r in section(os.path.join(src, "KeyPair.rsp"), "[P-256]") if "d" in r]
    pkv = [{"qx": r["Qx"], "qy": r["Qy"], "valid": r["Result"].startswith("P"), "note": r["Result"]}
           for r in section(os.path.join(src, "PKV.rsp"), "[P-256]") if "Qx" in r]
    sigver = [{"message": r["Msg"], "qx": r["Qx"], "qy": r["Qy"], "r": r["R"], "s": r["S"],
               "valid": r["Result"].startswith("P"), "note": r["Result"]}
              for r in section(os.path.join(src, "SigVer.rsp"), "[P-256,SHA-256]") if "Msg" in r]
    siggen = [{"message": r["Msg"], "d": r["d"], "qx": r["Qx"], "qy": r["Qy"], "k": r["k"], "r": r["R"], "s": r["S"]}
              for r in section(os.path.join(src, "SigGen.txt"), "[P-256,SHA-256]") if "Msg" in r]
    doc = {
        "name": "ECDSA P-256 with SHA-256",
        "note": "NIST CAVP 186-4ecdsatestvectors.zip (KeyPair.rsp, PKV.rsp, SigVer.rsp, SigGen.txt; "
                "P-256 and SHA-256 only) and RFC 6979 appendix A.2.5. Written by "
                "scripts/p256/convert_vectors.py; messages are hex except the RFC 6979 ones, which are ASCII.",
        "rfc6979": RFC6979,
        "keypair": keypair,
        "pkv": pkv,
        "sigver": sigver,
        "siggen": siggen,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print("keypair %d, pkv %d (%d valid), sigver %d (%d valid), siggen %d, rfc6979 %d" % (
        len(keypair), len(pkv), sum(1 for p in pkv if p["valid"]), len(sigver),
        sum(1 for s in sigver if s["valid"]), len(siggen), len(RFC6979["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
