import { NextResponse } from 'next/server';
import { lib } from '../../../lib/cryptolib.js';

// FFI needs the Node runtime, not the Edge runtime.
export const runtime = 'nodejs';

export async function POST(req) {
  const { op, text = '', passphrase = 'a good passphrase' } = await req.json();
  const c = lib();
  try {
    switch (op) {
      case 'version':
        return NextResponse.json({ version: c.version() });

      case 'sha256':
        return NextResponse.json({ sha256: c.sha256(Buffer.from(text)).toString('hex') });

      case 'molecular': {
        // Cascade + Argon2id under a passphrase, plus the PQ raw-key path.
        const pt = Buffer.from(text);
        const env = c.molecularSeal(pt, passphrase, null, 2, 1 << 20);
        const roundtrip = c.molecularOpen(env, passphrase).toString();
        const kp = c.hybridKemKeygen();
        const { ciphertext, sharedSecret } = c.hybridKemEncapsulate(kp.publicKey);
        const sealed = c.molecularSealWithKey(pt, sharedSecret);
        const pqOk = c.molecularOpenWithKey(
          sealed, c.hybridKemDecapsulate(ciphertext, kp.secretKey)).toString() === text;
        return NextResponse.json({ envelopeBytes: env.length, roundtrip, ok: roundtrip === text, pqRoundtripOk: pqOk });
      }

      case 'evm': {
        const digest = c.keccak256(Buffer.from(text));
        const kp = c.secp256k1Keygen();
        const sig = c.secp256k1Sign(digest, kp.secretKey);
        const ecrecoverMatches = c.secp256k1Recover(digest, sig).equals(kp.publicKey);
        return NextResponse.json({ keccak256: digest.toString('hex'), signatureBytes: sig.length, ecrecoverMatches });
      }

      default:
        return NextResponse.json({ error: `unknown op: ${op}` }, { status: 400 });
    }
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
