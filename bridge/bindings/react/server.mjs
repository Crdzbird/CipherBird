// Node HTTP server backing the React UI.
//
// The browser cannot dlopen a native library, so this small server performs the
// crypto with the real CryptoLib native library and exposes it over HTTP. It
// uses the `cryptolib-node` package (full 127-function parity) rather than
// re-declaring FFI signatures, so the UI can reach the entire library. Run:
//   node server.mjs                 # uses ../../../build/release/libcryptolib_c.dylib
//   CRYPTOLIB_DYLIB=/abs/path node server.mjs
// then `npm run dev` for the React frontend (Vite proxies /api here).

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import crypto from '../cryptolib-node/index.js';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const libPath = process.env.CRYPTOLIB_DYLIB
  || resolve(HERE, '../../../build/release/libcryptolib_c.dylib');
// The package loads the native library lazily on first call; point it at our
// local build so no prebuilt binary is required for the example.
process.env.CRYPTOLIB_DYLIB = libPath;
crypto.init();

const routes = {
  '/api/version': () => ({ version: crypto.version() }),

  '/api/sha256': ({ text }) =>
    ({ sha256: crypto.sha256(Buffer.from(text ?? '')).toString('hex') }),

  '/api/seal-open': ({ text }) => {
    const v = crypto.vaultCreate(crypto.randomBytes(32), 0);
    try {
      const pkt = crypto.vaultSeal(v, Buffer.from(text ?? ''), 'react');
      const opened = crypto.vaultOpen(v, pkt, 'react').toString();
      return { ciphertextBytes: pkt.ciphertext.length, roundtrip: opened, ok: opened === (text ?? '') };
    } finally { crypto.vaultFree(v); }
  },

  '/api/keyring': () => {
    const factor = crypto.randomBytes(32); // stands in for a hardware key
    const kr = crypto.keyringCreate();
    crypto.keyringAddDeviceSlot(kr, factor);
    crypto.keyringAddPassphraseSlot(kr, 'cross-device pass', 0);
    const blob = crypto.keyringSerialise(kr);
    const kr2 = crypto.keyringDeserialise(blob);
    try {
      const mDev = crypto.keyringUnlockWithDevice(kr2, factor);
      const mPass = crypto.keyringUnlockWithPassphrase(kr2, 'cross-device pass');
      return { slots: crypto.keyringSlotCount(kr), envelopeBytes: blob.length,
               sameMaster: Buffer.compare(mDev, mPass) === 0 };
    } finally { crypto.keyringFree(kr); crypto.keyringFree(kr2); }
  },

  // Wrap the keyring's master key under a caller-supplied 32-byte factor — e.g.
  // a WebAuthn PRF secret (see src/webauthn.js) or any platform device key.
  '/api/keyring-with-factor': (data) => {
    const hex = String(data.factorHex || '').replace(/[^0-9a-fA-F]/g, '');
    if (hex.length < 64) throw new Error('factor must be at least 32 bytes (64 hex chars)');
    const factor = Buffer.from(hex.slice(0, 64), 'hex');
    const kr = crypto.keyringCreate();
    crypto.keyringAddDeviceSlot(kr, factor);
    const blob = crypto.keyringSerialise(kr);
    const kr2 = crypto.keyringDeserialise(blob);
    try {
      const m = crypto.keyringUnlockWithDevice(kr2, factor);
      return { ok: m.length === 32, slots: crypto.keyringSlotCount(kr), envelopeBytes: blob.length };
    } finally { crypto.keyringFree(kr); crypto.keyringFree(kr2); }
  },

  // MolecularVault — cascade (XChaCha20 ∘ AES-GCM-SIV) + Argon2id under a
  // passphrase, plus the raw-key path composed with the hybrid PQC KEM.
  '/api/molecular': ({ text, passphrase }) => {
    const pt = Buffer.from(text ?? '');
    const pass = passphrase || 'demo passphrase';
    const env = crypto.molecularSeal(pt, pass, null, 2, 1 << 20);
    const roundtrip = crypto.molecularOpen(env, pass).toString();
    const kp = crypto.hybridKemKeygen();
    const { ciphertext, sharedSecret } = crypto.hybridKemEncapsulate(kp.publicKey);
    const sealed = crypto.molecularSealWithKey(pt, sharedSecret);
    const pqOk = crypto.molecularOpenWithKey(
      sealed, crypto.hybridKemDecapsulate(ciphertext, kp.secretKey)).toString() === (text ?? '');
    return { envelopeBytes: env.length, roundtrip, ok: roundtrip === (text ?? ''), pqRoundtripOk: pqOk };
  },

  // EVM / Bitcoin interop — Keccak-256 + secp256k1 sign / ecrecover.
  '/api/evm': ({ text }) => {
    const digest = crypto.keccak256(Buffer.from(text ?? ''));
    const kp = crypto.secp256k1Keygen();
    const sig = crypto.secp256k1Sign(digest, kp.secretKey);
    const recovered = crypto.secp256k1Recover(digest, sig);
    return { keccak256: digest.toString('hex'), signatureBytes: sig.length,
             ecrecoverMatches: recovered.equals(kp.publicKey) };
  },

  // Run the full Node showcase (every capability family) in a child process
  // against the same native library and stream its text report back to the UI.
  '/api/showcase': () => {
    const script = join(HERE, '..', 'node', 'showcase.js');
    let output, ok = true;
    try {
      output = execFileSync('node', [script, libPath],
        { cwd: join(HERE, '..', 'node'), encoding: 'utf8' });
    } catch (e) {
      ok = false;
      output = `${e.stdout || ''}${e.stderr || ''}` || String(e);
    }
    return { ok: ok && /showcase OK/.test(output), output };
  },
};

// Serve the built React app (dist/) so the UI and /api share one origin — this
// gives WebAuthn a secure http://localhost context (no proxy needed).
const DIST = join(HERE, 'dist');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
               '.svg': 'image/svg+xml', '.json': 'application/json', '.ico': 'image/x-icon' };

async function serveStatic(req, res) {
  let path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (path === '/') path = '/index.html';
  const filePath = join(DIST, path);
  if (!filePath.startsWith(DIST)) { res.writeHead(403); return res.end(); }
  try {
    const data = await readFile(filePath);
    res.writeHead(200, { 'Content-Type': MIME[extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404); res.end('not found (run `npm run build` first)');
  }
}

http.createServer((req, res) => {
  if (req.method === 'GET') return serveStatic(req, res);
  const route = routes[req.url];
  if (req.method !== 'POST' || !route) { res.writeHead(404); return res.end('not found'); }
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    try {
      const data = body ? JSON.parse(body) : {};
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(route(data)));
    } catch (e) { res.writeHead(500); res.end(String(e)); }
  });
}).listen(8787, () => console.log('CryptoLib server (UI + API) → http://localhost:8787'));
