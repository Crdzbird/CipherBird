// Node + koffi HTTP server backing the React UI.
//
// The browser cannot dlopen a native library, so this small server performs the
// crypto with the real CryptoLib native library and exposes it over HTTP. Run:
//   node server.mjs                 # uses ../../../build/release/libcryptolib_c.dylib
//   CRYPTOLIB_DYLIB=/abs/path node server.mjs
// then `npm run dev` for the React frontend (Vite proxies /api here).

import http from 'node:http';
import koffi from 'koffi';
import { readFile } from 'node:fs/promises';
import { join, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const HERE = fileURLToPath(new URL('.', import.meta.url));

const libPath = process.env.CRYPTOLIB_DYLIB || '../../../build/release/libcryptolib_c.dylib';
const lib = koffi.load(libPath);

const CryptoBuffer = koffi.struct('CryptoBuffer', { data: 'void *', len: 'size_t' });
const CryptoBufferResult = koffi.struct('CryptoBufferResult', { buf: CryptoBuffer, error: 'void *' });
const CryptoPacket = koffi.struct('CryptoPacket', {
  ciphertext: CryptoBuffer, signature: CryptoBuffer, kdf_salt: CryptoBuffer,
});

const fn = {
  init: lib.func('int cryptolib_init()'),
  version: lib.func('const char *cryptolib_version()'),
  sha256: lib.func('CryptoBufferResult cryptolib_sha256(uint8_t *msg, size_t len)'),
  randomBytes: lib.func('CryptoBufferResult cryptolib_random_bytes(size_t n)'),
  vaultCreate: lib.func('void *cryptolib_vault_create(uint8_t *key, size_t len, int kdf)'),
  vaultSeal: lib.func('CryptoPacket cryptolib_vault_seal(void *v, uint8_t *pt, size_t len, const char *aad, _Out_ char **err)'),
  vaultOpen: lib.func('CryptoBufferResult cryptolib_vault_open(void *v, CryptoPacket *pkt, const char *aad)'),
  bufferFree: lib.func('void cryptolib_buffer_free(CryptoBuffer *buf)'),
  packetFree: lib.func('void cryptolib_packet_free(CryptoPacket *p)'),
  vaultFree: lib.func('void cryptolib_vault_free(void *v)'),
  strFree: lib.func('void cryptolib_str_free(void *s)'),
  krCreate: lib.func('void *cryptolib_keyring_create()'),
  krAddDev: lib.func('int cryptolib_keyring_add_device_slot(void *kr, uint8_t *fk, size_t len)'),
  krAddPw: lib.func('int cryptolib_keyring_add_passphrase_slot(void *kr, const char *pw, int kdf)'),
  krCount: lib.func('size_t cryptolib_keyring_slot_count(void *kr)'),
  krSer: lib.func('CryptoBufferResult cryptolib_keyring_serialise(void *kr)'),
  krDeser: lib.func('void *cryptolib_keyring_deserialise(uint8_t *blob, size_t len, _Out_ char **err)'),
  krUnlockDev: lib.func('CryptoBufferResult cryptolib_keyring_unlock_with_device(void *kr, uint8_t *fk, size_t len)'),
  krUnlockPw: lib.func('CryptoBufferResult cryptolib_keyring_unlock_with_passphrase(void *kr, const char *pw)'),
  krFree: lib.func('void cryptolib_keyring_free(void *kr)'),
};

function consume(res) {
  if (!res.buf.data || Number(res.buf.len) === 0) {
    if (res.error) { const m = koffi.decode(res.error, 'char *'); fn.strFree(res.error); throw new Error(m); }
    return Buffer.alloc(0);
  }
  const bytes = Buffer.from(koffi.decode(res.buf.data, 'uint8_t', Number(res.buf.len)));
  fn.bufferFree(res.buf);
  return bytes;
}

if (fn.init() !== 0) throw new Error('cryptolib init failed');

const routes = {
  '/api/version': () => ({ version: fn.version() }),
  '/api/sha256': ({ text }) => ({ sha256: consume(fn.sha256(Buffer.from(text ?? ''), Buffer.byteLength(text ?? ''))).toString('hex') }),
  '/api/seal-open': ({ text }) => {
    const key = consume(fn.randomBytes(32));
    const vault = fn.vaultCreate(key, key.length, 0);
    try {
      const pt = Buffer.from(text ?? '');
      const errOut = [null];
      const pkt = fn.vaultSeal(vault, pt, pt.length, 'react', errOut);
      if (errOut[0]) throw new Error('seal failed');
      const opened = consume(fn.vaultOpen(vault, pkt, 'react'));
      const ctLen = Number(pkt.ciphertext.len);
      fn.packetFree(pkt);
      return { ciphertextBytes: ctLen, roundtrip: opened.toString(), ok: opened.toString() === (text ?? '') };
    } finally { fn.vaultFree(vault); }
  },
  '/api/keyring': () => {
    const factor = consume(fn.randomBytes(32)); // stands in for a hardware key
    const kr = fn.krCreate();
    fn.krAddDev(kr, factor, factor.length);
    fn.krAddPw(kr, 'cross-device pass', 0);
    const blob = consume(fn.krSer(kr));
    const errOut = [null];
    const kr2 = fn.krDeser(blob, blob.length, errOut);
    try {
      const mDev = consume(fn.krUnlockDev(kr2, factor, factor.length));
      const mPass = consume(fn.krUnlockPw(kr2, 'cross-device pass'));
      return { slots: Number(fn.krCount(kr)),
               envelopeBytes: blob.length,
               sameMaster: Buffer.compare(mDev, mPass) === 0 };
    } finally { fn.krFree(kr); fn.krFree(kr2); }
  },
  // Wrap the keyring's master key under a caller-supplied 32-byte factor — e.g.
  // a WebAuthn PRF secret (see src/webauthn.js) or any platform device key.
  '/api/keyring-with-factor': (data) => {
    const hex = String(data.factorHex || '').replace(/[^0-9a-fA-F]/g, '');
    if (hex.length < 64) throw new Error('factor must be at least 32 bytes (64 hex chars)');
    const factor = Buffer.from(hex.slice(0, 64), 'hex');
    const kr = fn.krCreate();
    fn.krAddDev(kr, factor, factor.length);
    const blob = consume(fn.krSer(kr));
    const errOut = [null];
    const kr2 = fn.krDeser(blob, blob.length, errOut);
    try {
      const m = consume(fn.krUnlockDev(kr2, factor, factor.length));
      return { ok: m.length === 32, slots: Number(fn.krCount(kr)), envelopeBytes: blob.length };
    } finally { fn.krFree(kr); fn.krFree(kr2); }
  },
  // Run the full Node showcase (every capability family) in a child process
  // against the same native library and stream its text report back to the UI.
  '/api/showcase': () => {
    const script = join(HERE, '..', 'node', 'showcase.js');
    const absLib = resolve(HERE, libPath);
    let output, ok = true;
    try {
      output = execFileSync('node', [script, absLib],
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
const DIST = join(fileURLToPath(new URL('.', import.meta.url)), 'dist');
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
