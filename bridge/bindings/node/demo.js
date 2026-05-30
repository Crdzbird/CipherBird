// CryptoLib Node.js demo via koffi (https://koffi.dev).
//
// This is the JavaScript native-call path: usable directly from Node/Electron,
// and the same approach a React Native TurboModule (C++) or a Node addon would
// wrap. (Browser React cannot load a .dylib — it would need a WASM build.)
//
// Run (see Makefile target `node`):
//   npm install
//   node demo.js <path-to-libcryptolib_c.dylib>

const koffi = require('koffi');

const libPath = process.argv[2] || 'build/release/libcryptolib_c.dylib';
const lib = koffi.load(libPath);

// ── C struct definitions ─────────────────────────────────────────────────────
const CryptoBuffer = koffi.struct('CryptoBuffer', { data: 'void *', len: 'size_t' });
// error kept as a raw pointer (not auto-decoded to a JS string) so we can free
// the *original* C allocation with cryptolib_str_free rather than a koffi temp.
const CryptoBufferResult = koffi.struct('CryptoBufferResult', { buf: CryptoBuffer, error: 'void *' });
const CryptoPacket = koffi.struct('CryptoPacket', {
  ciphertext: CryptoBuffer, signature: CryptoBuffer, kdf_salt: CryptoBuffer,
});

// ── Function bindings ────────────────────────────────────────────────────────
const cryptolib_init = lib.func('int cryptolib_init()');
const cryptolib_version = lib.func('const char *cryptolib_version()');
const cryptolib_random_bytes = lib.func('CryptoBufferResult cryptolib_random_bytes(size_t n)');
const cryptolib_sha256 = lib.func('CryptoBufferResult cryptolib_sha256(uint8_t *msg, size_t len)');
const cryptolib_vault_create = lib.func('void *cryptolib_vault_create(uint8_t *key, size_t len, int kdf)');
const cryptolib_vault_seal = lib.func('CryptoPacket cryptolib_vault_seal(void *v, uint8_t *pt, size_t len, const char *aad, _Out_ char **err)');
const cryptolib_vault_open = lib.func('CryptoBufferResult cryptolib_vault_open(void *v, CryptoPacket *pkt, const char *aad)');
const cryptolib_buffer_free = lib.func('void cryptolib_buffer_free(CryptoBuffer *buf)');
const cryptolib_packet_free = lib.func('void cryptolib_packet_free(CryptoPacket *p)');
const cryptolib_vault_free = lib.func('void cryptolib_vault_free(void *v)');
const cryptolib_str_free = lib.func('void cryptolib_str_free(void *s)');

// Keyring (envelope / key-slots)
const cryptolib_keyring_create = lib.func('void *cryptolib_keyring_create()');
const cryptolib_keyring_add_device_slot = lib.func('int cryptolib_keyring_add_device_slot(void *kr, uint8_t *fk, size_t len)');
const cryptolib_keyring_add_passphrase_slot = lib.func('int cryptolib_keyring_add_passphrase_slot(void *kr, const char *pw, int kdf)');
const cryptolib_keyring_slot_count = lib.func('size_t cryptolib_keyring_slot_count(void *kr)');
const cryptolib_keyring_serialise = lib.func('CryptoBufferResult cryptolib_keyring_serialise(void *kr)');
const cryptolib_keyring_deserialise = lib.func('void *cryptolib_keyring_deserialise(uint8_t *blob, size_t len, _Out_ char **err)');
const cryptolib_keyring_unlock_with_device = lib.func('CryptoBufferResult cryptolib_keyring_unlock_with_device(void *kr, uint8_t *fk, size_t len)');
const cryptolib_keyring_unlock_with_passphrase = lib.func('CryptoBufferResult cryptolib_keyring_unlock_with_passphrase(void *kr, const char *pw)');
const cryptolib_keyring_free = lib.func('void cryptolib_keyring_free(void *kr)');

// Copy a returned CryptoBufferResult into a Node Buffer and free the C memory.
function consume(res) {
  if (!res.buf.data || Number(res.buf.len) === 0) {
    if (res.error) {
      console.error('error:', koffi.decode(res.error, 'char *'));
      cryptolib_str_free(res.error);
    }
    return Buffer.alloc(0);
  }
  const n = Number(res.buf.len);
  const bytes = Buffer.from(koffi.decode(res.buf.data, 'uint8_t', n));
  cryptolib_buffer_free(res.buf);
  return bytes;
}

const hex = (b) => b.toString('hex');

if (cryptolib_init() !== 0) throw new Error('init failed');
console.log('CryptoLib version:', cryptolib_version());

console.log('random(32): ', hex(consume(cryptolib_random_bytes(32))));
console.log('sha256(abc):', hex(consume(cryptolib_sha256(Buffer.from('abc'), 3))));

const key = consume(cryptolib_random_bytes(32));
const vault = cryptolib_vault_create(key, key.length, 0);
if (!vault) throw new Error('vault_create failed');

const pt = Buffer.from('hello from node');
const errOut = [null];
const packet = cryptolib_vault_seal(vault, pt, pt.length, 'ctx', errOut);
if (errOut[0]) throw new Error('seal: ' + errOut[0]);

const opened = consume(cryptolib_vault_open(vault, packet, 'ctx'));
console.log('vault roundtrip: "%s"', opened.toString());

// Wrong AAD must fail.
const bad = cryptolib_vault_open(vault, packet, 'wrong');
if (bad.buf.data) throw new Error('wrong AAD should not decrypt');
if (bad.error) cryptolib_str_free(bad.error);

cryptolib_packet_free(packet);
cryptolib_vault_free(vault);

// Keyring: default device slot + opt-in passphrase slot → cross-device unlock.
const factor = consume(cryptolib_random_bytes(32)); // stands in for a hardware key
const kr = cryptolib_keyring_create();
cryptolib_keyring_add_device_slot(kr, factor, factor.length);
cryptolib_keyring_add_passphrase_slot(kr, 'cross-device pass', 0);
const blob = consume(cryptolib_keyring_serialise(kr));
const krErr = [null];
const kr2 = cryptolib_keyring_deserialise(blob, blob.length, krErr);
if (krErr[0]) throw new Error('keyring deserialise failed');
const mDev = consume(cryptolib_keyring_unlock_with_device(kr2, factor, factor.length));
const mPass = consume(cryptolib_keyring_unlock_with_passphrase(kr2, 'cross-device pass'));
console.log('keyring slots:', Number(cryptolib_keyring_slot_count(kr)),
            '· device==passphrase master:', Buffer.compare(mDev, mPass) === 0);
cryptolib_keyring_free(kr);
cryptolib_keyring_free(kr2);

console.log('Node demo OK');
