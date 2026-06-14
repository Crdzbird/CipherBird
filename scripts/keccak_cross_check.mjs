#!/usr/bin/env node
// Live differential check: cryptolib's native Keccak-256 vs the independent
// js-sha3 reference, across every length 0..512 plus a few string vectors.
//
// Keccak-256 (Ethereum, original 0x01 padding) has no in-process oracle in our
// C/C++ deps (OpenSSL ships SHA3, not original Keccak), so this out-of-process
// check is how CI pins our implementation to a second, widely-deployed one.
// It complements the offline KATs baked into tests/test_evm_btc.cpp.
//
// Usage:
//   npm i js-sha3 koffi          # in this script's working dir
//   node scripts/keccak_cross_check.mjs [path-to-libcryptolib_c.dylib]
//
// Exit 0 on full agreement, 1 on any mismatch or setup failure.

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

let keccak256, koffi;
try {
  ({ keccak256 } = require('js-sha3'));
  koffi = require('koffi');
} catch (e) {
  console.error('keccak_cross_check: missing dep (need js-sha3 + koffi):', e.message);
  process.exit(1);
}

const libPath = process.argv[2]
  || process.env.CRYPTOLIB_DYLIB
  || 'build/release/libcryptolib_c.dylib';

let lib;
try {
  lib = koffi.load(libPath);
} catch (e) {
  console.error(`keccak_cross_check: cannot load ${libPath}:`, e.message);
  process.exit(1);
}

const CryptoBuffer = koffi.struct('CryptoBuffer', { data: 'void *', len: 'size_t' });
const CryptoBufferResult = koffi.struct('CryptoBufferResult', { buf: CryptoBuffer, error: 'void *' });
const cryptolib_keccak256 = lib.func('CryptoBufferResult cryptolib_keccak256(uint8_t *msg, size_t len)');
const cryptolib_buffer_free = lib.func('void cryptolib_buffer_free(CryptoBuffer *buf)');
const cryptolib_str_free = lib.func('void cryptolib_str_free(void *s)');

function nativeKeccak(buf) {
  const res = cryptolib_keccak256(buf, buf.length);
  if (!res.buf.data || Number(res.buf.len) === 0) {
    if (res.error) cryptolib_str_free(res.error);
    throw new Error('native keccak256 returned empty');
  }
  const n = Number(res.buf.len);
  const out = Buffer.from(koffi.decode(res.buf.data, 'uint8_t', n)).toString('hex');
  cryptolib_buffer_free(res.buf);
  return out;
}

let checked = 0, mismatches = 0;

// Every length 0..512 with input byte[i] = i & 0xff.
for (let len = 0; len <= 512; len++) {
  const buf = Buffer.alloc(len);
  for (let i = 0; i < len; i++) buf[i] = i & 0xff;
  const ref = keccak256(buf);
  const got = nativeKeccak(buf);
  checked++;
  if (ref !== got) {
    mismatches++;
    console.error(`MISMATCH len=${len}\n  ref=${ref}\n  got=${got}`);
  }
}

// A few human-readable vectors.
for (const s of ['', 'abc', 'The quick brown fox jumps over the lazy dog']) {
  const buf = Buffer.from(s, 'utf8');
  const ref = keccak256(buf);
  const got = nativeKeccak(buf);
  checked++;
  if (ref !== got) {
    mismatches++;
    console.error(`MISMATCH "${s}"\n  ref=${ref}\n  got=${got}`);
  }
}

if (mismatches === 0) {
  console.log(`keccak_cross_check: OK — ${checked} inputs match js-sha3 exactly`);
  process.exit(0);
}
console.error(`keccak_cross_check: FAILED — ${mismatches}/${checked} mismatched`);
process.exit(1);
