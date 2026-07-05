// Server-only helper: loads the native CryptoLib binding once.
//
// The binding is a native FFI module — it must run in Node (never Edge or the
// browser). It is loaded with createRequire so Next's bundler never tries to
// bundle koffi's native addon; only route handlers (runtime = 'nodejs') import
// this file.
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);

// Point the binding at the local build if no prebuilt binary is present.
if (!process.env.CRYPTOLIB_DYLIB) {
  const ext = process.platform === 'darwin' ? 'dylib' : process.platform === 'win32' ? 'dll' : 'so';
  process.env.CRYPTOLIB_DYLIB = path.resolve(process.cwd(), `../../../build/release/libcryptolib_c.${ext}`);
}

const crypto = require(path.resolve(process.cwd(), '../cryptolib-node/index.js'));

let inited = false;
export function lib() {
  if (!inited) { crypto.init(); inited = true; }
  return crypto;
}
