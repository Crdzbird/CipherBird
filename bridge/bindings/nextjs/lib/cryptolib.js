// Server-only helper: lazily loads the native CryptoLib binding once.
//
// `cryptolib-node` wraps a native FFI addon and must run in Node (never Edge or
// the browser). It is loaded with a `webpackIgnore` dynamic import INSIDE the
// function (never at module top level), so Next's bundler never analyses or
// bundles the native addon, and the library is not touched until the first
// request actually needs it.
import path from 'node:path';

let crypto = null;

export async function lib() {
  if (crypto) return crypto;

  // Point the binding at the local build if no prebuilt binary is present.
  if (!process.env.CRYPTOLIB_DYLIB) {
    const ext = process.platform === 'darwin' ? 'dylib' : process.platform === 'win32' ? 'dll' : 'so';
    process.env.CRYPTOLIB_DYLIB = path.resolve(process.cwd(), `../../../build/release/libcryptolib_c.${ext}`);
  }

  const modPath = path.resolve(process.cwd(), '../cryptolib-node/index.js');
  const mod = await import(/* webpackIgnore: true */ modPath);
  crypto = mod.default ?? mod;
  crypto.init();
  return crypto;
}
