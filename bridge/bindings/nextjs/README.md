# CryptoLib · Next.js example

Uses CryptoLib from a **Next.js route handler** running on the Node runtime.
Native FFI cannot run in the browser or the Edge runtime, so all crypto happens
server-side; the client just POSTs to `/api/crypto`.

```
Browser (app/page.jsx, 'use client')
   │  POST /api/crypto  { op, text }
   ▼
Route handler (app/api/crypto/route.js, runtime = 'nodejs')
   │  cryptolib-node  (loaded via createRequire — never bundled)
   ▼
native libcryptolib_c
```

## Run

```sh
# 1. Build the native library (once), from the repo root:
cmake -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --target cryptolib_c

# 2. Install the sibling Node binding's deps (provides koffi), from the repo root:
(cd bridge/bindings/cryptolib-node && npm install)

# 3. Run this example:
cd bridge/bindings/nextjs
npm install
npm run dev            # http://localhost:3005
```

`lib/cryptolib.js` points the binding at `build/release/libcryptolib_c.<ext>` by
default; override with `CRYPTOLIB_DYLIB=/abs/path`.

## Endpoints (`POST /api/crypto`)

| `op` | Returns |
| --- | --- |
| `version` | native library version |
| `sha256` | SHA-256 of `text` |
| `molecular` | MolecularVault seal→open (passphrase) + hybrid-KEM PQ round-trip |
| `evm` | Keccak-256 of `text` + secp256k1 sign/ecrecover |

The binding exposes the full 127-function API, so adding more operations is just
another `case` in the route handler.

## Notes

- **Node runtime only.** The route sets `export const runtime = 'nodejs'`. FFI
  is not available on the Edge runtime.
- **Not bundled.** koffi (a native addon) and `cryptolib-node` are loaded at
  request time via `createRequire`, so Next's bundler leaves them alone.
- For deployment, bundle a self-contained `libcryptolib_c` (static-linked deps)
  or publish `cryptolib-node` with the prebuilt binary and depend on it normally.
