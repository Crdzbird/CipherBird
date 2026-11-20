# CipherBird Next.js example

Uses CipherBird from a **Next.js route handler** running on the Node runtime.
Native FFI cannot run in the browser or the Edge runtime, so all crypto happens
server-side; the client just POSTs to `/api/crypto`.

```
Browser (app/page.jsx, 'use client')
   |  POST /api/crypto  { op, text }
   v
Route handler (app/api/crypto/route.js, runtime = 'nodejs')
   |  the Node binding in ../cipherbird-node (loaded at request time, never bundled)
   v
native libcipherbird_c
```

## Run

```sh
# 1. Build the native library (once), from the repo root:
cmake -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --target cipherbird_c

# 2. Install the sibling Node binding's deps (provides koffi), from the repo root:
(cd bridge/bindings/cipherbird-node && npm install)

# 3. Run this example:
cd bridge/bindings/nextjs
npm install
npm run dev            # http://localhost:3005
```

`lib/cipherbird.js` points the binding at `build/release/libcipherbird_c.<ext>` by
default; override with `CIPHERBIRD_LIBRARY=/abs/path` (the binding also reads
`CIPHERBIRD_LIBRARY`, which wins when both are set).

## Endpoints (`POST /api/crypto`)

| `op` | Returns |
| --- | --- |
| `version` | native library version |
| `sha256` | SHA-256 of `text` |
| `molecular` | MolecularVault seal and open (passphrase) plus a hybrid-KEM post-quantum round trip |
| `evm` | Keccak-256 of `text` plus secp256k1 sign and ecrecover |

The binding wraps the whole C ABI (356 functions in 1.5.0; see
[its README](../cipherbird-node/README.md)), so adding an operation is another
`case` in the route handler.

## Notes

- **Node runtime only.** The route sets `export const runtime = 'nodejs'`. FFI
  is not available on the Edge runtime.
- **Not bundled.** koffi (a native addon) and the Node binding are loaded at
  request time through a dynamic `import()` marked `webpackIgnore`, so Next's
  bundler leaves them alone.
- For deployment, depend on the published `cipherbird` npm package, which
  carries its prebuilt engine, instead of the sibling directory and a local
  build.
