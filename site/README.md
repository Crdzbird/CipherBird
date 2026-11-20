# CipherBird demo site

The GitHub Pages site for CipherBird. Every demo calls the real engine: the
attested `cipherbird.wasm` from `bridge/bindings/cipherbird/assets/`, checked
against its SHA-384 digest before it is instantiated. Nothing is sent anywhere.

- `index.html` is the landing page.
- `tour.html` walks every feature area, one working demo per capability.
- `explorer.html` calls any of the 356 C ABI functions by hand.

## Run it locally

```bash
scripts/web/build_site.sh build/site
python3 -m http.server -d build/site 8080
```

Then open http://localhost:8080. `build_site.sh` copies the engine next to the
pages and writes its integrity digests. Add `--showcase` to also build the
Flutter showcase into `build/site/showcase/`.

## Test it

```bash
node site/test/run_demos.mjs
```

Runs every demo of every chapter against the engine under Node, fails on any
check that does not hold, and reports which C ABI functions the demos reach.

## How a demo is written

A chapter is a module in `js/chapters/` that default-exports:

```js
export default {
  id: 'hashing',
  title: 'Hashing and key derivation',
  lead: 'One or two sentences, plain prose.',
  demos: [
    {
      id: 'avalanche',
      title: 'Short title, sentence case',
      statement: 'Two short lines that say what this shows and why it matters.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'meet at the north gate' },
      ],
      run(cb, input) {
        return [row.bytes('SHA-256', cb.call('sha256', input.message))];
      },
    },
  ],
};
```

- `cb.call(name, ...args)` calls `cipherbird_<name>`. A `(pointer, length)`
  pair is one argument (a `Uint8Array` or a string, UTF-8 encoded); a list of
  byte strings is one array; `char**` error slots are handled and turn into a
  thrown `EngineError`; a returned `CryptoBufferResult` becomes its bytes, a
  `CryptoResult` becomes `true`, other structs become plain objects whose
  buffers are `Uint8Array`s. Engine memory is freed and wiped after every call.
- Outputs the engine writes through a pointer take an `Out`: `cb.Out.bytes(n)`,
  `cb.Out.text(n)`, `cb.Out.scalar()`, `cb.Out.buffer()`; read `.value` after.
- Handles (vault, keyring, Noise, session and so on) are numbers; free them with
  their `_free` function in a `finally`.
- Path APIs read and write the engine's in-memory file system:
  `cb.writeFile(path, bytes)` and `cb.readFile(path)`.
- `cb.engine.plan(name)` shows how a function's arguments are grouped.
- `run` returns rows from `js/kit.js`. A `row.check` states an outcome the
  library promises (a tampered ciphertext is refused, two parties agree on a
  key); the runner fails when one does not hold. `mustRefuse` wraps the common
  case.
- Input kinds: `text`, `textarea`, `number` (with `min`, `max`), `select`
  (with `options`), `toggle`, `file` (the default is generated when absent).
- Plain ASCII in every string and comment; no `//` comments, doc comments only.
