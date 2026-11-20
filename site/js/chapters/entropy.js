import { row, refuses } from '../kit.js';
import { same, utf8, hex, preview } from '../bytes.js';
import { makeBmp, makeWav, makePattern, carrierFrom, plain, workspace } from '../media.js';

const DIR = '/demo/entropy';
const picture = () => ({ bytes: makeBmp(256, 192), name: 'photo.bmp' });
const sound = () => ({ bytes: makeWav(1), name: 'tone.wav' });
const fileInput = { name: 'carrier', label: 'Source file (optional upload)', kind: 'file', accept: '.bmp,.png,.ppm,.jpg,.jpeg,.gif,.wav' };

/** A check row for an operation that must be refused, with the engine's message made plain. */
function refused(label, fn) {
  const outcome = refuses(fn);
  return row.check(label, outcome.refused, outcome.refused ? `refused: ${plain(outcome.message)}` : 'accepted');
}

/** Runs `fn` with an entropy handle and frees the handle afterwards. */
function withEntropy(cb, handle, fn) {
  try {
    return fn(handle);
  } finally {
    cb.call('entropy_free', handle);
  }
}

/** The 32-byte symmetric key of a fresh handle from `open`. */
function keyOf(cb, open) {
  return withEntropy(cb, open(), (h) => cb.call('entropy_symmetric_key', h));
}

const yes = (v) => (v ? 'passed' : 'FAILED');

export default {
  id: 'entropy',
  title: 'Media entropy and generators',
  lead: 'LavaRand-style key material from photos and sound, guarded by SP 800-90B health tests, and three generators that stretch it: a live source, HMAC-DRBG and a Fortuna pool. Every file here lives in the engine\'s in-memory file system.',
  demos: [
    {
      id: 'file-keys',
      title: 'Keys from a photo',
      statement: 'A file conditioned by the engine yields six domain-separated keys. Deterministic mode gives the same keys from the same file every time; LavaRand mode mixes in system randomness and never repeats.',
      inputs: [fileInput],
      run(cb, { carrier }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const path = ws.put(`source${c.ext}`, c.bytes);
          const h = cb.call('entropy_from_file_deterministic', path);
          let keys;
          let info;
          let bundle;
          let raw;
          let boost;
          try {
            keys = cb.call('entropy_derive_all', h);
            info = cb.call('entropy_info', h);
            bundle = cb.call('entropy_asym_bundle', h);
            raw = cb.call('entropy_raw', h);
            boost = cb.call('entropy_boost', h);
          } finally {
            cb.call('entropy_free', h);
          }
          const again = keyOf(cb, () => cb.call('entropy_from_file_deterministic', path));
          const lava1 = keyOf(cb, () => cb.call('entropy_from_file', path));
          const lava2 = keyOf(cb, () => cb.call('entropy_from_file', path));
          const quick1 = cb.call('key_from_file', path);
          const quick2 = cb.call('key_from_file', path);
          const names = ['symmetric_key', 'vault_master_key', 'signing_seed', 'box_seed', 'stream_key', 'raw_entropy'];
          return [
            row.text('Source', `${c.name}, ${c.bytes.length} bytes, ${c.uploaded ? 'uploaded' : 'generated in the browser'}`),
            row.table('entropy_info', ['File size', 'Read passes', 'Entropy estimate (engine)'],
              [[`${info.file_size} bytes`, String(info.chunks_read), `${Math.round(info.entropy_bits)} bits`]]),
            row.table('entropy_derive_all (deterministic)', ['Key', 'Bytes', 'Value'],
              names.map((n) => [n, String(keys[n].length), preview(keys[n], 8)])),
            row.bytes('X25519 public key from the same file', bundle.box_public),
            row.bytes('Ed25519 public key from the same file', bundle.sign_public),
            row.bytes('entropy_raw', raw),
            row.bytes('entropy_boost (second factor for a vault)', boost),
            row.check('Deterministic mode: same file, same key', same(keys.symmetric_key, again), preview(again, 8)),
            row.check('Keys for different purposes are independent', !same(keys.symmetric_key, keys.stream_key), 'symmetric_key differs from stream_key'),
            row.check('LavaRand mode: same file, new key each time', !same(lava1, lava2), `${preview(lava1, 6)} then ${preview(lava2, 6)}`),
            row.check('key_from_file is LavaRand mode too', !same(quick1, quick2) && !same(quick1, again), 'never repeats'),
          ];
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'many-files',
      title: 'Several files, one key',
      statement: 'A photo and a sound mixed together give a key that neither gives alone. A long-lived LavaRand handle can be refreshed with new system randomness in place.',
      inputs: [fileInput],
      run(cb, { carrier }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const a = ws.put(`photo${c.ext}`, c.bytes);
          const b = ws.put('tone.wav', sound().bytes);
          const both = keyOf(cb, () => cb.call('entropy_from_files_deterministic', [a, b]));
          const bothAgain = keyOf(cb, () => cb.call('entropy_from_files_deterministic', [a, b]));
          const swapped = keyOf(cb, () => cb.call('entropy_from_files_deterministic', [b, a]));
          const onlyA = keyOf(cb, () => cb.call('entropy_from_file_deterministic', a));
          const onlyB = keyOf(cb, () => cb.call('entropy_from_file_deterministic', b));
          const lava = cb.call('entropy_from_files', [a, b]);
          let before;
          let after;
          let lavaInfo;
          try {
            before = cb.call('entropy_symmetric_key', lava);
            cb.call('entropy_refresh', lava);
            after = cb.call('entropy_symmetric_key', lava);
            lavaInfo = cb.call('entropy_info', lava);
          } finally {
            cb.call('entropy_free', lava);
          }
          return [
            row.bytes('Key from photo and sound (deterministic)', both),
            row.bytes('Key from the photo alone', onlyA),
            row.bytes('Key from the sound alone', onlyB),
            row.check('Mixing both files repeats exactly', same(both, bothAgain), 'same key twice'),
            row.check('The mix is neither file alone', !same(both, onlyA) && !same(both, onlyB), 'three different keys'),
            row.text('Listing the files the other way round', same(both, swapped) ? 'gives the same key' : 'gives another key: order is part of the input'),
            row.text('LavaRand handle over both files', `${lavaInfo.file_size} bytes read, about ${Math.round(lavaInfo.entropy_bits)} bits estimated`),
            row.bytes('LavaRand key before refresh', before),
            row.bytes('LavaRand key after entropy_refresh', after),
            row.check('Refresh mixes in new randomness', !same(before, after), 'key changed'),
          ];
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'file-seal',
      title: 'Encrypt with a file as the key',
      statement: 'seal_from_file derives the vault key from a file in deterministic mode, so the same file opens the packet later. A copy with one bit changed is a different key.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'the spare key is in the blue vase' },
        { name: 'aad', label: 'Associated data', kind: 'text', value: 'household/v1' },
        fileInput,
      ],
      run(cb, { message, aad, carrier }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const path = ws.put(`key${c.ext}`, c.bytes);
          const nudged = Uint8Array.from(c.bytes);
          nudged[nudged.length - 9] ^= 1;
          const nudgedPath = ws.put(`key-nudged${c.ext}`, nudged);
          const otherPath = ws.put('other.wav', sound().bytes);
          const packet = cb.call('seal_from_file', path, message, aad);
          const back = cb.call('open_from_file', path, packet, aad);
          return [
            row.bytes('Ciphertext', packet.ciphertext),
            row.bytes('Signature (Ed25519)', packet.signature),
            row.bytes('KDF salt', packet.kdf_salt),
            row.check('The same file opens it', same(back, utf8.encode(message)), utf8.decode(back)),
            refused('The file with one bit flipped is refused', () => cb.call('open_from_file', nudgedPath, packet, aad)),
            refused('Another file is refused', () => cb.call('open_from_file', otherPath, packet, aad)),
            refused('Other associated data is refused', () => cb.call('open_from_file', path, packet, `${aad}.`)),
          ];
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'health',
      title: 'Health tests before trust',
      statement: 'Before a file becomes key material the engine estimates its min-entropy and runs the SP 800-90B repetition-count and adaptive-proportion tests. A blank or repeating file is refused unless the caller opts out on purpose.',
      inputs: [
        fileInput,
        { name: 'floor', label: 'Policy floor (bits per byte)', kind: 'number', value: 3, min: 0, max: 8 },
      ],
      run(cb, { carrier, floor }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const claim = Number(floor);
          const files = [
            [c.name, ws.put(`source${c.ext}`, c.bytes)],
            ['64 KiB of zeros', ws.put('zeros.bin', makePattern(65536, [0]))],
            ['bytes 1..8 repeated', ws.put('pattern.bin', makePattern(65536, [1, 2, 3, 4, 5, 6, 7, 8]))],
            ['64 KiB from random_bytes', ws.put('random.bin', cb.call('random_bytes', 65536))],
          ];
          const v1 = files.map(([, p]) => cb.call('entropy_assess_file_health', p, 0));
          const v2 = files.map(([, p]) => cb.call('entropy_assess_file_health_v2', p, 0, claim));
          const policy = (p, f, rct) => refuses(() => {
            const h = cb.call('entropy_from_file_with_policy', p, 1, f, rct);
            cb.call('entropy_free', h);
            return true;
          });
          const verdicts = files.map(([, p]) => policy(p, claim, 1));
          const zeros = files[1][1];
          const patternLow = v2[2].min_entropy_per_byte < claim;
          const permissive = policy(zeros, 0, 0);
          return [
            row.table('entropy_assess_file_health', ['File', 'Min-entropy (bits/byte)', 'Longest run', 'Repetition count', 'Adaptive proportion'],
              files.map(([n], i) => [n, v1[i].min_entropy_per_byte.toFixed(2), String(v1[i].longest_run), yes(v1[i].rct_passed), yes(v1[i].apt_passed)])),
            row.table(`entropy_assess_file_health_v2 at a floor of ${claim}`, ['File', 'MCV', 'Markov', 'Run cutoff', 'Window cutoff', `Harvest with floor ${claim}`],
              files.map(([n], i) => [n, v2[i].mcv_bits_per_byte.toFixed(2), v2[i].markov_bits_per_byte.toFixed(2),
                String(v2[i].rct_cutoff), String(v2[i].apt_cutoff), verdicts[i].refused ? 'refused' : 'accepted'])),
            row.text(`Summary for ${c.name}`, plain(v2[0].summary)),
            row.check('Zeros fail both tests', !v1[1].rct_passed && !v1[1].apt_passed, `longest run ${v1[1].longest_run}`),
            row.check('Random bytes pass both tests', v1[3].rct_passed && v1[3].apt_passed, `${v1[3].min_entropy_per_byte.toFixed(2)} bits/byte`),
            refused('The default harvest refuses the zeros', () => cb.call('entropy_from_file', zeros)),
            patternLow
              ? row.check(`The repeating pattern is refused at a floor of ${claim}`, verdicts[2].refused,
                verdicts[2].refused ? plain(verdicts[2].message) : 'accepted')
              : row.text('The repeating pattern', `its estimate ${v2[2].min_entropy_per_byte.toFixed(2)} clears a floor of ${claim}; raise the floor to see it refused`),
            row.check('A permissive policy (floor 0, no run test) takes even zeros, by explicit choice', !permissive.refused,
              permissive.refused ? plain(permissive.message) : 'accepted'),
            row.text('Why the pattern passes the run tests', 'no byte repeats twice in a row, so only the min-entropy estimate exposes it'),
          ];
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'live',
      title: 'A live source that only credits healthy chunks',
      statement: 'LiveEntropy assesses each chunk as it arrives, the way camera frames or audio buffers would. A stuck or repeating chunk is mixed in but earns no credit, and output stays locked until enough credit is earned.',
      inputs: [
        fileInput,
        { name: 'floor', label: 'Policy floor (bits per byte)', kind: 'number', value: 3, min: 0, max: 8 },
      ],
      run(cb, { carrier, floor }) {
        const c = carrierFrom(carrier, picture);
        const h = cb.call('live_entropy_new', Number(floor), 1, 256);
        try {
          const locked = refuses(() => cb.call('live_entropy_generate', h, 32));
          const feeds = [
            ['stuck sensor: 4096 zeros', makePattern(4096, [0]), 1],
            ['looping buffer: 1..8 repeated', makePattern(4096, [1, 2, 3, 4, 5, 6, 7, 8]), 1],
            ['tiny chunk: 64 bytes', c.bytes.subarray(c.bytes.length - 64), 2],
            ['a 4096-byte slice of the source', c.bytes.subarray(Math.max(0, c.bytes.length - 8192), Math.max(0, c.bytes.length - 8192) + 4096), 2],
          ];
          const reports = feeds.map(([, data, source]) => cb.call('live_entropy_feed', h, data, source));
          const out = cb.call('live_entropy_generate', h, 32);
          const second = cb.call('live_entropy_generate', h, 32);
          const status = cb.call('live_entropy_status', h);
          return [
            row.check('Before any credit, generate is refused', locked.refused, plain(locked.message)),
            row.table('live_entropy_feed', ['Chunk', 'Credited bits', 'Min-entropy', 'Longest run', 'Why not credited'],
              feeds.map(([name], i) => [name, reports[i].credited_bits.toFixed(0), reports[i].min_entropy_per_byte.toFixed(2),
                String(reports[i].longest_run), reports[i].accepted ? '' : plain(reports[i].reason)])),
            row.check('The stuck chunk earns nothing', reports[0].accepted === 0 && reports[0].credited_bits === 0, 'credited 0'),
            row.check('The tiny chunk earns nothing', reports[2].accepted === 0, 'below the 1024-byte minimum'),
            row.check('A real frame is credited', reports[3].accepted === 1 && reports[3].credited_bits > 0, `${reports[3].credited_bits.toFixed(0)} bits`),
            row.bytes('32 bytes once seeded', out),
            row.check('Successive draws differ', !same(out, second), 'fresh output'),
            row.table('live_entropy_status', ['Chunks fed', 'Accepted', 'Rejected', 'Bytes fed', 'Reseeds', 'Credited bits', 'Ready'],
              [[status.chunks_fed, status.chunks_accepted, status.chunks_rejected, status.bytes_fed, status.reseeds,
                status.credited_bits_total.toFixed(0), status.ready ? 'yes' : 'no'].map(String)]),
          ];
        } finally {
          cb.call('live_entropy_free', h);
        }
      },
    },
    {
      id: 'drbg',
      title: 'HMAC-DRBG: a reproducible stream',
      statement: 'An SP 800-90A HMAC-DRBG turns a seed into a keystream. The same seed always gives the same stream, which suits beacons and tests, and a reseed sends it somewhere new.',
      inputs: [
        { name: 'seed', label: 'Seed text (hashed to 32 bytes)', kind: 'text', value: 'beacon round 1024' },
        { name: 'label', label: 'Personalization', kind: 'text', value: 'demo/drbg' },
      ],
      run(cb, { seed, label }) {
        const entropy = cb.call('sha256', seed);
        const nonce = utf8.encode('nonce-01');
        const a = cb.call('drbg_instantiate', entropy, nonce, label);
        let b = 0;
        try {
          b = cb.call('drbg_instantiate', entropy, nonce, label);
          const a1 = cb.call('drbg_generate', a, 32, null);
          const b1 = cb.call('drbg_generate', b, 32, null);
          const a2 = cb.call('drbg_generate', a, 32, null);
          const b2 = cb.call('drbg_generate', b, 32, null);
          cb.call('drbg_reseed', a, cb.call('random_bytes', 32), null);
          const a3 = cb.call('drbg_generate', a, 32, null);
          const b3 = cb.call('drbg_generate', b, 32, null);
          const mixed = cb.call('drbg_generate', b, 32, 'extra input');
          return [
            row.bytes('Seed (SHA-256 of the text)', entropy),
            row.bytes('Twin A, first 32 bytes', a1),
            row.bytes('Twin B, first 32 bytes', b1),
            row.check('Same seed, same stream', same(a1, b1) && same(a2, b2), 'identical twice'),
            row.check('The stream moves on', !same(a1, a2), `${hex(a1).slice(0, 12)}... then ${hex(a2).slice(0, 12)}...`),
            row.bytes('Twin A after a reseed', a3),
            row.bytes('Twin B, not reseeded', b3),
            row.check('A reseed separates the twins', !same(a3, b3), 'different'),
            row.bytes('Twin B with additional input', mixed),
            refused('A seed shorter than 32 bytes is refused', () => cb.call('drbg_instantiate', entropy.subarray(0, 16), null, null)),
            refused('More than 65536 bytes per request is refused', () => cb.call('drbg_generate', b, 65537, null)),
          ];
        } finally {
          cb.call('drbg_free', a);
          if (b) cb.call('drbg_free', b);
        }
      },
    },
    {
      id: 'fortuna',
      title: 'A Fortuna pool that reseeds itself',
      statement: 'Events from many sources spread round-robin over 32 pools. Output stays locked until pool 0 has 64 bytes, and every reseed is counted.',
      inputs: [fileInput],
      run(cb, { carrier }) {
        const c = carrierFrom(carrier, picture);
        const f = cb.call('fortuna_new');
        try {
          const start = cb.call('fortuna_reseed_count', f);
          const locked = refuses(() => cb.call('fortuna_generate', f, 32));
          let events = 0;
          let firstOut = null;
          while (!firstOut && events < 200) {
            const source = events % 3;
            const at = (events * 32) % Math.max(1, c.bytes.length - 32);
            const timer = new Uint8Array(32);
            timer.set(new Uint8Array(new Float64Array([performance.now()]).buffer));
            const data = [c.bytes.subarray(at, at + 32), cb.call('random_bytes', 32), timer][source];
            cb.call('fortuna_add_entropy', f, source, data);
            events++;
            const attempt = refuses(() => cb.call('fortuna_generate', f, 32));
            if (!attempt.refused) firstOut = attempt.value;
          }
          const afterAuto = cb.call('fortuna_reseed_count', f);
          cb.call('fortuna_reseed', f);
          const afterForced = cb.call('fortuna_reseed_count', f);
          const next = cb.call('fortuna_generate', f, 32);
          return [
            row.text('Reseeds before any event', start),
            row.check('Generate is refused while unseeded', locked.refused, plain(locked.message)),
            row.text('Events of 32 bytes until output unlocked', `${events} (photo, random_bytes and a timer, round-robin)`),
            row.bytes('First output', firstOut || new Uint8Array(0)),
            row.check('Pool 0 filling triggers the first reseed', start === 0 && afterAuto >= 1, `count ${afterAuto}`),
            row.check('A forced reseed is counted', afterForced === afterAuto + 1, `count ${afterForced}`),
            row.bytes('Output after the forced reseed', next),
            row.check('Outputs do not repeat', firstOut && !same(firstOut, next), 'different'),
          ];
        } finally {
          cb.call('fortuna_free', f);
        }
      },
    },
  ],
};
