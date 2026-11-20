import { row, refuses } from '../kit.js';
import { same, utf8, concat } from '../bytes.js';
import {
  makeBmp, makeWav, bmpFromRgb, pixelsOf, pixelDiff, samplesFromWav, sampleDiff,
  carrierFrom, outExt, imageMime, fileMime, plain, workspace,
} from '../media.js';

const DIR = '/demo/stego';
const picture = () => ({ bytes: makeBmp(256, 192), name: 'carrier.bmp' });
const sound = () => ({ bytes: makeWav(1), name: 'carrier.wav' });
const keyPhoto = () => ({ bytes: makeBmp(160, 120, 99), name: 'key-photo.bmp' });
const pictureInput = { name: 'carrier', label: 'Carrier picture (optional upload)', kind: 'file', accept: '.bmp,.png,.ppm,.gif,.jpg,.jpeg' };

/** A check row for an operation that must be refused, with the engine's message made plain. */
function refused(label, fn) {
  const outcome = refuses(fn);
  return row.check(label, outcome.refused, outcome.refused ? `refused: ${plain(outcome.message)}` : 'accepted');
}

/** Rows that show a carrier: the picture itself when a browser can display it, and a download. */
function showCarrier(label, bytes, ext, name) {
  const mime = imageMime(ext);
  const ppm = ext === '.ppm' ? pixelsOf(bytes, ext) : null;
  const rows = mime ? [row.image(label, bytes, mime)]
    : ppm ? [row.image(label, bmpFromRgb(ppm.rgb, ppm.width, ppm.height), 'image/bmp', 'shown as BMP; the file itself is PPM')] : [];
  rows.push(row.file(`Download: ${label.toLowerCase()}`, bytes, name, fileMime(ext)));
  return rows;
}

/** How far the carrier moved: pixels for BMP and PPM, samples for WAV. */
function changeRows(before, after, ext) {
  if (ext === '.wav') {
    const a = samplesFromWav(before);
    const b = samplesFromWav(after);
    if (!a || !b) return [];
    const d = sampleDiff(a, b);
    return [
      row.text('Samples changed', `${d.changed} of ${d.total} (${((d.changed / d.total) * 100).toFixed(1)}%)`),
      row.text('Largest change to one sample', `${d.maxDelta} of 65536 levels`),
      row.text('Signal-to-noise ratio of the change', `${d.snr.toFixed(1)} dB`),
    ];
  }
  const a = pixelsOf(before, ext);
  const b = pixelsOf(after, ext);
  if (!a || !b || a.rgb.length !== b.rgb.length) return [row.text('Pixel comparison', 'only for BMP and PPM carriers')];
  const d = pixelDiff(a.rgb, b.rgb);
  return [
    row.text('Pixels changed', `${d.changed} of ${d.total} (${((d.changed / d.total) * 100).toFixed(1)}%)`),
    row.text('Largest change to one channel', `${d.maxDelta} of 255 levels`),
  ];
}

export default {
  id: 'stego',
  title: 'Steganography',
  lead: 'Hide bytes inside pictures and sound, then find them again. The engine writes and reads the carriers in its own in-memory file system; the pictures here are drawn in your browser, or you can upload your own.',
  demos: [
    {
      id: 'hide',
      title: 'Hide a message in a picture or a sound',
      statement: 'stego_embed hides bytes in the DCT coefficients of a picture, or in the phase of a sound. Extraction returns every byte while the carrier barely changes.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'meet at the north gate at nine' },
        { name: 'kind', label: 'Generated carrier', kind: 'select', value: 'picture', options: ['picture', 'sound'] },
        { name: 'carrier', label: 'Carrier (optional upload)', kind: 'file', accept: '.bmp,.png,.ppm,.gif,.jpg,.jpeg,.wav' },
      ],
      run(cb, { message, kind, carrier }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, kind === 'sound' ? sound : picture);
          const cover = ws.put(`cover${c.ext}`, c.bytes);
          const out = ws.path(`hidden${outExt(c.ext)}`);
          const cap = { bytes: cb.call('stego_capacity', cover), via: 'stego_capacity' };
          cb.call('stego_embed', cover, message, out);
          const stego = cb.readFile(out);
          const back = cb.call('stego_extract', out);
          const rows = [
            ...showCarrier('Carrier', c.bytes, c.ext, c.name),
            row.text('Carrier', `${c.name}, ${c.bytes.length} bytes, ${c.uploaded ? 'uploaded' : 'generated in the browser'}`),
            row.text('Capacity', cap.bytes ? `${cap.bytes} bytes` : 'not reported for this format', cap.via),
            row.text('Hidden message', `${utf8.encode(message).length} bytes`),
            row.check('Extraction returns the exact message', same(back, utf8.encode(message)), utf8.decode(back)),
            ...changeRows(c.bytes, stego, c.ext),
            ...showCarrier('Carrier with the message inside', stego, outExt(c.ext), `hidden${outExt(c.ext)}`),
          ];
          if (cap.bytes) {
            const full = cb.call('random_bytes', cap.bytes);
            cb.call('stego_embed', cover, full, out);
            rows.push(row.check('A payload of exactly the capacity fits', same(cb.call('stego_extract', out), full), `${cap.bytes} bytes`));
            rows.push(refused('One byte more is refused', () => cb.call('stego_embed', cover, concat(full, [0]), out)));
          }
          return rows;
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'keyed',
      title: 'A key that hides the hiding',
      statement: 'Unkeyed hiding writes a header any extractor can find. A key whitens the whole stream, so without it there is nothing to find, and the detector sees no payload.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'the drop is under the bridge' },
        { name: 'key', label: 'Stego key', kind: 'text', value: 'blue heron' },
        pictureInput,
      ],
      run(cb, { message, key, carrier }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const cover = ws.put(`cover${c.ext}`, c.bytes);
          const open = ws.path(`open${outExt(c.ext)}`);
          const keyed = ws.path(`keyed${outExt(c.ext)}`);
          cb.call('stego_embed', cover, message, open);
          cb.call('stego_embed_keyed', cover, message, keyed, key);
          const back = cb.call('stego_extract_keyed', keyed, key);
          const probe = (path) => cb.call('stego_detect_hidden', path);
          const clean = probe(cover);
          const plainHit = probe(open);
          const keyedHit = probe(keyed);
          const pct = (r) => `${(r.lsb_embedding_likelihood * 100).toFixed(1)}%`;
          return [
            row.check('The right key extracts the message', same(back, utf8.encode(message)), utf8.decode(back)),
            refused('Another key finds nothing', () => cb.call('stego_extract_keyed', keyed, `${key}!`)),
            refused('No key finds nothing', () => cb.call('stego_extract', keyed)),
            row.table('stego_detect_hidden', ['File', 'CipherBird payload found', 'LSB heuristic'], [
              ['clean carrier', clean.cipherbird_payload ? 'yes' : 'no', pct(clean)],
              ['unkeyed embed', plainHit.cipherbird_payload ? 'yes' : 'no', pct(plainHit)],
              ['keyed embed', keyedHit.cipherbird_payload ? 'yes' : 'no', pct(keyedHit)],
            ]),
            row.check('The unkeyed payload is detected', plainHit.cipherbird_payload === 1, 'found'),
            row.check('The clean carrier is not flagged', clean.cipherbird_payload === 0, 'nothing found'),
            row.check('The keyed payload is not detected', keyedHit.cipherbird_payload === 0, 'nothing found'),
            row.text('LSB heuristic on the clean carrier', `${pct(clean)}: a statistic, not proof; only the payload flag is definitive`),
            row.text('What the detector says about itself', plain(clean.note)),
            ...showCarrier('Keyed picture', cb.readFile(keyed), outExt(c.ext), `keyed${outExt(c.ext)}`),
          ];
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'encrypted',
      title: 'Encrypt, then hide',
      statement: 'stego_embed_encrypted seals the message with XChaCha20-Poly1305 before hiding it, so the carrier never holds plaintext. Even the stego layer opened with the right key yields only ciphertext.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'rendezvous moved to friday' },
        { name: 'passphrase', label: 'Passphrase', kind: 'text', value: 'lantern orchard 42' },
        pictureInput,
      ],
      run(cb, { message, passphrase, carrier }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const salt = utf8.encode('cipherbird stego');
          const key = cb.call('argon2id_derive', passphrase, salt, 32, 2, 8 * 1024 * 1024);
          const other = cb.call('argon2id_derive', `${passphrase}x`, salt, 32, 2, 8 * 1024 * 1024);
          const cover = ws.put(`cover${c.ext}`, c.bytes);
          const out = ws.path(`sealed${outExt(c.ext)}`);
          cb.call('stego_embed_encrypted', cover, message, out, key);
          const stego = cb.readFile(out);
          const back = cb.call('stego_extract_decrypt', out, key);
          const inner = cb.call('stego_extract_keyed', out, key);
          const text = utf8.encode(message);
          const contains = (hay, needle) => utf8.decode(hay).includes(utf8.decode(needle));
          const rows = [
            row.bytes('Master key (Argon2id of the passphrase)', key),
            row.check('The passphrase opens it', same(back, text), utf8.decode(back)),
            row.bytes('What the stego layer alone gives back', inner, 'nonce, ciphertext and tag'),
            row.check('That is ciphertext, not the message', inner.length === text.length + 40 && !contains(inner, text),
              `${inner.length} bytes = 24 nonce + ${text.length} + 16 tag`),
            refused('Another passphrase is refused', () => cb.call('stego_extract_decrypt', out, other)),
          ];
          const pixels = pixelsOf(stego, outExt(c.ext));
          if (pixels) {
            const rgb = Uint8Array.from(pixels.rgb);
            const stripe = Math.min(16, pixels.height);
            for (let i = 0; i < pixels.width * stripe * 3; i++) rgb[i] = 255;
            const painted = bmpFromRgb(rgb, pixels.width, pixels.height);
            const tampered = ws.put('painted.bmp', painted);
            rows.push(row.image('The same picture with a white stripe painted over the top', painted, 'image/bmp'));
            rows.push(refused('The painted picture is refused', () => cb.call('stego_extract_decrypt', tampered, key)));
          }
          rows.push(...showCarrier('Picture with the sealed message', stego, outExt(c.ext), `sealed${outExt(c.ext)}`));
          return rows;
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'analysis',
      title: 'Inspect and fingerprint a carrier',
      statement: 'stego_inspect reads the magic bytes, says whether a file is the format its name claims, and checks that the file holds every pixel its header promises. A stored content digest catches any change at all, including the few pixels a hidden message moves.',
      inputs: [
        { name: 'message', label: 'Message to hide', kind: 'text', value: 'a few bytes are enough' },
        pictureInput,
      ],
      run(cb, { message, carrier }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const cover = ws.put(`cover${c.ext}`, c.bytes);
          const out = ws.path(`hidden${outExt(c.ext)}`);
          cb.call('stego_embed', cover, message, out);
          const disguise = c.ext === '.png' ? '.bmp' : '.png';
          const renamed = ws.put(`renamed${disguise}`, c.bytes);
          const cut = ws.put(`cut${c.ext}`, c.bytes.subarray(0, 40));
          const wiped = Uint8Array.from(c.bytes);
          wiped.fill(0, 0, 4);
          const blank = ws.put(`wiped${c.ext}`, wiped);
          const look = (path) => {
            const r = cb.call('stego_inspect', path);
            return [path.slice(DIR.length + 1), r.parses ? 'yes' : 'no', r.ext_matches ? 'yes' : 'no', plain(r.detail)];
          };
          const before = cb.call('stego_content_digest', cover);
          const after = cb.call('stego_content_digest', out);
          const again = cb.call('stego_content_digest', ws.put(`copy${c.ext}`, c.bytes));
          const truncated = cb.call('stego_content_digest', cut);
          const named = cb.call('stego_inspect', renamed);
          const unknown = cb.call('stego_inspect', blank);
          const short = cb.call('stego_inspect', cut);
          return [
            row.table('stego_inspect', ['File', 'Parses', 'Extension matches', 'Detail'],
              [look(cover), look(out), look(renamed), look(blank), look(cut)]),
            row.check(`A ${c.ext} file renamed to ${disguise} is caught`, named.ext_matches === 0, plain(named.detail)),
            row.check('A file with its magic bytes wiped is not recognised', unknown.parses === 0, plain(unknown.detail)),
            row.check('A copy cut to 40 bytes does not parse', short.parses === 0, plain(short.detail)),
            row.bytes('Digest of the carrier', before),
            row.bytes('Digest after hiding the message', after),
            row.check('A copy of the carrier has the same digest', cb.call('secure_equal', before, again) === 1, 'equal'),
            row.check('Hiding a message changes the digest', cb.call('secure_equal', before, after) === 0, 'different'),
            row.check('The digest catches the cut copy', cb.call('secure_equal', before, truncated) === 0, 'different'),
          ];
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'fec',
      title: 'Error correction for a noisy channel',
      statement: 'Classic codes trade capacity for repair. Within its bound the code fixes every flipped bit; past it, it decodes wrong without warning. These are perfect codes, so every received group sits next to some codeword and no decoder can notice, which is why a payload should also carry an AEAD tag.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'attack at dawn' },
        { name: 'scheme', label: 'Code', kind: 'select', value: 'Repetition-3', options: ['Repetition-3', 'Repetition-5', 'Hamming(7,4)'] },
      ],
      run(cb, { message, scheme }) {
        const id = { 'Repetition-3': 1, 'Repetition-5': 2, 'Hamming(7,4)': 3 }[scheme] || 1;
        const group = id === 1 ? 3 : id === 2 ? 5 : 7;
        const bound = id === 2 ? 2 : 1;
        const data = utf8.encode(message);
        const names = ['None', 'Repetition-3', 'Repetition-5', 'Hamming(7,4)'];
        const sizes = names.map((n, k) => [n, String(cb.call('fec_encode', data, k).length)]);
        const encoded = cb.call('fec_encode', data, id);
        const groups = Math.floor((data.length * 8 * (id === 3 ? 7 / 4 : group)) / group);
        const flip = (bytes, bit) => {
          bytes[bit >> 3] ^= 0x80 >> (bit & 7);
        };
        const noisy = Uint8Array.from(encoded);
        for (let g = 0; g < groups; g++) {
          for (let k = 0; k < bound; k++) flip(noisy, g * group + ((g + k * 2) % group));
        }
        const fixed = cb.call('fec_decode', noisy, id, data.length);
        const broken = Uint8Array.from(encoded);
        for (let k = 0; k <= bound; k++) flip(broken, k);
        const wrong = cb.call('fec_decode', broken, id, data.length);
        return [
          row.table('Encoded size of the message', ['Code', 'Bytes'], sizes),
          row.bytes(`${scheme} encoding`, encoded),
          row.text('Bits flipped', `${groups * bound} of ${encoded.length * 8}: ${bound} in every ${group}-bit group`),
          row.check('Every flipped bit is corrected', same(fixed, data), utf8.decode(fixed)),
          row.text('Past the bound', `${bound + 1} flips in the first group`),
          row.check('One flip past the bound decodes wrong, silently', !same(wrong, data), plain(utf8.decode(wrong))),
          refused('A truncated encoding is refused', () => cb.call('fec_decode', encoded.subarray(0, encoded.length >> 1), id, data.length)),
        ];
      },
    },
    {
      id: 'physical',
      title: 'Two files to open one message',
      statement: 'physical_seal derives the keys from one photo and hides the sealed message in another picture. Neither file alone opens it, and a photo one bit different is refused.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'the vault code is 4417' },
        { name: 'context', label: 'Context bound to the message', kind: 'text', value: 'safe deposit, box 12' },
        pictureInput,
        { name: 'photo', label: 'Key photo (optional upload)', kind: 'file', accept: '.bmp,.png,.ppm,.jpg,.jpeg,.wav' },
      ],
      run(cb, { message, context, carrier, photo }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const k = carrierFrom(photo, keyPhoto);
          const keyPath = ws.put(`key-photo${k.ext}`, k.bytes);
          const nudged = Uint8Array.from(k.bytes);
          nudged[nudged.length - 7] ^= 1;
          const nudgedPath = ws.put(`key-photo-nudged${k.ext}`, nudged);
          const cover = ws.put(`cover${c.ext}`, c.bytes);
          const out = ws.path(`sealed${outExt(c.ext)}`);
          cb.call('physical_seal', keyPath, message, context, cover, out);
          const back = cb.call('physical_open', keyPath, context, out);
          return [
            ...showCarrier('Key photo', k.bytes, k.ext, k.name),
            row.check('Key photo and stego picture together open it', same(back, utf8.encode(message)), utf8.decode(back)),
            refused('The stego picture alone yields nothing', () => cb.call('stego_extract', out)),
            refused('The key photo with one bit flipped is refused', () => cb.call('physical_open', nudgedPath, context, out)),
            refused('Another context is refused', () => cb.call('physical_open', keyPath, `${context}.`, out)),
            ...showCarrier('Stego picture', cb.readFile(out), outExt(c.ext), `sealed${outExt(c.ext)}`),
          ];
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'image-factor',
      title: 'A picture as a second factor',
      statement: 'image_factor_seal keys the message with an OPRF over a secret and a reference picture. Knowing the secret is not enough: the exact picture is needed too.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'wire the funds on monday' },
        { name: 'secret', label: 'Secret', kind: 'text', value: 'only the treasurer knows this' },
        pictureInput,
      ],
      run(cb, { message, secret, carrier }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const ref = makeBmp(192, 144, 42);
          const seed = cb.call('sha256', secret);
          const refPath = ws.put('reference.bmp', ref);
          const edited = Uint8Array.from(ref);
          edited[ref.length - 100] ^= 1;
          const editedPath = ws.put('reference-edited.bmp', edited);
          const otherPath = ws.put('other.bmp', makeBmp(192, 144, 43));
          const cover = ws.put(`cover${c.ext}`, c.bytes);
          const out = ws.path(`sealed${outExt(c.ext)}`);
          const aad = 'treasury/v1';
          cb.call('image_factor_seal', seed, refPath, message, aad, cover, out);
          const back = cb.call('image_factor_open', seed, refPath, aad, out);
          return [
            row.image('Reference picture', ref, 'image/bmp'),
            row.bytes('OPRF secret seed (SHA-256 of the secret)', seed),
            row.check('Secret and picture together open it', same(back, utf8.encode(message)), utf8.decode(back)),
            refused('Another picture is refused', () => cb.call('image_factor_open', seed, otherPath, aad, out)),
            refused('The picture with one bit changed is refused', () => cb.call('image_factor_open', seed, editedPath, aad, out)),
            refused('Another secret is refused', () => cb.call('image_factor_open', cb.call('sha256', `${secret}.`), refPath, aad, out)),
            ...showCarrier('Stego picture', cb.readFile(out), outExt(c.ext), `sealed${outExt(c.ext)}`),
          ];
        } finally {
          ws.clean();
        }
      },
    },
    {
      id: 'hpke',
      title: 'Public-key encryption inside a picture',
      statement: 'hpke_stego_seal encrypts to a recipient public key with HPKE and hides the ciphertext under a key from the same session. Only the recipient secret key finds and opens it.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'your new badge number is 7731' },
        { name: 'info', label: 'Context info', kind: 'text', value: 'badge office' },
        pictureInput,
      ],
      run(cb, { message, info, carrier }) {
        const ws = workspace(cb, DIR);
        try {
          const c = carrierFrom(carrier, picture);
          const recipient = cb.call('hpke_keygen');
          const stranger = cb.call('hpke_keygen');
          const cover = ws.put(`cover${c.ext}`, c.bytes);
          const out = ws.path(`sealed${outExt(c.ext)}`);
          const aad = 'mailroom';
          const enc = cb.call('hpke_stego_seal', recipient.public_key, message, aad, info, cover, out);
          const back = cb.call('hpke_stego_open', recipient.secret_key, enc, aad, info, out);
          const report = cb.call('stego_detect_hidden', out);
          return [
            row.bytes('Recipient public key (X25519)', recipient.public_key),
            row.bytes('Encapsulated key enc, sent beside the picture', enc),
            row.check('The recipient opens it', same(back, utf8.encode(message)), utf8.decode(back)),
            refused('Another secret key is refused', () => cb.call('hpke_stego_open', stranger.secret_key, enc, aad, info, out)),
            refused('Another context info is refused', () => cb.call('hpke_stego_open', recipient.secret_key, enc, aad, `${info}.`, out)),
            row.check('The detector finds no CipherBird payload', report.cipherbird_payload === 0, 'nothing found'),
            ...showCarrier('Stego picture', cb.readFile(out), outExt(c.ext), `sealed${outExt(c.ext)}`),
          ];
        } finally {
          ws.clean();
        }
      },
    },
  ],
};
