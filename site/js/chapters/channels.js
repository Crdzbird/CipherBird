import { row, mustRefuse } from '../kit.js';
import { same, utf8, flipBit } from '../bytes.js';

function noisePair(cb, prologueA, prologueB) {
  const a = cb.call('x25519_keygen');
  const b = cb.call('x25519_keygen');
  const i = cb.call('noise_create', 1, a.public_key, a.secret_key, prologueA);
  const r = cb.call('noise_create', 0, b.public_key, b.secret_key, prologueB);
  return { a, b, i, r };
}

function noiseHandshake(cb, i, r, payloads = ['', '', '']) {
  const flow = [];
  const steps = [[i, r, 'Initiator', 'Responder'], [r, i, 'Responder', 'Initiator'], [i, r, 'Initiator', 'Responder']];
  steps.forEach(([from, to, who, whom], k) => {
    const message = cb.call('noise_write_message', from, payloads[k] || null);
    const payload = utf8.decode(cb.call('noise_read_message', to, message));
    flow.push([`message ${k}`, `${who} to ${whom}`, `${message.length} bytes`, payload || '(none)']);
  });
  return flow;
}

function freeNoise(cb, pair) {
  if (pair && pair.i) cb.call('noise_free', pair.i);
  if (pair && pair.r) cb.call('noise_free', pair.r);
}

function freeSession(cb, name, ...handles) {
  for (const h of handles) if (h) cb.call(name, h);
}

const flowHead = ['Step', 'Direction', 'Size', 'Payload'];

export default {
  id: 'channels',
  title: 'Secure channels',
  lead: 'A Noise XX handshake and two post-quantum ratchets, with both parties running in this page. Every message below crosses from one engine handle to the other, so you can watch what goes over the wire.',
  demos: [
    {
      id: 'noise-handshake',
      title: 'A Noise XX handshake',
      statement: 'Three messages turn two static X25519 keys into an encrypted channel. Each side learns the other\'s static key and both end with the same handshake hash.',
      inputs: [
        { name: 'prologue', label: 'Prologue (both sides must agree)', kind: 'text', value: 'cipherbird demo v1' },
        { name: 'hello', label: 'Responder payload', kind: 'text', value: 'hello from the responder' },
      ],
      run(cb, { prologue, hello }) {
        let pair;
        let other;
        try {
          pair = noisePair(cb, prologue, prologue);
          const early = cb.call('noise_split', pair.i);
          const flow = noiseHandshake(cb, pair.i, pair.r, ['', hello, 'hello back']);
          const hi = cb.call('noise_handshake_hash', pair.i);
          const hr = cb.call('noise_handshake_hash', pair.r);
          const seenByI = cb.call('noise_remote_static', pair.i);
          const seenByR = cb.call('noise_remote_static', pair.r);
          other = noisePair(cb, prologue, `${prologue}!`);
          return [
            row.table('Handshake messages', flowHead, flow),
            row.bytes('Handshake hash (initiator)', hi),
            row.bytes('Handshake hash (responder)', hr),
            row.check('Both sides finished the handshake',
              cb.call('noise_handshake_finished', pair.i) === 1 && cb.call('noise_handshake_finished', pair.r) === 1, 'finished'),
            row.check('Both sides hold the same handshake hash', same(hi, hr), 'identical'),
            row.check('The initiator learned the responder\'s static key', same(seenByI, pair.b.public_key), 'matches'),
            row.check('The responder learned the initiator\'s static key', same(seenByR, pair.a.public_key), 'matches'),
            row.check('Split is refused before the handshake ends', early === 0, `returned ${early}`),
            mustRefuse('A peer with a different prologue cannot finish the handshake', () => noiseHandshake(cb, other.i, other.r)),
          ];
        } finally {
          freeNoise(cb, pair);
          freeNoise(cb, other);
        }
      },
    },
    {
      id: 'noise-transport',
      title: 'Records after the handshake',
      statement: 'After split, each record is sealed under a counter that only moves forward. A record changed in flight, sent under other associated data or played twice is refused.',
      inputs: [{ name: 'message', label: 'Record text', kind: 'text', value: 'move the meeting to noon' }],
      run(cb, { message }) {
        let pair;
        try {
          pair = noisePair(cb, null, null);
          noiseHandshake(cb, pair.i, pair.r);
          cb.call('noise_split', pair.i);
          cb.call('noise_split', pair.r);
          const ad = 'channel 7';
          const record = cb.call('noise_encrypt', pair.i, message, ad);
          const tampered = flipBit(record, 0);
          const refusedTamper = mustRefuse('A record with one flipped bit is refused', () => cb.call('noise_decrypt', pair.r, tampered, ad));
          const refusedAd = mustRefuse('The record under other associated data is refused', () => cb.call('noise_decrypt', pair.r, record, 'channel 8'));
          const opened = utf8.decode(cb.call('noise_decrypt', pair.r, record, ad));
          const replay = mustRefuse('The same record played again is refused', () => cb.call('noise_decrypt', pair.r, record, ad));
          const reply = cb.call('noise_encrypt', pair.r, 'noon works', ad);
          const back = utf8.decode(cb.call('noise_decrypt', pair.i, reply, ad));
          return [
            row.bytes('Record on the wire (ciphertext and 16-byte tag)', record),
            row.text('Size', `${record.length} bytes for ${utf8.encode(message).length} bytes of text`),
            refusedTamper,
            refusedAd,
            row.check('The original record still opens after the failed attempts', opened === message, opened),
            replay,
            row.check('The responder answers in the other direction', back === 'noon works', back),
          ];
        } finally {
          freeNoise(cb, pair);
        }
      },
    },
    {
      id: 'noise-out-of-order',
      title: 'Opening records that arrive out of order',
      statement: 'decrypt_at opens the record sent at a given counter without moving the channel. A record presented under the wrong counter does not authenticate.',
      inputs: [{ name: 'count', label: 'Records', kind: 'number', value: 4, min: 2, max: 8 }],
      run(cb, { count }) {
        const n = Math.max(2, Math.min(8, Number(count)));
        let pair;
        try {
          pair = noisePair(cb, null, null);
          noiseHandshake(cb, pair.i, pair.r);
          cb.call('noise_split', pair.i);
          cb.call('noise_split', pair.r);
          const texts = Array.from({ length: n }, (_, k) => `chunk ${k} of ${n}`);
          const records = texts.map((t) => cb.call('noise_encrypt', pair.i, t, null));
          const arrival = Array.from({ length: n }, (_, k) => n - 1 - k);
          const opened = new Array(n);
          const body = arrival.map((k) => {
            opened[k] = utf8.decode(cb.call('noise_decrypt_at', pair.r, k, records[k], null));
            return [k, `${records[k].length} bytes`, opened[k]];
          });
          const serial = utf8.decode(cb.call('noise_decrypt', pair.r, records[0], null));
          return [
            row.table('Arrival order, newest first', ['Counter', 'Size', 'Opened'], body),
            row.check('Every record opened and reassembles in order', opened.every((t, k) => t === texts[k]), `${n} records`),
            mustRefuse('A record tried under another counter is refused', () => cb.call('noise_decrypt_at', pair.r, 0, records[1], null)),
            row.check('decrypt_at did not move the channel: serial decrypt still starts at record 0', serial === texts[0], serial),
          ];
        } finally {
          freeNoise(cb, pair);
        }
      },
    },
    {
      id: 'ratchet',
      title: 'A post-quantum ratchet',
      statement: 'The responder publishes a hybrid KEM prekey and the initiator keys a session to it. Every message moves the ratchet, so the same text never encrypts the same way twice.',
      inputs: [{ name: 'message', label: 'First message', kind: 'text', value: 'are you there' }],
      run(cb, { message }) {
        let alice;
        let bob;
        try {
          const prekey = cb.call('session_generate_prekey');
          alice = cb.call('session_initiate', prekey.public_key);
          const handshake = cb.call('session_handshake', alice);
          bob = cb.call('session_accept', handshake, prekey.public_key, prekey.secret_key);
          const early = mustRefuse('The responder cannot send before it hears from the initiator',
            () => cb.call('session_encrypt', bob, 'too soon', null));
          const m1 = cb.call('session_encrypt', alice, message, null);
          const got1 = utf8.decode(cb.call('session_decrypt', bob, m1, null));
          const m2 = cb.call('session_encrypt', bob, 'yes, here', null);
          const got2 = utf8.decode(cb.call('session_decrypt', alice, m2, null));
          const m3 = cb.call('session_encrypt', alice, message, null);
          const got3 = utf8.decode(cb.call('session_decrypt', bob, m3, null));
          return [
            row.table('Message flow', ['Step', 'Direction', 'Size', 'Opened as'], [
              ['prekey', 'Responder publishes', `${prekey.public_key.length} bytes`, '(public key)'],
              ['handshake', 'Initiator to responder', `${handshake.length} bytes`, '(KEM ciphertext)'],
              ['message 1', 'Initiator to responder', `${m1.length} bytes`, got1],
              ['message 2', 'Responder to initiator', `${m2.length} bytes`, got2],
              ['message 3', 'Initiator to responder', `${m3.length} bytes`, got3],
            ]),
            row.text('Responder\'s own handshake message', `${cb.call('session_handshake', bob).length} bytes (only the initiator sends one)`),
            early,
            row.check('Both directions open', got1 === message && got2 === 'yes, here' && got3 === message, 'three messages'),
            row.check('The same text sent twice gives unrelated ciphertexts', !same(m1, m3), 'fresh keys per message'),
          ];
        } finally {
          freeSession(cb, 'session_free', alice, bob);
        }
      },
    },
    {
      id: 'ratchet-disorder',
      title: 'Late, lost and replayed messages',
      statement: 'The ratchet opens messages in any order it receives them, keeping keys for the ones it skipped. Each key is used once, so a replayed or altered message is refused.',
      inputs: [{ name: 'count', label: 'Messages', kind: 'number', value: 4, min: 2, max: 8 }],
      run(cb, { count }) {
        const n = Math.max(2, Math.min(8, Number(count)));
        let alice;
        let bob;
        try {
          const prekey = cb.call('session_generate_prekey');
          alice = cb.call('session_initiate', prekey.public_key);
          bob = cb.call('session_accept', cb.call('session_handshake', alice), prekey.public_key, prekey.secret_key);
          const texts = Array.from({ length: n }, (_, k) => `note ${k}`);
          const sent = texts.map((t) => cb.call('session_encrypt', alice, t, 'thread 42'));
          const order = Array.from({ length: n }, (_, k) => n - 1 - k);
          const tampered = mustRefuse('An altered message is refused',
            () => cb.call('session_decrypt', bob, flipBit(sent[order[0]], -1), 'thread 42'));
          const wrongAad = mustRefuse('A message under other associated data is refused',
            () => cb.call('session_decrypt', bob, sent[order[0]], 'thread 43'));
          const body = order.map((k, step) => [step + 1, `note ${k}`, utf8.decode(cb.call('session_decrypt', bob, sent[k], 'thread 42'))]);
          const replay = mustRefuse('A replayed message is refused', () => cb.call('session_decrypt', bob, sent[0], 'thread 42'));
          const reply = cb.call('session_encrypt', bob, 'all received', null);
          const back = utf8.decode(cb.call('session_decrypt', alice, reply, null));
          return [
            row.table('Delivered newest first', ['Arrival', 'Sent as', 'Opened as'], body),
            row.check('Every message opened despite the order', body.every((r) => r[1] === r[2]), `${n} messages`),
            tampered,
            wrongAad,
            replay,
            row.check('Failed attempts left the session usable', back === 'all received', back),
          ];
        } finally {
          freeSession(cb, 'session_free', alice, bob);
        }
      },
    },
    {
      id: 'session2',
      title: 'An authenticated ratchet',
      statement: 'In session v2 the prekey is signed by the responder\'s identity and the initiator signs the handshake. Both identities are hybrid Ed25519 plus ML-DSA-65 keys.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'it is me, Alice' }],
      run(cb, { message }) {
        let alice;
        let bob;
        try {
          const aliceId = cb.call('hybrid_sig_keygen');
          const bobId = cb.call('hybrid_sig_keygen');
          const prekey = cb.call('session2_generate_prekey', bobId.secret_key);
          const xwing = cb.call('session2_verify_prekey', prekey.public_key, bobId.public_key);
          alice = cb.call('session2_initiate', prekey.public_key, bobId.public_key, aliceId.public_key, aliceId.secret_key);
          const handshake = cb.call('session2_handshake', alice);
          const claimed = cb.call('session2_claimed_initiator', handshake);
          bob = cb.call('session2_accept', handshake, prekey.public_key, prekey.secret_key,
            bobId.public_key, bobId.secret_key, claimed);
          const m1 = cb.call('session2_encrypt', alice, message, 'aad');
          const got1 = utf8.decode(cb.call('session2_decrypt', bob, m1, 'aad'));
          const m2 = cb.call('session2_encrypt', bob, 'welcome back', null);
          const got2 = utf8.decode(cb.call('session2_decrypt', alice, m2, null));
          return [
            row.table('Message flow', ['Step', 'Direction', 'Size', 'Opened as'], [
              ['prekey bundle', 'Responder publishes', `${prekey.public_key.length} bytes`, '(signed X-Wing key)'],
              ['handshake', 'Initiator to responder', `${handshake.length} bytes`, '(signed by the initiator)'],
              ['message 1', 'Initiator to responder', `${m1.length} bytes`, got1],
              ['message 2', 'Responder to initiator', `${m2.length} bytes`, got2],
            ]),
            row.text('Prekey secret the responder keeps', `${prekey.secret_key.length}-byte X-Wing seed`),
            row.check('The bundle verifies under the responder\'s identity', xwing.length > 0, `${xwing.length}-byte X-Wing key inside`),
            row.check('The handshake names the initiator: Alice\'s identity', same(claimed, aliceId.public_key), `${claimed.length}-byte hybrid key`),
            row.check('Messages carry the v2 tag', utf8.decode(m1.subarray(0, 4)) === 'RTC2', utf8.decode(m1.subarray(0, 4))),
            row.check('Both directions open', got1 === message && got2 === 'welcome back', 'two messages'),
            mustRefuse('A replayed message is refused', () => cb.call('session2_decrypt', bob, m1, 'aad')),
          ];
        } finally {
          freeSession(cb, 'session2_free', alice, bob);
        }
      },
    },
    {
      id: 'session2-impostors',
      title: 'Impostors on both ends',
      statement: 'Mallory tries to stand in for Bob with her own prekey and for Alice with her own handshake. The signatures give her away each time.',
      inputs: [],
      run(cb) {
        let real;
        let fake;
        let bob;
        try {
          const aliceId = cb.call('hybrid_sig_keygen');
          const bobId = cb.call('hybrid_sig_keygen');
          const malloryId = cb.call('hybrid_sig_keygen');
          const bobPrekey = cb.call('session2_generate_prekey', bobId.secret_key);
          const malloryPrekey = cb.call('session2_generate_prekey', malloryId.secret_key);
          real = cb.call('session2_initiate', bobPrekey.public_key, bobId.public_key, aliceId.public_key, aliceId.secret_key);
          const handshake = cb.call('session2_handshake', real);
          fake = cb.call('session2_initiate', bobPrekey.public_key, bobId.public_key, malloryId.public_key, malloryId.secret_key);
          const forged = cb.call('session2_handshake', fake);
          const claimed = cb.call('session2_claimed_initiator', forged);
          const accept = (hs, expected) => cb.call('session2_accept', hs, bobPrekey.public_key, bobPrekey.secret_key,
            bobId.public_key, bobId.secret_key, expected);
          const rows = [
            mustRefuse('Mallory\'s prekey, presented as Bob\'s, fails verification',
              () => cb.call('session2_verify_prekey', malloryPrekey.public_key, bobId.public_key)),
            mustRefuse('Alice refuses to start a session to it',
              () => cb.call('session2_initiate', malloryPrekey.public_key, bobId.public_key, aliceId.public_key, aliceId.secret_key)),
            mustRefuse('Bob\'s own bundle with one bit flipped fails verification',
              () => cb.call('session2_verify_prekey', flipBit(bobPrekey.public_key, 40), bobId.public_key)),
            row.check('Mallory\'s handshake honestly claims Mallory', same(claimed, malloryId.public_key), 'claimed initiator'),
            mustRefuse('Bob, expecting Alice, refuses Mallory\'s handshake', () => accept(forged, aliceId.public_key)),
            mustRefuse('Alice\'s handshake with one bit flipped is refused', () => accept(flipBit(handshake, -1), aliceId.public_key)),
          ];
          bob = accept(handshake, aliceId.public_key);
          rows.push(row.check('The genuine handshake from Alice is accepted', bob !== 0, 'accepted'));
          return rows;
        } finally {
          freeSession(cb, 'session2_free', real, fake, bob);
        }
      },
    },
  ],
};
