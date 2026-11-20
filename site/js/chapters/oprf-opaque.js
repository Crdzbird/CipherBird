import { row, mustRefuse } from '../kit.js';
import { same, hex, fromHex, utf8, flipBit } from '../bytes.js';

const rfcSeed = 'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3';
const rfcInfo = '74657374206b6579';
const rfcSecret = '5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e';
const rfcVectors = [
  ['00', '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706',
    '609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c',
    '7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e',
    '527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6'],
  ['5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a', '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706',
    'da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418',
    'b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25',
    'f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73'],
];

function contains(haystack, needle) {
  if (!needle.length) return false;
  for (let i = 0; i + needle.length <= haystack.length; i++) {
    if (needle.every((v, k) => haystack[i + k] === v)) return true;
  }
  return false;
}

function opaqueServer(cb) {
  return {
    keys: cb.call('oprf_derive_keypair', cb.call('random_bytes', 32), null),
    seed: cb.call('random_bytes', 64),
  };
}

function register(cb, server, user, password) {
  const request = cb.call('opaque_registration_request', password);
  const response = cb.call('opaque_registration_response', request.blinded_element, server.keys.public_key, user, server.seed);
  const record = cb.call('opaque_finalize_request', password, request.blind, response, null, null);
  return { request, response, record };
}

function login(cb, server, user, record, password, context = 'cipherbird demo', serverContext = context) {
  const ke1 = cb.call('opaque_client_init', password);
  const ke2 = cb.call('opaque_server_respond', serverContext, server.keys.secret_key, server.keys.public_key,
    record, user, server.seed, ke1.ke1, null, null);
  return { ke1, ke2, finish: () => cb.call('opaque_client_finish', ke1.client_state, ke2.ke2, context, null, null) };
}

export default {
  id: 'oprf-opaque',
  title: 'Oblivious functions and password login',
  lead: 'An OPRF lets a server compute a keyed function of your input without seeing it. OPAQUE builds a password login on top, where the server never receives the password, not even at registration.',
  demos: [
    {
      id: 'oprf-flow',
      title: 'A keyed hash the server cannot read',
      statement: 'The client blinds its input, the server evaluates the blinded point under its key, and the client unblinds. The result equals the server\'s own evaluation, yet the server saw only a random-looking point.',
      inputs: [{ name: 'input', label: 'Client input', kind: 'text', value: 'alice@example.com' }],
      run(cb, { input }) {
        const server = cb.call('oprf_derive_keypair', cb.call('random_bytes', 32), 'demo server');
        const first = cb.call('oprf_blind', input);
        const evaluated = cb.call('oprf_blind_evaluate', server.secret_key, first.blinded_element);
        const output = cb.call('oprf_finalize', input, first.blind, evaluated);
        const second = cb.call('oprf_blind', input);
        const output2 = cb.call('oprf_finalize', input, second.blind, cb.call('oprf_blind_evaluate', server.secret_key, second.blinded_element));
        const direct = cb.call('oprf_evaluate', server.secret_key, input);
        const otherKey = cb.call('oprf_derive_keypair', cb.call('random_bytes', 32), 'demo server');
        return [
          row.table('Message flow', ['Step', 'Direction', 'Size'], [
            ['blinded element', 'Client to server', `${first.blinded_element.length} bytes`],
            ['evaluated element', 'Server to client', `${evaluated.length} bytes`],
          ]),
          row.bytes('What the server saw (first run)', first.blinded_element),
          row.bytes('What the server saw (second run, same input)', second.blinded_element),
          row.bytes('PRF output', output),
          row.check('The blinded output equals the server\'s direct evaluation', same(output, direct), 'identical'),
          row.check('Same input, a new blinded element every time', !same(first.blinded_element, second.blinded_element), 'unlinkable'),
          row.check('Both runs unblind to the same output', same(output, output2), 'identical'),
          row.check('Another server key gives an unrelated output', !same(output, cb.call('oprf_evaluate', otherKey.secret_key, input)), 'keyed'),
        ];
      },
    },
    {
      id: 'oprf-rfc',
      title: 'RFC 9497 known answers',
      statement: 'With a fixed blind the protocol is deterministic. The engine reproduces the ristretto255-SHA512 base-mode vectors at every step: key, blinded element, evaluation and output.',
      inputs: [],
      run(cb) {
        const kp = cb.call('oprf_derive_keypair', fromHex(rfcSeed), fromHex(rfcInfo));
        const body = rfcVectors.map(([input, blind, blinded, evaluated, output]) => {
          const b = cb.call('oprf_blind_with_scalar', fromHex(input), fromHex(blind));
          const ev = cb.call('oprf_blind_evaluate', kp.secret_key, b.blinded_element);
          const out = cb.call('oprf_finalize', fromHex(input), b.blind, ev);
          const direct = cb.call('oprf_evaluate', kp.secret_key, fromHex(input));
          const ok = hex(b.blinded_element) === blinded && hex(ev) === evaluated && hex(out) === output && hex(direct) === output;
          return [input, `${input.length / 2} bytes`, ok ? 'match' : 'MISMATCH'];
        });
        return [
          row.bytes('Derived secret key', kp.secret_key),
          row.check('derive_keypair matches the vector key', hex(kp.secret_key) === rfcSecret, 'known answer'),
          row.table('Vectors', ['Input (hex)', 'Length', 'All four values'], body),
          row.check('Every vector matches', body.every((r) => r[2] === 'match'), `${body.length} vectors`),
        ];
      },
    },
    {
      id: 'opaque-login',
      title: 'Register, then log in',
      statement: 'Registration leaves the server a 192-byte record and no password. Login runs three messages, after which client and server hold the same 64-byte session key.',
      inputs: [
        { name: 'user', label: 'Username', kind: 'text', value: 'alice' },
        { name: 'password', label: 'Password', kind: 'text', value: 'correct horse battery staple' },
      ],
      run(cb, { user, password }) {
        const server = opaqueServer(cb);
        const reg = register(cb, server, user, password);
        const { record } = reg.record;
        const run = login(cb, server, user, record, password);
        const ke3 = run.finish();
        const serverKey = cb.call('opaque_server_finish', run.ke2.server_state, ke3.ke3);
        const pw = utf8.encode(password);
        const seenByServer = [reg.request.blinded_element, record, run.ke1.ke1, ke3.ke3];
        return [
          row.table('Messages', ['Phase', 'Message', 'Direction', 'Size'], [
            ['register', 'request', 'Client to server', `${reg.request.blinded_element.length} bytes`],
            ['register', 'response', 'Server to client', `${reg.response.length} bytes`],
            ['register', 'record', 'Client to server', `${record.length} bytes`],
            ['login', 'KE1', 'Client to server', `${run.ke1.ke1.length} bytes`],
            ['login', 'KE2', 'Server to client', `${run.ke2.ke2.length} bytes`],
            ['login', 'KE3', 'Client to server', `${ke3.ke3.length} bytes`],
          ]),
          row.table('What the server stores for this user', ['Field', 'Bytes'], [
            ['client public key', hex(record.subarray(0, 32))],
            ['masking key', hex(record.subarray(32, 96))],
            ['envelope nonce', hex(record.subarray(96, 128))],
            ['envelope MAC', hex(record.subarray(128, 192))],
          ]),
          row.bytes('Session key (client)', ke3.session_key),
          row.bytes('Session key (server)', serverKey),
          row.check('Both sides hold the same session key', same(ke3.session_key, serverKey), 'identical'),
          row.check('The client recovers the export key from registration', same(ke3.export_key, reg.record.export_key), 'identical'),
          row.check('The password bytes appear in nothing the server received or stored',
            pw.length < 4 || !seenByServer.some((m) => contains(m, pw)), pw.length < 4 ? 'password too short to search for' : 'not present'),
        ];
      },
    },
    {
      id: 'opaque-refusals',
      title: 'Wrong passwords and forged messages',
      statement: 'A wrong password fails on the client, which cannot open its envelope. The server in turn refuses a tampered final message, and a login bound to another context does not complete.',
      inputs: [
        { name: 'password', label: 'Registered password', kind: 'text', value: 'hunter2 but longer' },
        { name: 'guess', label: 'Password typed at login', kind: 'text', value: 'hunter3 but longer' },
      ],
      run(cb, { password, guess }) {
        const server = opaqueServer(cb);
        const { record } = register(cb, server, 'bob', password).record;
        const wrong = login(cb, server, 'bob', record, guess);
        const good = login(cb, server, 'bob', record, password);
        const ke3 = good.finish();
        const crossed = login(cb, server, 'bob', record, password, 'app A', 'app B');
        return [
          row.text('Server response to the wrong password', `KE2 of ${wrong.ke2.ke2.length} bytes; the right password gets ${good.ke2.ke2.length}`),
          guess === password
            ? row.check('The guess equals the password, so it logs in', wrong.finish().session_key.length === 64, 'logged in')
            : mustRefuse('The wrong password is refused by the client', () => wrong.finish()),
          mustRefuse('The server refuses a KE3 with one flipped bit', () => cb.call('opaque_server_finish', good.ke2.server_state, flipBit(ke3.ke3, 0))),
          row.check('The genuine KE3 completes', same(cb.call('opaque_server_finish', good.ke2.server_state, ke3.ke3), ke3.session_key), 'same key'),
          mustRefuse('A client and server bound to different contexts do not complete', () => crossed.finish()),
        ];
      },
    },
  ],
};
