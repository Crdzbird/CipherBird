import { row } from '../kit.js';
import { same, utf8, base64 } from '../bytes.js';

const CODES = { 0: 'OK', '-1': 'INVALID', '-2': 'ARGUMENT', '-3': 'INTERNAL', '-4': 'UNAVAILABLE', '-5': 'FORMAT' };
const CLAIMS = '{"sub":"alice@example.com","scope":"invoices:read","iat":"2026-11-20T09:00:00Z","exp":"2026-11-20T10:00:00Z"}';

const code = (rc) => `${rc} (${CODES[rc] || 'unknown'})`;

/** A check row for a token call that must return CIPHERBIRD_TOKEN_ERR_INVALID; 0 means accepted here. */
function rejected(label, rc) {
  return row.check(label, rc === -1, rc === 0 ? 'accepted' : `refused: ${code(rc)}`);
}

function b64url(bytes) {
  return base64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(text) {
  const bin = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function keygen(cb, format) {
  const table = formats(cb).find((f) => f.format === format);
  const secret = cb.Out.bytes(table.key_bytes || table.secret_key_bytes);
  const pub = cb.Out.bytes(table.public_key_bytes);
  const rc = cb.call('token_keygen', format, secret, pub);
  return { rc, secret: secret.value, pub: pub.value };
}

function formats(cb) {
  const need = cb.call('token_formats', cb.Out.text(0));
  const out = cb.Out.text(need);
  cb.call('token_formats', out);
  return JSON.parse(out.value);
}

function issue(cb, format, key, payload, footer, implicit) {
  const out = cb.Out.bytes(cb.call('token_issue_len', format, utf8.encode(payload).length, utf8.encode(footer || '').length));
  const rc = cb.call('token_issue', format, out, key, payload, footer || null, implicit || null);
  return { rc, token: out.value };
}

function accept(cb, format, token, key, footer, implicit) {
  const out = cb.Out.bytes(cb.call('token_accept_cap', format, token.length));
  const rc = cb.call('token_accept', format, out, token, key, footer || null, implicit || null);
  return { rc, payload: out.value };
}

export default {
  id: 'tokens',
  title: 'Tokens: PASETO v4.local and cb1',
  lead: 'Encrypted and signed tokens for sessions and APIs. One set of functions takes the format as an argument, and the token never chooses its own algorithm.',
  demos: [
    {
      id: 'formats',
      title: 'The formats this engine knows',
      statement: 'token_formats publishes the table every other call works from: purpose, key sizes and limits. Sizing calls give exact token lengths, so buffers are allocated once.',
      inputs: [{ name: 'payload', label: 'Payload for the size column', kind: 'textarea', value: CLAIMS }],
      run(cb, { payload }) {
        const list = formats(cb);
        const n = utf8.encode(payload).length;
        const body = list.map((f) => [f.format, f.purpose, f.standard,
          f.purpose === 'local' ? `${f.key_bytes}` : `${f.secret_key_bytes} / ${f.public_key_bytes}`,
          `${f.signature_bytes}`, `${cb.call('token_issue_len', f.format, n, 12)}`, f.available ? 'yes' : 'no']);
        return [
          row.table('token_formats', ['Format', 'Purpose', 'Standard', 'Key bytes (secret / public)', 'Signature bytes',
            `Token length for ${n} + 12 bytes`, 'Available'], body),
          row.check('All three formats are listed', ['v4.local', 'cb1.local', 'cb1.public'].every((f) => list.some((x) => x.format === f)),
            list.map((f) => f.format).join(', ')),
          row.check('Generic and per-format sizes agree',
            cb.call('token_issue_len', 'v4.local', n, 12) === cb.call('paseto_v4_local_encrypt_len', n, 12)
            && cb.call('token_issue_len', 'cb1.local', n, 12) === cb.call('cb1_local_encrypt_len', n, 12)
            && cb.call('token_issue_len', 'cb1.public', n, 12) === cb.call('cb1_public_sign_len', n, 12), 'identical'),
          row.check('An unknown format has no size', cb.call('token_issue_len', 'v9.local', n, 0) === 0, '0'),
          row.check('An unknown format is refused by name', issue(cb, 'v9.local', new Uint8Array(32), payload).rc === -5, code(-5)),
        ];
      },
    },
    {
      id: 'v4-local',
      title: 'An encrypted session token',
      statement: 'PASETO v4.local encrypts the claims with XChaCha20 and authenticates them with keyed BLAKE2b. The implicit assertion is authenticated but never stored, so a token only works in the context it was issued for.',
      inputs: [
        { name: 'claims', label: 'Claims', kind: 'textarea', value: CLAIMS },
        { name: 'implicit', label: 'Implicit assertion', kind: 'text', value: 'tenant=acme' },
      ],
      run(cb, { claims, implicit }) {
        const key = keygen(cb, 'v4.local');
        const issued = issue(cb, 'v4.local', key.secret, claims, '', implicit);
        const text = utf8.decode(issued.token);
        const ok = accept(cb, 'v4.local', issued.token, key.secret, '', implicit);
        const viaPaseto = cb.Out.bytes(cb.call('paseto_v4_local_decrypt_cap', issued.token.length));
        const prc = cb.call('paseto_v4_local_decrypt', viaPaseto, issued.token, key.secret, null, implicit);
        const direct = cb.Out.bytes(cb.call('paseto_v4_local_encrypt_len', utf8.encode(claims).length, 0));
        cb.call('paseto_v4_local_encrypt', direct, key.secret, claims, null, implicit);
        const changed = utf8.encode(text.slice(0, 20) + (text[20] === 'A' ? 'B' : 'A') + text.slice(21));
        return [
          row.bytes('Key (token_keygen v4.local)', key.secret),
          row.text('Token', text),
          row.check('token_accept returns the claims', ok.rc === 0 && same(ok.payload, utf8.encode(claims)), utf8.decode(ok.payload)),
          row.text('Expires', `${JSON.parse(utf8.decode(ok.payload)).exp || 'no exp claim'} (checking it is the application's job)`),
          row.check('The PASETO-named function accepts the same token', prc === 0 && same(viaPaseto.value, ok.payload), code(prc)),
          row.check('token_accept accepts a token from paseto_v4_local_encrypt',
            accept(cb, 'v4.local', direct.value, key.secret, '', implicit).rc === 0, 'same format, same code path'),
          rejected('Another implicit assertion is refused', accept(cb, 'v4.local', issued.token, key.secret, '', 'tenant=globex').rc),
          rejected('Another key is refused', accept(cb, 'v4.local', issued.token, keygen(cb, 'v4.local').secret, '', implicit).rc),
          rejected('One changed character is refused', accept(cb, 'v4.local', changed, key.secret, '', implicit).rc),
        ];
      },
    },
    {
      id: 'footer',
      title: 'A footer anyone can read, nobody can change',
      statement: 'The footer travels in clear, usually with a key id, so a server can pick the key before it verifies. It is covered by the tag, and accept compares it with the footer the caller expects.',
      inputs: [
        { name: 'kid', label: 'Key id', kind: 'text', value: 'k-2026-11' },
        { name: 'claims', label: 'Claims', kind: 'textarea', value: CLAIMS },
      ],
      run(cb, { kid, claims }) {
        const footer = JSON.stringify({ kid });
        const forgedFooter = JSON.stringify({ kid: `${kid}-old` });
        const key = keygen(cb, 'v4.local').secret;
        const { token } = issue(cb, 'v4.local', key, claims, footer);
        const peek = cb.Out.bytes(token.length);
        const prc = cb.call('token_peek_footer', token, peek);
        const fmt = cb.Out.text(32);
        cb.call('token_peek_format', token, fmt);
        const parts = utf8.decode(token).split('.');
        const swapped = utf8.encode([...parts.slice(0, 3), b64url(utf8.encode(forgedFooter))].join('.'));
        return [
          row.text('Token', utf8.decode(token)),
          row.text('token_peek_format, no key needed', fmt.value),
          row.check('token_peek_footer reads the key id without the key', prc === 0 && utf8.decode(peek.value) === footer, utf8.decode(peek.value)),
          row.check('The footer is plain base64url of the JSON', parts[3] === b64url(utf8.encode(footer)), parts[3]),
          row.check('Accepted with the expected footer', accept(cb, 'v4.local', token, key, footer).rc === 0, 'valid'),
          rejected('Accept with another expected footer is refused', accept(cb, 'v4.local', token, key, forgedFooter).rc),
          rejected('A rewritten footer is refused even when expected', accept(cb, 'v4.local', swapped, key, forgedFooter).rc),
          rejected('Removing the footer is refused', accept(cb, 'v4.local', utf8.encode(parts.slice(0, 3).join('.')), key, '').rc),
        ];
      },
    },
    {
      id: 'no-confusion',
      title: 'The caller picks the format, not the token',
      statement: 'cb1.local is PASETO v4.local with BLAKE3 in place of BLAKE2b, so both take a 32-byte key. Accept compares the header with the format the caller names before it touches the key, and neither format passes for the other.',
      inputs: [{ name: 'claims', label: 'Claims', kind: 'textarea', value: CLAIMS }],
      run(cb, { claims }) {
        const key = keygen(cb, 'v4.local').secret;
        const v4 = issue(cb, 'v4.local', key, claims).token;
        const cbLen = cb.call('cb1_local_encrypt_len', utf8.encode(claims).length, 0);
        const cbOut = cb.Out.bytes(cbLen);
        const crc = cb.call('cb1_local_encrypt', cbOut, key, claims, null, null);
        const cb1 = cbOut.value;
        const back = cb.Out.bytes(cb.call('cb1_local_decrypt_cap', cb1.length));
        const brc = cb.call('cb1_local_decrypt', back, cb1, key, null, null);
        const relabelled = utf8.encode(utf8.decode(v4).replace(/^v4\.local\./, 'cb1.local.'));
        const v4Into = cb.Out.bytes(cb.call('cb1_local_decrypt_cap', v4.length));
        const allow = ['cb1.local'];
        const fmt = cb.Out.text(32);
        cb.call('token_peek_format', v4, fmt);
        return [
          row.text('v4.local token', utf8.decode(v4)),
          row.text('cb1.local token, same key and claims', utf8.decode(cb1)),
          row.check('cb1_local_encrypt and _decrypt round trip', crc === 0 && brc === 0 && same(back.value, utf8.encode(claims)), code(brc)),
          row.check('The generic accept takes the cb1 token as cb1.local', accept(cb, 'cb1.local', cb1, key).rc === 0, 'valid'),
          rejected('The v4.local token offered as cb1.local is refused', accept(cb, 'cb1.local', v4, key).rc),
          rejected('cb1_local_decrypt refuses it too', cb.call('cb1_local_decrypt', v4Into, v4, key, null, null)),
          rejected('The cb1 token offered as v4.local is refused', accept(cb, 'v4.local', cb1, key).rc),
          rejected('Relabelling the header to cb1.local is refused', accept(cb, 'cb1.local', relabelled, key).rc),
          row.check('A rotation-time verifier peeks, then checks its allow-list', !allow.includes(fmt.value),
            `peeked "${fmt.value}", allowed ${allow.join(', ')}: not passed to accept`),
        ];
      },
    },
    {
      id: 'cb1-public',
      title: 'A token signed with Ed25519 and ML-DSA-65',
      statement: 'cb1.public carries both an Ed25519 and an ML-DSA-65 signature, and both must verify, so a forgery needs a break of each. The token is signed, not encrypted: anyone can read the claims, nobody can change them.',
      inputs: [
        { name: 'claims', label: 'Claims', kind: 'textarea', value: CLAIMS },
        { name: 'kid', label: 'Key id', kind: 'text', value: 'issuer-2026' },
      ],
      run(cb, { claims, kid }) {
        const pair = keygen(cb, 'cb1.public');
        const footer = JSON.stringify({ kid });
        const n = utf8.encode(claims).length;
        const out = cb.Out.bytes(cb.call('cb1_public_sign_len', n, utf8.encode(footer).length));
        const src = cb.call('cb1_public_sign', out, pair.secret, claims, footer, null);
        const token = out.value;
        const verified = cb.Out.bytes(cb.call('cb1_public_verify_cap', token.length));
        const vrc = cb.call('cb1_public_verify', verified, token, pair.pub, footer, null);
        const parts = utf8.decode(token).split('.');
        const body = fromB64url(parts[2]);
        const edited = Uint8Array.from(body);
        edited.set(utf8.encode('mallory'), utf8.encode('{"sub":"').length);
        const forged = utf8.encode([parts[0], parts[1], b64url(edited), parts[3]].join('.'));
        const other = keygen(cb, 'cb1.public');
        const generic = issue(cb, 'cb1.public', pair.secret, claims, footer);
        return [
          row.text('Key sizes', `secret ${pair.secret.length} bytes, public ${pair.pub.length} bytes`),
          row.text('Token length', `${token.length} characters, signature ${body.length - n} bytes`),
          row.text('Token (start)', `${utf8.decode(token).slice(0, 72)}...`),
          row.check('cb1_public_verify returns the claims', src === 0 && vrc === 0 && same(verified.value, utf8.encode(claims)), code(vrc)),
          row.check('The claims are readable without any key', same(body.subarray(0, n), utf8.encode(claims)), utf8.decode(body.subarray(0, n))),
          row.check('token_accept verifies a token from token_issue', generic.rc === 0
            && accept(cb, 'cb1.public', generic.token, pair.pub, footer).rc === 0, 'valid'),
          rejected('An edited subject is refused', accept(cb, 'cb1.public', forged, pair.pub, footer).rc),
          rejected('Another issuer\'s public key is refused', accept(cb, 'cb1.public', token, other.pub, footer).rc),
          rejected('Another expected footer is refused', accept(cb, 'cb1.public', token, pair.pub, '{"kid":"other"}').rc),
        ];
      },
    },
  ],
};
