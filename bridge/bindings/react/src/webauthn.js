// WebAuthn PRF factor provider.
//
// A passkey can emit a deterministic per-credential secret via the WebAuthn PRF
// extension (CTAP2 hmac-secret). That secret is a hardware/authenticator-backed
// 32-byte factor key for the CryptoLib keyring's device slot — nothing secret is
// stored in the browser, and the authenticator (Touch ID / Windows Hello /
// security key) performs user verification + liveness.
//
// Requires a real browser + platform authenticator over https or http://localhost.
// The factor is sent to the Node/koffi server (/api/keyring-with-factor), which
// wraps the keyring's master key under it. The browser never sees the master key.
//
// Note: not all authenticators implement PRF; getPrfFactorHex throws a clear
// error if the result is absent.

const RP_ID = location.hostname;
const PRF_SALT = new TextEncoder().encode('cryptolib:keyring:prf:v1');
const CRED_KEY = 'cryptolib.webauthn.credId';

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
function bytesToB64url(b) {
  return btoa(String.fromCharCode(...new Uint8Array(b)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Register a passkey with the PRF extension enabled; remembers its credential id. */
export async function enrollPasskey() {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { id: RP_ID, name: 'CryptoLib' },
      user: { id: rand(16), name: 'cryptolib-user', displayName: 'CryptoLib User' },
      challenge: rand(32),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      extensions: { prf: {} },
    },
  });
  localStorage.setItem(CRED_KEY, bytesToB64url(cred.rawId));
  return cred.id;
}

/** Derive the 32-byte PRF factor (hex) from the enrolled passkey. */
export async function getPrfFactorHex() {
  const idB64 = localStorage.getItem(CRED_KEY);
  const allowCredentials = idB64
    ? [{ type: 'public-key', id: b64urlToBytes(idB64) }]
    : [];
  const assertion = await navigator.credentials.get({
    publicKey: {
      rpId: RP_ID,
      challenge: rand(32),
      allowCredentials,
      userVerification: 'required',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const prf = assertion.getClientExtensionResults()?.prf?.results?.first;
  if (!prf) {
    throw new Error('Authenticator returned no PRF result (needs PRF / hmac-secret support).');
  }
  return hex(prf); // 32 bytes
}

export function hasPasskey() {
  return localStorage.getItem(CRED_KEY) != null;
}
