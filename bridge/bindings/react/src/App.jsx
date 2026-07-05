import React, { useState } from 'react';
import { enrollPasskey, getPrfFactorHex, hasPasskey } from './webauthn.js';

// The browser can't load a native .dylib, so the UI calls the Node+koffi server
// (server.mjs), which performs the crypto using the real CryptoLib native library.
async function api(path, body) {
  const res = await fetch('/api/' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export default function App() {
  const [version, setVersion] = useState('');
  const [text, setText] = useState('hello from react');
  const [out, setOut] = useState(null);
  const [showcase, setShowcase] = useState(null);
  const [err, setErr] = useState('');

  const call = (fn) => async () => {
    setErr('');
    try { await fn(); } catch (e) { setErr(String(e)); }
  };

  return (
    <main style={{ fontFamily: 'system-ui', maxWidth: 640, margin: '2rem auto', padding: '0 1rem' }}>
      <h1>CryptoLib · React</h1>
      <p style={{ color: '#666' }}>
        React UI → <code>/api</code> → Node + koffi → native <code>libcryptolib_c</code>.
      </p>

      <button onClick={call(async () => setVersion((await api('version')).version))}>
        Get version
      </button>{' '}
      {version && <span>v{version}</span>}

      <hr />

      <label>
        Plaintext:{' '}
        <input value={text} onChange={(e) => setText(e.target.value)} style={{ width: 280 }} />
      </label>
      <div style={{ marginTop: 8 }}>
        <button onClick={call(async () => setOut(await api('sha256', { text })))}>
          SHA-256
        </button>{' '}
        <button onClick={call(async () => setOut(await api('seal-open', { text })))}>
          Vault seal → open
        </button>{' '}
        <button onClick={call(async () => setOut(await api('keyring')))}>
          Keyring (device + passphrase)
        </button>{' '}
        <button onClick={call(async () => setOut(await api('molecular', { text, passphrase: 'a good passphrase' })))}>
          MolecularVault (cascade + PQC)
        </button>{' '}
        <button onClick={call(async () => setOut(await api('evm', { text })))}>
          EVM: Keccak-256 + secp256k1
        </button>
      </div>

      <p style={{ marginTop: 12, color: '#666' }}>
        Unlock the keyring with a passkey — the authenticator's WebAuthn PRF secret
        becomes the device factor (needs a browser + Touch ID / security key):
      </p>
      <button
        onClick={call(async () => {
          if (!hasPasskey()) await enrollPasskey();
          const factorHex = await getPrfFactorHex();
          setOut(await api('keyring-with-factor', { factorHex }));
        })}
      >
        Unlock keyring with passkey (WebAuthn PRF)
      </button>

      {out && (
        <pre style={{ background: '#f5f5f5', padding: 12, marginTop: 12, overflowX: 'auto' }}>
          {JSON.stringify(out, null, 2)}
        </pre>
      )}

      <hr />

      <p style={{ color: '#666' }}>
        Run the full Node showcase (every capability family — hashing, symmetric,
        asymmetric, vaults, post-quantum, BLS, keyring) against the native library:
      </p>
      <button onClick={call(async () => setShowcase(await api('showcase')))}>
        Run full showcase
      </button>
      {showcase && (
        <pre style={{
          background: showcase.ok ? '#f0fff0' : '#fff0f0',
          border: `1px solid ${showcase.ok ? '#8c8' : '#c88'}`,
          padding: 12, marginTop: 12, overflowX: 'auto', whiteSpace: 'pre-wrap',
          fontFamily: 'ui-monospace, monospace', fontSize: 13,
        }}>
          {showcase.output}
        </pre>
      )}

      {err && <p style={{ color: 'crimson' }}>{err}</p>}
    </main>
  );
}
