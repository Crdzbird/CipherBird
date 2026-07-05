'use client';
import { useState } from 'react';

async function call(op, body = {}) {
  const res = await fetch('/api/crypto', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ op, ...body }),
  });
  return res.json();
}

export default function Home() {
  const [text, setText] = useState('hello from next.js');
  const [out, setOut] = useState(null);
  const [err, setErr] = useState('');
  const run = (op) => async () => {
    setErr('');
    try { setOut(await call(op, { text })); } catch (e) { setErr(String(e)); }
  };

  const btn = { marginRight: 8, marginTop: 8, padding: '6px 10px' };
  return (
    <main style={{ fontFamily: 'system-ui', maxWidth: 680, margin: '2rem auto', padding: '0 1rem' }}>
      <h1>CryptoLib · Next.js</h1>
      <p style={{ color: '#666' }}>
        Client → <code>/api/crypto</code> (Node runtime route handler) →{' '}
        <code>cryptolib-node</code> → native <code>libcryptolib_c</code>. Native FFI
        runs only on the server; the browser never loads the library.
      </p>
      <label>
        Plaintext:{' '}
        <input value={text} onChange={(e) => setText(e.target.value)} style={{ width: 300 }} />
      </label>
      <div>
        <button style={btn} onClick={run('version')}>Version</button>
        <button style={btn} onClick={run('sha256')}>SHA-256</button>
        <button style={btn} onClick={run('molecular')}>MolecularVault (cascade + PQC)</button>
        <button style={btn} onClick={run('evm')}>EVM: Keccak-256 + secp256k1</button>
      </div>
      {out && (
        <pre style={{ background: '#f5f5f5', padding: 12, marginTop: 12, overflowX: 'auto' }}>
          {JSON.stringify(out, null, 2)}
        </pre>
      )}
      {err && <p style={{ color: 'crimson' }}>{err}</p>}
    </main>
  );
}
