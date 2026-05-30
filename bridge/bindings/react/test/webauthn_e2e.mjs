// End-to-end WebAuthn test with a Chrome *virtual authenticator* (PRF-enabled).
//
// Drives the real passkey ceremony — navigator.credentials.create/get with the
// PRF extension — against the live React UI + Node/koffi server, then asserts the
// keyring unlocked under the authenticator-derived factor. No physical biometric
// needed: CDP's virtual authenticator simulates user verification + presence.
//
// Run (see Makefile target `react-webauthn-test`):
//   cd bridge/react && npm install && npm run build
//   node test/webauthn_e2e.mjs

import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PORT = 8787;
const reactDir = fileURLToPath(new URL('..', import.meta.url));
const dylib = process.env.CRYPTOLIB_DYLIB
  || fileURLToPath(new URL('../../../../build/release/libcryptolib_c.dylib', import.meta.url));

function fail(msg) { console.error('WEBAUTHN E2E FAIL:', msg); process.exit(1); }

// 1. Start the server (serves UI + /api).
const srv = spawn('node', ['server.mjs'], {
  cwd: reactDir,
  env: { ...process.env, CRYPTOLIB_DYLIB: dylib },
  stdio: 'inherit',
});
const cleanup = () => { try { srv.kill('SIGKILL'); } catch {} };
process.on('exit', cleanup);

await new Promise((r) => setTimeout(r, 1500));

const browser = await chromium.launch();
try {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  // 2. Install a PRF-capable virtual authenticator via CDP.
  const client = await ctx.newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  });

  // 3. Load the app and run the passkey → keyring flow via the button.
  await page.goto(`http://localhost:${PORT}/`, { waitUntil: 'load' });
  await page.getByRole('button', { name: /passkey/i }).click();

  // 4. The result <pre> must report the keyring unlocked (ok: true).
  await page.waitForFunction(() => {
    const pre = document.querySelector('pre');
    return pre && pre.textContent.includes('"ok": true');
  }, { timeout: 20000 });

  const result = (await page.locator('pre').textContent()).replace(/\s+/g, ' ').trim();
  console.log('WebAuthn PRF → keyring result:', result);
  console.log('WEBAUTHN E2E OK');
} catch (e) {
  fail(e.message);
} finally {
  await browser.close();
  cleanup();
}
