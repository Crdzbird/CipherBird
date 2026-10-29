/*
 * Heavy work off the main thread: cipherbird.async.<method>(...args) runs
 * any data-in, data-out method of the flat API on one long-lived worker
 * thread and resolves with its result, the way the Dart packages move
 * Argon2id, the post-quantum signatures and the media methods to a
 * background isolate. Arguments and results travel by structured clone, so
 * Buffers, strings, numbers, plain objects and arrays work; native handles
 * (keyrings, vaults, sessions) do not and must stay on the thread that made
 * them. The worker is unreferenced while idle, so it never keeps the process
 * alive; close() ends it early.
 */
'use strict';
const path = require('node:path');

const revive = (v) => {
  if (v instanceof Uint8Array && !Buffer.isBuffer(v)) return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
  if (Array.isArray(v)) return v.map(revive);
  if (v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
    const o = {};
    for (const [k, x] of Object.entries(v)) o[k] = revive(x);
    return o;
  }
  return v;
};

module.exports = (api) => {
  let worker = null;
  let seq = 0;
  const pending = new Map();

  function ensureWorker() {
    if (worker) return worker;
    const { Worker } = require('node:worker_threads');
    worker = new Worker(path.join(__dirname, 'async_worker.js'), { workerData: { modulePath: path.join(__dirname, '..', 'index.js') } });
    worker.on('message', (m) => {
      const p = pending.get(m.id);
      if (!p) return;
      pending.delete(m.id);
      if (pending.size === 0) worker.unref();
      if (m.ok) p.resolve(revive(m.value)); else p.reject(new Error(m.error));
    });
    const fail = (err) => {
      for (const p of pending.values()) p.reject(err instanceof Error ? err : new Error(String(err)));
      pending.clear();
      worker = null;
    };
    worker.on('error', fail);
    worker.on('exit', (code) => { if (pending.size) fail(new Error(`cipherbird: worker exited with code ${code}`)); worker = null; });
    worker.unref();
    return worker;
  }

  /** Run `method` (a dotted path into the API, such as 'suite2Seal' or 'Fips.digest') on the worker. */
  function run(method, ...args) {
    return new Promise((resolve, reject) => {
      const id = ++seq;
      pending.set(id, { resolve, reject });
      const w = ensureWorker();
      w.ref();
      w.postMessage({ id, method, args });
    });
  }

  const handler = {
    get(target, prop) {
      if (prop in target) return target[prop];
      if (typeof prop !== 'string') return undefined;
      return (...args) => run(prop, ...args);
    },
  };
  const asyncApi = new Proxy({
    run,
    /** End the worker; it restarts on the next call. */
    close() { if (worker) { const w = worker; worker = null; return w.terminate(); } return Promise.resolve(0); },
    /** Whether a worker is currently alive. */
    get alive() { return worker !== null; },
  }, handler);

  const named = {};
  for (const m of ['mlDsaKeygen', 'slhDsaKeygen', 'hybridSigSign', 'keyFromBytes', 'mlDsaSign', 'slhDsaSign',
    'stegoEmbedBytes', 'stegoEmbedEncryptedBytes', 'stegoExtractBytes', 'stegoExtractDecryptBytes',
    'suite2Open', 'suite2Seal', 'argon2idDerive', 'argon2idHashStr', 'argon2idVerifyStr']) {
    named[`${m}Async`] = (...args) => run(m, ...args);
  }
  void api;
  return { async: asyncApi, runAsync: run, ...named };
};
