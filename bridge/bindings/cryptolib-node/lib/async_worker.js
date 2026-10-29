/* The worker behind cipherbird.async: loads the engine once and runs the methods it is sent. */
'use strict';
const { parentPort, workerData } = require('node:worker_threads');
const api = require(workerData.modulePath);

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

const plain = (v) => {
  if (Buffer.isBuffer(v)) return v;
  if (Array.isArray(v)) return v.map(plain);
  if (v && typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v)) {
      const x = v[k];
      if (typeof x !== 'function') o[k] = plain(x);
    }
    return o;
  }
  return v;
};

function resolveMethod(method) {
  let target = api;
  let owner = null;
  for (const part of String(method).split('.')) {
    if (target == null || !(part in target)) throw new Error(`cipherbird: no method ${method}`);
    owner = target;
    target = target[part];
  }
  if (typeof target !== 'function') throw new Error(`cipherbird: ${method} is not a function`);
  return target.bind(owner);
}

parentPort.on('message', ({ id, method, args }) => {
  try {
    const value = resolveMethod(method)(...args.map(revive));
    parentPort.postMessage({ id, ok: true, value: plain(value) });
  } catch (e) {
    parentPort.postMessage({ id, ok: false, error: e && e.message ? e.message : String(e) });
  }
});
