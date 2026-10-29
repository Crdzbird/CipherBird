/*
 * Scratch files for the media entry points, in a private temporary directory:
 * a file is written, the path-taking entry point runs, the result is read
 * back, and both are overwritten with zeros and removed.
 */
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

class MediaScratch {
  constructor() {
    this._dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cipherbird_'));
    this._n = 0;
  }
  /** Writes `bytes` under a fresh name with `extension` and returns its path. */
  put(extension, bytes) {
    const p = this.reserve(extension);
    fs.writeFileSync(p, bytes);
    return p;
  }
  /** A fresh path with `extension` for the engine to write to. */
  reserve(extension) { return path.join(this._dir, `${this._n++}.${extension}`); }
  /** Reads `p` back, overwrites it with zeros and removes it. */
  take(p) {
    const bytes = fs.readFileSync(p);
    this._wipe(p);
    return bytes;
  }
  /** Overwrites and removes every file this scratch created. */
  dispose() {
    if (!fs.existsSync(this._dir)) return;
    for (const f of fs.readdirSync(this._dir)) this._wipe(path.join(this._dir, f));
    fs.rmSync(this._dir, { recursive: true, force: true });
  }
  _wipe(p) {
    if (!fs.existsSync(p)) return;
    fs.writeFileSync(p, Buffer.alloc(fs.statSync(p).size));
    fs.unlinkSync(p);
  }
}

/** Runs `op` with a scratch that is disposed afterwards, whatever happens. */
function withScratch(op) {
  const s = new MediaScratch();
  try { return op(s); } finally { s.dispose(); }
}

module.exports = { MediaScratch, withScratch };
