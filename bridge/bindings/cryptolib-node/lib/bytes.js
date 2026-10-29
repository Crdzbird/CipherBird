/*
 * Steganography, the composed seals and media entropy on bytes instead of
 * files: the same engine entry points over a scratch file, so a carrier
 * held in memory works without the caller managing paths. The format names
 * the carrier's container; it is a MediaFormat name ('pngImage'), its wire
 * value, or a bare extension ('png').
 */
'use strict';
const { withScratch } = require('./scratch');

const EXTENSIONS = {
  ppmImage: 'ppm', wavAudio: 'wav', crvfVideo: 'crvf', bmpImage: 'bmp', pngImage: 'png', flacAudio: 'flac',
  aviVideo: 'avi', gifImage: 'gif', jpegImage: 'jpg', mp3Audio: 'mp3', mp4Video: 'mp4', unknown: 'bin',
};

module.exports = (api) => {
  const { MediaFormat } = api;
  for (const name of Object.keys(EXTENSIONS)) {
    const value = Object.keys(MediaFormat).find((k) => MediaFormat[k] === name);
    if (value !== undefined) MediaFormat[name] = Number(value);
  }
  MediaFormat.extensions = EXTENSIONS;
  /** The file extension the engine dispatches on for a format. */
  MediaFormat.extensionOf = (format) => {
    if (typeof format === 'number') return EXTENSIONS[MediaFormat[format] || 'unknown'];
    if (EXTENSIONS[format]) return EXTENSIONS[format];
    if (typeof format === 'string' && /^[a-z0-9]{2,5}$/.test(format)) return format;
    throw new TypeError(`cipherbird: unknown media format ${String(format)}`);
  };
  const ext = MediaFormat.extensionOf;
  const embedTo = (cover, format, write) => withScratch((s) => {
    const out = s.reserve(ext(format));
    write(s.put(ext(format), cover), out);
    return s.take(out);
  });

  return {
    /** Embed `payload` into `cover` and return the carrier bytes. */
    stegoEmbedBytes: (cover, format, payload) => embedTo(cover, format, (c, o) => api.stegoEmbed(c, payload, o)),
    /** Extract the payload hidden in `stego`. */
    stegoExtractBytes: (stego, format) => withScratch((s) => api.stegoExtract(s.put(ext(format), stego))),
    /** The payload capacity of `cover` in bytes. */
    stegoCapacityOf: (cover, format) => withScratch((s) => api.stegoCapacity(s.put(ext(format), cover))),
    /** Structural validity and true format of `bytes`. */
    stegoInspectBytes: (bytes, format) => withScratch((s) => api.StegoAdvanced.inspect(s.put(ext(format), bytes))),
    /** Probe `bytes` for hidden data; see StegoAdvanced.detectHidden for the caveats. */
    stegoDetectHiddenBytes: (bytes, format) => withScratch((s) => api.StegoAdvanced.detectHidden(s.put(ext(format), bytes))),
    /** Digest of the decoded content of `bytes`. */
    stegoContentDigestOf: (bytes, format) => withScratch((s) => api.StegoAdvanced.contentDigest(s.put(ext(format), bytes))),
    /** StegoAdvanced.embedKeyed on bytes: placement permuted under `key`. */
    stegoEmbedKeyedBytes: (cover, format, payload, key) =>
      embedTo(cover, format, (c, o) => api.StegoAdvanced.embedKeyed(c, payload, o, key)),
    stegoExtractKeyedBytes: (stego, format, key) =>
      withScratch((s) => api.StegoAdvanced.extractKeyed(s.put(ext(format), stego), key)),
    /** StegoAdvanced.embedEncrypted on bytes: sealed under `masterKey`, then hidden. */
    stegoEmbedEncryptedBytes: (cover, format, plaintext, masterKey) =>
      embedTo(cover, format, (c, o) => api.StegoAdvanced.embedEncrypted(c, plaintext, o, masterKey)),
    stegoExtractDecryptBytes: (stego, format, masterKey) =>
      withScratch((s) => api.StegoAdvanced.extractDecrypt(s.put(ext(format), stego), masterKey)),

    /** Composed.physicalSeal on bytes; returns the carrier. */
    physicalSealBytes: ({ keyMedia, keyMediaFormat, plaintext, cover, coverFormat, aad = null }) => withScratch((s) => {
      const out = s.reserve(ext(coverFormat));
      api.Composed.physicalSeal({ keyMediaPath: s.put(ext(keyMediaFormat), keyMedia), plaintext,
        coverPath: s.put(ext(coverFormat), cover), outputPath: out, aad });
      return s.take(out);
    }),
    physicalOpenBytes: ({ keyMedia, keyMediaFormat, stego, stegoFormat, aad = null }) => withScratch((s) =>
      api.Composed.physicalOpen({ keyMediaPath: s.put(ext(keyMediaFormat), keyMedia), stegoPath: s.put(ext(stegoFormat), stego), aad })),
    /** Composed.hpkeStegoSeal on bytes; returns { enc, carrier }. */
    hpkeStegoSealBytes: ({ recipientPublic, plaintext, cover, coverFormat, aad = null, info = null }) => withScratch((s) => {
      const out = s.reserve(ext(coverFormat));
      const enc = api.Composed.hpkeStegoSeal({ recipientPublic, plaintext, coverPath: s.put(ext(coverFormat), cover), outputPath: out, aad, info });
      return { enc, carrier: s.take(out) };
    }),
    hpkeStegoOpenBytes: ({ recipientSecret, enc, stego, stegoFormat, aad = null, info = null }) => withScratch((s) =>
      api.Composed.hpkeStegoOpen({ recipientSecret, enc, stegoPath: s.put(ext(stegoFormat), stego), aad, info })),
    /** Composed.imageFactorSeal on bytes; returns the carrier. */
    imageFactorSealBytes: ({ oprfSecretSeed, referenceImage, referenceFormat, plaintext, cover, coverFormat, aad = null }) => withScratch((s) => {
      const out = s.reserve(ext(coverFormat));
      api.Composed.imageFactorSeal({ oprfSecretSeed, referenceImagePath: s.put(ext(referenceFormat), referenceImage), plaintext,
        coverPath: s.put(ext(coverFormat), cover), outputPath: out, aad });
      return s.take(out);
    }),
    imageFactorOpenBytes: ({ oprfSecretSeed, referenceImage, referenceFormat, stego, stegoFormat, aad = null }) => withScratch((s) =>
      api.Composed.imageFactorOpen({ oprfSecretSeed, referenceImagePath: s.put(ext(referenceFormat), referenceImage),
        stegoPath: s.put(ext(stegoFormat), stego), aad })),

    /** entropyFromFileWithPolicy on bytes; free the handle with entropyFree. `extension` only names the scratch file. */
    entropyFromBytes: (bytes, { deterministic = false, minBitsPerByte = 1.0, requireRct = true, extension = 'bin' } = {}) =>
      withScratch((s) => api.entropyFromFileWithPolicy(s.put(extension, bytes), { deterministic, minBitsPerByte, requireRct })),
    /** assessFileHealth on bytes. */
    assessHealthOf: (bytes, maxBytes = 1 << 20, floorBitsPerByte = 1.0) =>
      withScratch((s) => api.assessFileHealth(s.put('bin', bytes), maxBytes, floorBitsPerByte)),
    /** keyFromFile on bytes: a 32-byte key from any buffer. */
    keyFromBytes: (bytes) => withScratch((s) => api.keyFromFile(s.put('bin', bytes))),
    /** sealFromFile on bytes: encrypt `plaintext` with `bytes` as the key. */
    sealWithBytes: (bytes, plaintext, aad = '') => withScratch((s) => api.sealFromFile(s.put('bin', bytes), plaintext, aad)),
    /** openFromFile on bytes. */
    openWithBytes: (bytes, packet, aad = '') => withScratch((s) => api.openFromFile(s.put('bin', bytes), packet, aad)),
  };
};
