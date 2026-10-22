/// The carriers the steganography playground can generate.
const stegoCarriers = [
  'photo 512x512 PPM',
  'photo 256x256 PPM',
  'tone 10 s WAV',
  'tone 2 s WAV',
];

/// The ways the steganography playground can hide a secret.
const stegoModes = [
  'plain',
  'keyed placement',
  'encrypted',
  'physical seal (a photo is the key)',
  'HPKE to Bob',
  'image factor (OPRF secret + reference photo)',
  'recipe (custom pipeline)',
];

/// The key sources the recipe mode can start from.
const stegoRecipeKeys = ['passphrase', 'raw key', 'key photo'];
