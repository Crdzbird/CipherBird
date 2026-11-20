/** Feature areas of the C ABI, matched in order by function name; `chapter` links the tour. */
export const AREAS = [
  { id: 'memory', title: 'Memory', test: /_free$|^str_free$|^init$/, chapter: null },
  { id: 'stego', title: 'Steganography', test: /^(stego_|physical_|fec_|image_factor_|hpke_stego_)/, chapter: 'stego' },
  { id: 'hpke', title: 'HPKE', test: /^hpke_/, chapter: 'hpke' },
  { id: 'hashing', title: 'Hashing', test: /^(blake2b|sha256|sha512|hmac_|hkdf_|argon2id_|blake3|keccak256|ripemd160|random_bytes|secure_equal|version)/, chapter: 'hashing' },
  { id: 'aead', title: 'Symmetric', test: /^(sym_keygen|xchacha20_|aes256gcm_|committing_|stream_|molecular_)/, chapter: 'aead' },
  { id: 'public-key', title: 'Public key', test: /^(ed25519_|x25519_|box_|sealedbox_|secp256k1_|p256_|suite_evm_address)/, chapter: 'public-key' },
  { id: 'post-quantum', title: 'Post-quantum', test: /^(ml_kem_|hybrid_kem_|sntrup_|xwing_|ml_dsa_|slh_dsa_|hybrid_sig_)/, chapter: 'post-quantum' },
  { id: 'sealed', title: 'Envelopes', test: /^(sealed_|suite_|suite2_)/, chapter: 'sealed' },
  { id: 'vault', title: 'Vaults', test: /^(vault_|packet_|asym_)/, chapter: 'vault' },
  { id: 'keyring', title: 'Keyring', test: /^keyring_/, chapter: 'keyring' },
  { id: 'tokens', title: 'Tokens', test: /^(token_|paseto_|cb1_)/, chapter: 'tokens' },
  { id: 'threshold', title: 'Threshold', test: /^(frost_|bls_)/, chapter: 'threshold' },
  { id: 'bbs', title: 'Credentials', test: /^bbs_/, chapter: 'bbs' },
  { id: 'oprf-opaque', title: 'OPRF and OPAQUE', test: /^(oprf_|opaque_)/, chapter: 'oprf-opaque' },
  { id: 'vrf', title: 'VRF', test: /^ecvrf_/, chapter: 'vrf' },
  { id: 'channels', title: 'Channels', test: /^(noise_|session_|session2_)/, chapter: 'channels' },
  { id: 'entropy', title: 'Entropy', test: /^(entropy_|key_from_file|seal_from_file|open_from_file|live_entropy_|drbg_|fortuna_)/, chapter: 'entropy' },
  { id: 'fips', title: 'FIPS profile', test: /^fips_/, chapter: 'fips' },
];

/** The area of a function, by its short name (without the cipherbird_ prefix). */
export function areaOf(short) {
  return AREAS.find((a) => a.test.test(short)) || AREAS[0];
}

const DISPLAY = ['hashing', 'aead', 'public-key', 'post-quantum', 'sealed', 'hpke', 'tokens', 'vault', 'keyring',
  'threshold', 'bbs', 'oprf-opaque', 'vrf', 'channels', 'stego', 'entropy', 'fips', 'memory'];

/** Functions grouped by area, in the order of the tour; memory helpers last. */
export function groupFunctions(abi) {
  const groups = new Map(AREAS.map((a) => [a.id, { ...a, fns: [] }]));
  for (const fn of abi.functions) {
    const short = fn.name.replace(/^cipherbird_/, '');
    groups.get(areaOf(short).id).fns.push({ ...fn, short });
  }
  return DISPLAY.map((id) => groups.get(id)).filter((g) => g && g.fns.length);
}
