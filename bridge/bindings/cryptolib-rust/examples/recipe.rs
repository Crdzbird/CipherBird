//! SecurityProfile + Recipe checks, and the Rust end of the cross-language
//! interop harness.
//!
//!   cargo run --example recipe                 # run the checks
//!   cargo run --example recipe seal|open DIR   # interop mode
use cryptolib::{FecScheme, ProtectionLayer, Recipe, SecurityProfile, SignatureAlgorithm};
use std::fs;
use std::path::PathBuf;

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SK_HEX: &str = "d463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6";
const PASSPHRASE: &str = "interop passphrase";
const PLAINTEXT: &[u8] = b"cross-language recipe envelope";

use std::sync::atomic::{AtomicU32, Ordering};

static PASS: AtomicU32 = AtomicU32::new(0);
static FAIL: AtomicU32 = AtomicU32::new(0);

fn ck(label: &str, ok: bool) {
    println!("{} {}", if ok { "  ok  " } else { " FAIL " }, label);
    if ok { PASS.fetch_add(1, Ordering::Relaxed); } else { FAIL.fetch_add(1, Ordering::Relaxed); }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn noise_ppm(w: usize, h: usize, seed: u32) -> Vec<u8> {
    let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
    let mut s = if seed == 0 { 1 } else { seed };
    for _ in 0..w * h * 3 {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        out.push(s as u8);
    }
    out
}

fn cheap(r: Recipe) -> Recipe { r.argon2_cost(1, 8 * 1024 * 1024) }

fn interop_configs(pk: &[u8], sk: &[u8]) -> Vec<(&'static str, Recipe)> {
    let key = hex(KEY_HEX);
    vec![
        ("balanced", cryptolib::recipe(SecurityProfile::Balanced).with_key(&key)),
        ("maximum", cryptolib::recipe(SecurityProfile::Maximum).with_key(&key)),
        ("signed", cryptolib::recipe(SecurityProfile::High).with_key(&key)
            .signed_by(sk, SignatureAlgorithm::Ed25519).verified_by(pk)),
        ("passphrase", cheap(cryptolib::recipe(SecurityProfile::Balanced).with_passphrase(PASSPHRASE))),
        ("fec", cryptolib::recipe(SecurityProfile::Balanced).with_key(&key).with_fec(FecScheme::Repetition3)),
    ]
}

fn main() {
    cryptolib::init();
    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 3 && (args[1] == "seal" || args[1] == "open") {
        let (mode, dir) = (&args[1], PathBuf::from(&args[2]));
        let (pk, sk) = cryptolib::ed25519_keygen_from_seed(&hex(SK_HEX));
        let mut failures = 0;
        let cfgs = interop_configs(&pk, &sk);
        let n = cfgs.len();
        for (name, r) in cfgs {
            let path = dir.join(format!("{name}.bin"));
            if mode == "seal" {
                fs::write(&path, r.seal(PLAINTEXT).expect("seal")).expect("write");
            } else {
                match fs::read(&path).map_err(|e| e.to_string()).and_then(|b| r.open(&b)) {
                    Ok(got) if got == PLAINTEXT => println!("  ok   rust opens {name}"),
                    Ok(_) => { println!(" FAIL  rust opens {name}: plaintext mismatch"); failures += 1; }
                    Err(e) => { println!(" FAIL  rust opens {name}: {e}"); failures += 1; }
                }
            }
        }
        if mode == "seal" { println!("  rust sealed {n} envelopes"); }
        std::process::exit(if failures == 0 { 0 } else { 1 });
    }

    println!("CryptoLib {} — security profiles + recipes (Rust)", cryptolib::version());
    let tmp = std::env::temp_dir().join(format!("cl_sec_rs_{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();
    let secret = b"the treaty text nobody may read";

    let mx = SecurityProfile::Maximum;
    ck("maximum picks the strongest options",
       mx.ml_kem_level() == 2 && mx.ml_dsa_level() == 2 && mx.slh_dsa_hash() == 1
       && mx.sealed_tier() == 1 && mx.kdf_preset() == 1);
    ck("maximum cascade ends key-committing",
       mx.cascade().len() == 3 && *mx.cascade().last().unwrap() == ProtectionLayer::Committing);
    ck("profiles are ordered", SecurityProfile::Balanced.argon2_memory() < mx.argon2_memory());

    let key = cryptolib::random_bytes(32).unwrap();
    let r = cryptolib::recipe(SecurityProfile::High).with_key(&key);
    ck("raw key round-trip", r.open(&r.seal(secret).unwrap()).unwrap() == secret);

    let pr = cheap(cryptolib::maximum_security().with_passphrase("correct horse battery staple"));
    ck("maximum + passphrase round-trip", pr.open(&pr.seal(secret).unwrap()).unwrap() == secret);

    let key_file = tmp.join("key.ppm");
    fs::write(&key_file, noise_ppm(96, 96, 0x5EED)).unwrap();
    let kf = key_file.to_str().unwrap();
    let by_file = cryptolib::recipe(SecurityProfile::Balanced).with_key_file(kf).seal(secret).unwrap();
    ck("key file reproducible across recipe objects",
       cryptolib::recipe(SecurityProfile::Balanced).with_key_file(kf).open(&by_file).unwrap() == secret);

    let mol = cryptolib::recipe(SecurityProfile::Balanced).with_key(&key)
        .with_layers(&[ProtectionLayer::Molecular]);
    ck("MolecularVault as one layer", mol.open(&mol.seal(secret).unwrap()).unwrap() == secret);

    let one = cryptolib::recipe(SecurityProfile::Balanced).with_key(&key)
        .with_layers(&[ProtectionLayer::XChaCha20Poly1305]).seal(secret).unwrap();
    let three = cryptolib::recipe(SecurityProfile::Balanced).with_key(&key)
        .with_layers(&[ProtectionLayer::XChaCha20Poly1305, ProtectionLayer::Aes256Gcm])
        .add_layer(ProtectionLayer::Committing).seal(secret).unwrap();
    ck("each layer adds overhead", three.len() > one.len());

    let (pk, sk) = cryptolib::ed25519_keygen();
    let signed = cryptolib::recipe(SecurityProfile::High).with_key(&key)
        .signed_by(&sk, SignatureAlgorithm::Ed25519).verified_by(&pk);
    let senv = signed.seal(secret).unwrap();
    ck("signed round-trip", signed.open(&senv).unwrap() == secret);

    let (hpk, hsk) = cryptolib::hybrid_sig_keygen();
    let hy = cryptolib::recipe(SecurityProfile::Balanced).with_key(&key)
        .signed_by(&hsk, SignatureAlgorithm::Hybrid).verified_by(&hpk);
    ck("hybrid PQ signed round-trip", hy.open(&hy.seal(secret).unwrap()).unwrap() == secret);

    let (ipk, _) = cryptolib::ed25519_keygen();
    ck("wrong signer rejected",
       cryptolib::recipe(SecurityProfile::High).with_key(&key).verified_by(&ipk).open(&senv).is_err());
    ck("signed envelope refuses to open unverified",
       cryptolib::recipe(SecurityProfile::High).with_key(&key).open(&senv).is_err());

    let fr = cryptolib::recipe(SecurityProfile::Balanced).with_key(&key).with_fec(FecScheme::Repetition3);
    let mut fenv = fr.seal(secret).unwrap();
    let mid = fenv.len() / 2;
    fenv[mid] ^= 1;
    ck("FEC corrects a flipped bit", fr.open(&fenv).unwrap() == secret);

    let cover = tmp.join("cover.ppm");
    let carrier = tmp.join("carrier.ppm");
    fs::write(&cover, noise_ppm(256, 256, 0x0FF1CE)).unwrap();
    let cr = cheap(cryptolib::maximum_security().with_passphrase("a long passphrase here"));
    cr.seal_into_carrier(secret, cover.to_str().unwrap(), carrier.to_str().unwrap()).unwrap();
    ck("pipeline hides itself in a carrier",
       cr.open_from_carrier(carrier.to_str().unwrap()).unwrap() == secret);

    let mut tenv = r.seal(secret).unwrap();
    let last = tenv.len() - 1;
    tenv[last] ^= 1;
    ck("flipped ciphertext byte rejected", r.open(&tenv).is_err());
    let mut henv = r.seal(secret).unwrap();
    henv[7] = 1;
    ck("tampered header rejected (descriptor is AAD)", r.open(&henv).is_err());
    let other = cryptolib::random_bytes(32).unwrap();
    ck("wrong key rejected",
       cryptolib::recipe(SecurityProfile::High).with_key(&other).open(&r.seal(secret).unwrap()).is_err());
    ck("foreign bytes rejected", r.open(b"not an envelope at all").is_err());
    ck("short key refused",
       cryptolib::recipe(SecurityProfile::Balanced).with_key(&[0u8; 31]).seal(secret).is_err());
    ck("empty layer list refused",
       cryptolib::recipe(SecurityProfile::Balanced).with_layers(&[]).seal(secret).is_err());

    fs::remove_dir_all(&tmp).ok();
    let (passed, failed) = (PASS.load(Ordering::Relaxed), FAIL.load(Ordering::Relaxed));
    println!("\n{passed} passed, {failed} failed — recipes {}", if failed == 0 { "OK" } else { "FAILED" });
    std::process::exit(if failed == 0 { 0 } else { 1 });
}
