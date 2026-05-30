// Smoke test: load the bundled native lib (no path) and round-trip.
fn main() {
    let mut pass = 0;
    let mut fail = 0;
    let mut ck = |label: &str, ok: bool| {
        println!("  {} {}", if ok { "✓" } else { "✗" }, label);
        if ok { pass += 1 } else { fail += 1 }
    };

    cryptolib::init();
    ck("version == 3.0.0", cryptolib::version() == "3.0.0");

    let hex = cryptolib::sha256(b"abc").unwrap().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    ck("SHA-256(b\"abc\") KAT",
       hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    let (pub_, sec) = cryptolib::hybrid_kem_keygen();
    let (ct, ss)    = cryptolib::hybrid_kem_encapsulate(&pub_).unwrap();
    let ss2         = cryptolib::hybrid_kem_decapsulate(&ct, &sec).unwrap();
    ck("Hybrid X25519+ML-KEM-768 round-trip", ss == ss2 && ss.len() == 32);

    println!("\ncryptolib Rust smoke: {} ({} passed, {} failed)",
             if fail == 0 { "OK" } else { "FAILED" }, pass, fail);
    std::process::exit(if fail == 0 { 0 } else { 1 });
}
