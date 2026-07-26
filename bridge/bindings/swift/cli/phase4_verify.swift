// Verifies the Phase 1-4 stego/FEC/analysis bindings from Swift via the C ABI
// bridging header (cryptolib_c.h). Exits non-zero on any failure.
//   swiftc -import-objc-header ../../../cryptolib_c.h phase4_verify.swift \
//          -L ../../../../build/release -lcryptolib_c -o phase4_verify
//   DYLD_LIBRARY_PATH=../../../../build/release ./phase4_verify <dylib?>
import Foundation

var failures = 0
func check(_ ok: Bool, _ label: String) {
    print("\(ok ? "  ok  " : " FAIL ") \(label)")
    if !ok { failures += 1 }
}

func consume(_ r: CryptoBufferResult) -> [UInt8]? {
    var buf = r.buf
    if let e = r.error { cryptolib_str_free(e); cryptolib_buffer_free(&buf); return nil }
    guard let data = buf.data, buf.len > 0 else { return [] }
    let out = Array(UnsafeBufferPointer(start: data, count: buf.len))
    cryptolib_buffer_free(&buf)
    return out
}
func okResult(_ r: CryptoResult) -> Bool {
    if let e = r.error { cryptolib_str_free(e) }
    return r.ok != 0
}

func noisePpm(_ path: String, _ w: Int, _ h: Int, _ seed: UInt32) {
    var s = seed == 0 ? 1 : seed
    var d = Data("P6\n\(w) \(h)\n255\n".utf8)
    d.reserveCapacity(d.count + w * h * 3)
    for _ in 0..<(w * h * 3) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5
        d.append(UInt8(s & 0xFF))
    }
    try? d.write(to: URL(fileURLWithPath: path))
}

guard cryptolib_init() == 0 else { fatalError("init failed") }
let dir = NSTemporaryDirectory() + "cl_p4_swift_\(getpid())/"
try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
let key = [UInt8](repeating: 0x5a, count: 32)

// 1. Keyed stego
do {
    let cover = dir + "c1.ppm", out = dir + "o1.ppm"
    noisePpm(cover, 256, 256, 0xC0FFEE)
    let payload = Array("keyed stego via Swift".utf8)
    let embedded = payload.withUnsafeBufferPointer { p in key.withUnsafeBufferPointer { k in
        okResult(cryptolib_stego_embed_keyed(cover, p.baseAddress, p.count, out, k.baseAddress, k.count))
    }}
    check(embedded, "keyed embed")
    let got = key.withUnsafeBufferPointer { cryptolib_stego_extract_keyed(out, $0.baseAddress, $0.count) }
    check(consume(got) ?? [] == payload, "keyed stego round-trip")
    let wrong = [UInt8](repeating: 0x99, count: 32)
    let bad = wrong.withUnsafeBufferPointer { cryptolib_stego_extract_keyed(out, $0.baseAddress, $0.count) }
    check(consume(bad) == nil, "keyed stego wrong-key rejected")
}

// 2. Always-encrypt
do {
    let cover = dir + "c2.ppm", out = dir + "o2.ppm"
    noisePpm(cover, 256, 256, 0xBEEF)
    let secret = Array("never in the clear".utf8)
    let ok = secret.withUnsafeBufferPointer { p in key.withUnsafeBufferPointer { k in
        okResult(cryptolib_stego_embed_encrypted(cover, p.baseAddress, p.count, out, k.baseAddress, k.count))
    }}
    check(ok, "embed_encrypted")
    let got = key.withUnsafeBufferPointer { cryptolib_stego_extract_decrypt(out, $0.baseAddress, $0.count) }
    check(consume(got) ?? [] == secret, "always-encrypt round-trip")
}

// 3. PhysicalSeal
do {
    let km = dir + "k3.ppm", cover = dir + "c3.ppm", out = dir + "o3.ppm"
    noisePpm(km, 64, 64, 0xABCDEF); noisePpm(cover, 256, 256, 0x123456)
    let msg = Array("the photo is the key".utf8), aad = Array("swift-ctx".utf8)
    let ok = msg.withUnsafeBufferPointer { m in aad.withUnsafeBufferPointer { a in
        okResult(cryptolib_physical_seal(km, m.baseAddress, m.count, a.baseAddress, a.count, cover, out))
    }}
    check(ok, "physical_seal")
    let got = aad.withUnsafeBufferPointer { cryptolib_physical_open(km, $0.baseAddress, $0.count, out) }
    check(consume(got) ?? [] == msg, "PhysicalSeal round-trip")
}

// 4. FEC single-flip
do {
    let data: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]
    for scheme in Int32(1)...3 {
        var enc = data.withUnsafeBufferPointer { consume(cryptolib_fec_encode($0.baseAddress, $0.count, scheme)) } ?? []
        enc[0] ^= 0x40
        let dec = enc.withUnsafeBufferPointer { consume(cryptolib_fec_decode($0.baseAddress, $0.count, scheme, data.count)) } ?? []
        check(dec == data, "FEC scheme \(scheme) corrects a single flip")
    }
}

// 5. Analysis
do {
    let cover = dir + "a.ppm", stego = dir + "as.ppm"
    noisePpm(cover, 128, 128, 0x99)
    let insp = cryptolib_stego_inspect(cover)
    let parses = insp.parses != 0, ext = insp.ext_matches != 0, w = insp.width
    if let d = insp.detail { cryptolib_str_free(d) }
    if let e = insp.error { cryptolib_str_free(e) }
    check(parses && ext && w == 128, "inspect valid PPM")

    let d1 = consume(cryptolib_stego_content_digest(cover)) ?? []
    if let fh = FileHandle(forWritingAtPath: cover) { fh.seekToEndOfFile(); fh.write(Data([0])); fh.closeFile() }
    let d2 = consume(cryptolib_stego_content_digest(cover)) ?? []
    check(d1 != d2, "content digest changes on tamper")

    noisePpm(cover, 128, 128, 0x99)
    let hi = Array("hi".utf8)
    _ = hi.withUnsafeBufferPointer { okResult(cryptolib_stego_embed(cover, $0.baseAddress, $0.count, stego)) }
    let rep = cryptolib_stego_detect_hidden(stego)
    let payload = rep.cryptolib_payload != 0
    var note = ""
    if let n = rep.note { note = String(cString: n); cryptolib_str_free(n) }
    if let e = rep.error { cryptolib_str_free(e) }
    check(payload && !note.isEmpty, "detect unkeyed payload + honesty note")
}

// 6. ImageFactorSeal (C2)
do {
    let img = dir + "ref.ppm", cover = dir + "ifs_cover.ppm", out = dir + "ifs_out.ppm"
    noisePpm(img, 64, 64, 0xFEED); noisePpm(cover, 256, 256, 0xCAFE)
    let seed = [UInt8](repeating: 0x42, count: 32)
    let msg = Array("image is the second factor".utf8)
    let ok = seed.withUnsafeBufferPointer { s in msg.withUnsafeBufferPointer { m in
        okResult(cryptolib_image_factor_seal(s.baseAddress, s.count, img, m.baseAddress, m.count, nil, 0, cover, out))
    }}
    check(ok, "image_factor_seal")
    let got = seed.withUnsafeBufferPointer { cryptolib_image_factor_open($0.baseAddress, $0.count, img, nil, 0, out) }
    check(consume(got) ?? [] == msg, "ImageFactorSeal round-trip")
    let other = dir + "ref2.ppm"; noisePpm(other, 64, 64, 0xBEEF)
    let bad = seed.withUnsafeBufferPointer { cryptolib_image_factor_open($0.baseAddress, $0.count, other, nil, 0, out) }
    check(consume(bad) == nil, "ImageFactorSeal wrong-image rejected")
}

// 7. HpkeStegoSeal (C3)
do {
    let cover = dir + "hss_cover.ppm", out = dir + "hss_out.ppm"
    noisePpm(cover, 256, 256, 0x4321)
    func kpBytes(_ b: CryptoBuffer) -> [UInt8] { b.data == nil ? [] : Array(UnsafeBufferPointer(start: b.data, count: b.len)) }
    var kp = cryptolib_hpke_keygen()
    let pk = kpBytes(kp.public_key), sk = kpBytes(kp.secret_key)
    cryptolib_keypair_free(&kp)
    let info = Array("session".utf8), msg = Array("one session keys both".utf8)
    let encR = pk.withUnsafeBufferPointer { p in msg.withUnsafeBufferPointer { m in info.withUnsafeBufferPointer { i in
        cryptolib_hpke_stego_seal(p.baseAddress, p.count, m.baseAddress, m.count, nil, 0, i.baseAddress, i.count, cover, out)
    }}}
    let enc = consume(encR) ?? []
    let got = sk.withUnsafeBufferPointer { s in enc.withUnsafeBufferPointer { e in info.withUnsafeBufferPointer { i in
        consume(cryptolib_hpke_stego_open(s.baseAddress, s.count, e.baseAddress, e.count, nil, 0, i.baseAddress, i.count, out))
    }}}
    check(got ?? [] == msg, "HpkeStegoSeal round-trip")
    var kp2 = cryptolib_hpke_keygen(); let sk2 = kpBytes(kp2.secret_key); cryptolib_keypair_free(&kp2)
    let bad = sk2.withUnsafeBufferPointer { s in enc.withUnsafeBufferPointer { e in info.withUnsafeBufferPointer { i in
        consume(cryptolib_hpke_stego_open(s.baseAddress, s.count, e.baseAddress, e.count, nil, 0, i.baseAddress, i.count, out))
    }}}
    check(bad == nil, "HpkeStegoSeal wrong-recipient rejected")
}

// 8. HMAC-DRBG handle (A3)
do {
    let seed = [UInt8](repeating: 0x01, count: 32), perso = Array("beacon".utf8)
    func inst() -> CryptoDrbgHandle? {
        var err: UnsafeMutablePointer<CChar>? = nil
        let h = seed.withUnsafeBufferPointer { s in perso.withUnsafeBufferPointer { p in
            cryptolib_drbg_instantiate(s.baseAddress, s.count, nil, 0, p.baseAddress, p.count, &err)
        }}
        if let e = err { cryptolib_str_free(e) }
        return h
    }
    let h1 = inst(), h2 = inst()
    let a = consume(cryptolib_drbg_generate(h1, 64, nil, 0)) ?? []
    let b = consume(cryptolib_drbg_generate(h1, 64, nil, 0)) ?? []
    check(a != b, "DRBG successive blocks differ")
    check(a == (consume(cryptolib_drbg_generate(h2, 64, nil, 0)) ?? []), "DRBG reproducible from same seed")
    cryptolib_drbg_free(h1); cryptolib_drbg_free(h2)
    var err: UnsafeMutablePointer<CChar>? = nil
    let short: [UInt8] = [1, 2, 3]
    let bad = short.withUnsafeBufferPointer { cryptolib_drbg_instantiate($0.baseAddress, $0.count, nil, 0, nil, 0, &err) }
    check(bad == nil && err != nil, "DRBG short-entropy rejected")
    if let e = err { cryptolib_str_free(e) }
}

// 9. Fortuna handle (A5)
do {
    let h = cryptolib_fortuna_new()
    check(consume(cryptolib_fortuna_generate(h, 32)) == nil, "Fortuna unseeded generate rejected")
    for i in 0..<40 {
        let d = [UInt8](repeating: UInt8(i & 0xFF), count: 16)
        d.withUnsafeBufferPointer { cryptolib_fortuna_add_entropy(h, UInt8(i & 7), $0.baseAddress, $0.count) }
    }
    cryptolib_fortuna_reseed(h)
    check(cryptolib_fortuna_reseed_count(h) >= 1, "Fortuna reseed count advances")
    check((consume(cryptolib_fortuna_generate(h, 64)) ?? []).count == 64, "Fortuna generate after seeding")
    cryptolib_fortuna_free(h)
}

try? FileManager.default.removeItem(atPath: dir)
print(failures == 0 ? "ALL PASS" : "\(failures) FAILURE(S)")
exit(failures == 0 ? 0 : 1)
