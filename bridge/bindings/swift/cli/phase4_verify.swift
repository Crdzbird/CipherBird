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

try? FileManager.default.removeItem(atPath: dir)
print(failures == 0 ? "ALL PASS" : "\(failures) FAILURE(S)")
exit(failures == 0 ? 0 : 1)
