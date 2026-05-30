$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'cryptolib'

pass = 0; fail = 0
ck = ->(label, ok) { puts "  #{ok ? '✓' : '✗'} #{label}"; ok ? pass += 1 : fail += 1 }

CryptoLib.init
ck.call('version == 3.0.0', CryptoLib.version == '3.0.0')

sha = CryptoLib.sha256('abc').unpack1('H*')
ck.call('SHA-256("abc") KAT',
        sha == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

pub, sec = CryptoLib.hybrid_kem_keygen
ct, ss   = CryptoLib.hybrid_kem_encapsulate(pub)
ss2      = CryptoLib.hybrid_kem_decapsulate(ct, sec)
ck.call('Hybrid X25519+ML-KEM-768 round-trip', ss == ss2 && ss.bytesize == 32)

puts "\ncryptolib Ruby smoke: #{fail.zero? ? 'OK' : 'FAILED'} (#{pass} passed, #{fail} failed)"
exit(fail.zero? ? 0 : 1)
