# SecurityProfile + Recipe checks, and the Ruby end of the cross-language
# interop harness.
#
#   ruby -Ilib test/recipe.rb                 # run the checks
#   ruby -Ilib test/recipe.rb seal|open DIR   # interop mode
require 'cryptolib'
require 'tmpdir'

KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
SK_HEX  = 'd463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6'
PASSPHRASE = 'interop passphrase'
PLAINTEXT  = 'cross-language recipe envelope'.b

$pass = 0
$fail = 0

def ck(label, ok)
  puts(ok ? "  ok   #{label}" : " FAIL  #{label}")
  ok ? $pass += 1 : $fail += 1
end

def throws?
  yield
  false
rescue StandardError, ArgumentError
  true
end

def noise_ppm(w, h, seed)
  body = String.new(capacity: w * h * 3)
  s = seed.zero? ? 1 : seed
  (w * h * 3).times do
    s ^= (s << 13) & 0xFFFFFFFF
    s ^= s >> 17
    s ^= (s << 5) & 0xFFFFFFFF
    body << (s & 0xFF).chr
  end
  "P6\n#{w} #{h}\n255\n".b + body.b
end

def cheap(r) = r.argon2_cost(ops: 1, memory_bytes: 8 * 1024 * 1024)

def interop_configs(pk, sk)
  key = [KEY_HEX].pack('H*')
  [
    ['balanced', CryptoLib.recipe.with_key(key)],
    ['maximum', CryptoLib.recipe(CryptoLib::SecurityProfile::MAXIMUM).with_key(key)],
    ['signed', CryptoLib.recipe(CryptoLib::SecurityProfile::HIGH).with_key(key)
                 .signed_by(sk, CryptoLib::SignatureAlgorithm::ED25519).verified_by(pk)],
    ['passphrase', cheap(CryptoLib.recipe.with_passphrase(PASSPHRASE))],
    ['fec', CryptoLib.recipe.with_key(key).with_fec(CryptoLib::FecScheme::REPETITION3)]
  ]
end

CryptoLib.init

if ARGV.length >= 2 && %w[seal open].include?(ARGV[0])
  mode, dir = ARGV[0], ARGV[1]
  pk, sk = CryptoLib.ed25519_keygen_from_seed([SK_HEX].pack('H*'))
  failures = 0
  configs = interop_configs(pk, sk)
  configs.each do |name, r|
    path = File.join(dir, "#{name}.bin")
    if mode == 'seal'
      File.binwrite(path, r.seal(PLAINTEXT))
    else
      begin
        ok = r.open(File.binread(path)) == PLAINTEXT
        puts(ok ? "  ok   ruby opens #{name}" : " FAIL  ruby opens #{name}")
        failures += 1 unless ok
      rescue StandardError => e
        puts " FAIL  ruby opens #{name}: #{e.message}"
        failures += 1
      end
    end
  end
  puts "  ruby sealed #{configs.length} envelopes" if mode == 'seal'
  exit(failures.zero? ? 0 : 1)
end

puts "CryptoLib #{CryptoLib.version} — security profiles + recipes (Ruby)"
Dir.mktmpdir('cl_sec_rb_') do |tmp|
  secret = 'the treaty text nobody may read'.b
  mx = CryptoLib::SecurityProfile.params(CryptoLib::SecurityProfile::MAXIMUM)
  ck('maximum picks the strongest options',
     mx[:ml_kem_level] == 2 && mx[:ml_dsa_level] == 2 && mx[:slh_dsa_hash] == 1 && mx[:kdf_preset] == 1)
  ck('maximum cascade ends key-committing',
     mx[:cascade].length == 3 && mx[:cascade].last == CryptoLib::ProtectionLayer::COMMITTING)
  ck('profiles are ordered',
     CryptoLib::SecurityProfile.params(CryptoLib::SecurityProfile::BALANCED)[:argon2_memory] < mx[:argon2_memory])

  key = CryptoLib.random_bytes(32)
  r = CryptoLib.recipe(CryptoLib::SecurityProfile::HIGH).with_key(key)
  ck('raw key round-trip', r.open(r.seal(secret)) == secret)

  pr = cheap(CryptoLib.maximum_security.with_passphrase('correct horse battery staple'))
  ck('maximum + passphrase round-trip', pr.open(pr.seal(secret)) == secret)

  key_file = File.join(tmp, 'key.ppm')
  File.binwrite(key_file, noise_ppm(96, 96, 0x5EED))
  by_file = CryptoLib.recipe.with_key_file(key_file).seal(secret)
  ck('key file reproducible across recipe objects',
     CryptoLib.recipe.with_key_file(key_file).open(by_file) == secret)

  mol = CryptoLib.recipe.with_key(key).with_layers([CryptoLib::ProtectionLayer::MOLECULAR])
  ck('MolecularVault as one layer', mol.open(mol.seal(secret)) == secret)

  pk, sk = CryptoLib.ed25519_keygen
  signed = CryptoLib.recipe(CryptoLib::SecurityProfile::HIGH).with_key(key).signed_by(sk).verified_by(pk)
  senv = signed.seal(secret)
  ck('signed round-trip', signed.open(senv) == secret)

  hpk, hsk = CryptoLib.hybrid_sig_keygen
  hy = CryptoLib.recipe.with_key(key).signed_by(hsk, CryptoLib::SignatureAlgorithm::HYBRID).verified_by(hpk)
  ck('hybrid PQ signed round-trip', hy.open(hy.seal(secret)) == secret)

  ipk, = CryptoLib.ed25519_keygen
  ck('wrong signer rejected',
     throws? { CryptoLib.recipe(CryptoLib::SecurityProfile::HIGH).with_key(key).verified_by(ipk).open(senv) })
  ck('signed envelope refuses to open unverified',
     throws? { CryptoLib.recipe(CryptoLib::SecurityProfile::HIGH).with_key(key).open(senv) })

  fr = CryptoLib.recipe.with_key(key).with_fec(CryptoLib::FecScheme::REPETITION3)
  fenv = fr.seal(secret).dup
  fenv.setbyte(fenv.bytesize / 2, fenv.getbyte(fenv.bytesize / 2) ^ 1)
  ck('FEC corrects a flipped bit', fr.open(fenv) == secret)

  cover = File.join(tmp, 'cover.ppm')
  carrier = File.join(tmp, 'carrier.ppm')
  File.binwrite(cover, noise_ppm(256, 256, 0x0FF1CE))
  cr = cheap(CryptoLib.maximum_security.with_passphrase('a long passphrase here'))
  cr.seal_into_carrier(secret, cover, carrier)
  ck('pipeline hides itself in a carrier', cr.open_from_carrier(carrier) == secret)

  tenv = r.seal(secret).dup
  tenv.setbyte(tenv.bytesize - 1, tenv.getbyte(tenv.bytesize - 1) ^ 1)
  ck('flipped ciphertext byte rejected', throws? { r.open(tenv) })
  henv = r.seal(secret).dup
  henv.setbyte(7, 1)
  ck('tampered header rejected (descriptor is AAD)', throws? { r.open(henv) })
  ck('wrong key rejected',
     throws? { CryptoLib.recipe(CryptoLib::SecurityProfile::HIGH).with_key(CryptoLib.random_bytes(32)).open(r.seal(secret)) })
  ck('foreign bytes rejected', throws? { r.open('not an envelope at all'.b) })
  ck('short key refused', throws? { CryptoLib.recipe.with_key("\x00".b * 31) })
  ck('empty layer list refused', throws? { CryptoLib.recipe.with_layers([]) })
end

puts "\n#{$pass} passed, #{$fail} failed — recipes #{$fail.zero? ? 'OK' : 'FAILED'}"
exit($fail.zero? ? 0 : 1)
