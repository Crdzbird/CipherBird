# SecurityProfile + Recipe checks, and the Ruby end of the cross-language
# interop harness.
#
#   ruby -Ilib test/recipe.rb                 # run the checks
#   ruby -Ilib test/recipe.rb seal|open DIR   # interop mode
require 'cipherbird'
require 'tmpdir'

KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
SK_HEX  = 'd463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6'
PASSPHRASE = 'interop passphrase'
PLAINTEXT  = 'cross-language recipe envelope'.b

$pass = 0
$fail = 0

# ── custom parts used by the extension-point checks ─────────────────────────

class MyLayer < CipherBird::ProtectionLayer
  def id = 200
  def wire_name = 'my-xchacha'
  def seal(key, aad, pt) = CipherBird.xchacha20_encrypt(pt, key, aad)
  def open(key, aad, ct) = CipherBird.xchacha20_decrypt(ct, key, aad)
end

class BeltAndBraces < CipherBird::CascadeLayer
  def initialize
    super(201, 'belt-and-braces',
          [CipherBird::ProtectionLayer::XCHACHA20_POLY1305, CipherBird::ProtectionLayer::AES256_GCM, MyLayer.new])
  end
end

class Impostor < CipherBird::ProtectionLayer
  def id = 3
  def wire_name = 'committing'
  def seal(_key, _aad, pt) = pt
  def open(_key, _aad, ct) = ct
end

class TokenSource < CipherBird::KeySource
  def initialize(token) = @token = token
  def id = 210
  def label = 'token'
  def derive_root(_salt, _ops, _mem) = @token
end

class WeakSource < CipherBird::KeySource
  def id = 211
  def label = 'weak'
  def derive_root(_salt, _ops, _mem) = "\x00".b * 16
end

class PrefixedEd25519 < CipherBird::SignatureScheme
  def initialize(sk: nil, pk: nil)
    @sk = sk
    @pk = pk
  end
  def id = 220
  def label = 'prefixed-ed25519'
  def sign(m) = CipherBird.ed25519_sign('custom:'.b + m, @sk)
  def verify(m, sig) = CipherBird.ed25519_verify('custom:'.b + m, sig, @pk)
end

class FakeEd25519 < CipherBird::SignatureScheme
  def id = 1
  def label = 'fake'
  def sign(_m) = "\x00".b * 64
  def verify(_m, _sig) = true
end

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
    ['balanced', CipherBird.recipe.with_key(key)],
    ['maximum', CipherBird.recipe(CipherBird::SecurityProfile::MAXIMUM).with_key(key)],
    ['signed', CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key(key)
                 .signed_by(sk, CipherBird::SignatureAlgorithm::ED25519).verified_by(pk)],
    ['passphrase', cheap(CipherBird.recipe.with_passphrase(PASSPHRASE))],
    ['fec', CipherBird.recipe.with_key(key).with_fec(CipherBird::FecScheme::REPETITION3)]
  ]
end

CipherBird.init

if ARGV.length >= 2 && %w[seal open].include?(ARGV[0])
  mode, dir = ARGV[0], ARGV[1]
  pk, sk = CipherBird.ed25519_keygen_from_seed([SK_HEX].pack('H*'))
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

puts "CipherBird #{CipherBird.version} — security profiles + recipes (Ruby)"
Dir.mktmpdir('cl_sec_rb_') do |tmp|
  secret = 'the treaty text nobody may read'.b
  mx = CipherBird::SecurityProfile.params(CipherBird::SecurityProfile::MAXIMUM)
  ck('maximum picks the strongest options',
     mx[:ml_kem_level] == 2 && mx[:ml_dsa_level] == 2 && mx[:slh_dsa_hash] == 1 && mx[:kdf_preset] == 1)
  ck('maximum cascade ends key-committing',
     mx[:cascade].length == 3 && mx[:cascade].last == CipherBird::ProtectionLayer::COMMITTING)
  ck('profiles are ordered',
     CipherBird::SecurityProfile.params(CipherBird::SecurityProfile::BALANCED)[:argon2_memory] < mx[:argon2_memory])

  key = CipherBird.random_bytes(32)
  r = CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key(key)
  ck('raw key round-trip', r.open(r.seal(secret)) == secret)

  pr = cheap(CipherBird.maximum_security.with_passphrase('correct horse battery staple'))
  ck('maximum + passphrase round-trip', pr.open(pr.seal(secret)) == secret)

  key_file = File.join(tmp, 'key.ppm')
  File.binwrite(key_file, noise_ppm(96, 96, 0x5EED))
  by_file = CipherBird.recipe.with_key_file(key_file).seal(secret)
  ck('key file reproducible across recipe objects',
     CipherBird.recipe.with_key_file(key_file).open(by_file) == secret)

  mol = CipherBird.recipe.with_key(key).with_layers([CipherBird::ProtectionLayer::MOLECULAR])
  ck('MolecularVault as one layer', mol.open(mol.seal(secret)) == secret)

  pk, sk = CipherBird.ed25519_keygen
  signed = CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key(key).signed_by(sk).verified_by(pk)
  senv = signed.seal(secret)
  ck('signed round-trip', signed.open(senv) == secret)

  hpk, hsk = CipherBird.hybrid_sig_keygen
  hy = CipherBird.recipe.with_key(key).signed_by(hsk, CipherBird::SignatureAlgorithm::HYBRID).verified_by(hpk)
  ck('hybrid PQ signed round-trip', hy.open(hy.seal(secret)) == secret)

  ipk, = CipherBird.ed25519_keygen
  ck('wrong signer rejected',
     throws? { CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key(key).verified_by(ipk).open(senv) })
  ck('signed envelope refuses to open unverified',
     throws? { CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key(key).open(senv) })

  fr = CipherBird.recipe.with_key(key).with_fec(CipherBird::FecScheme::REPETITION3)
  fenv = fr.seal(secret).dup
  fenv.setbyte(fenv.bytesize / 2, fenv.getbyte(fenv.bytesize / 2) ^ 1)
  ck('FEC corrects a flipped bit', fr.open(fenv) == secret)

  cover = File.join(tmp, 'cover.ppm')
  carrier = File.join(tmp, 'carrier.ppm')
  File.binwrite(cover, noise_ppm(256, 256, 0x0FF1CE))
  cr = cheap(CipherBird.maximum_security.with_passphrase('a long passphrase here'))
  cr.seal_into_carrier(secret, cover, carrier)
  ck('pipeline hides itself in a carrier', cr.open_from_carrier(carrier) == secret)

  tenv = r.seal(secret).dup
  tenv.setbyte(tenv.bytesize - 1, tenv.getbyte(tenv.bytesize - 1) ^ 1)
  ck('flipped ciphertext byte rejected', throws? { r.open(tenv) })
  henv = r.seal(secret).dup
  henv.setbyte(7, 1)
  ck('tampered header rejected (descriptor is AAD)', throws? { r.open(henv) })
  ck('wrong key rejected',
     throws? { CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key(CipherBird.random_bytes(32)).open(r.seal(secret)) })
  ck('foreign bytes rejected', throws? { r.open('not an envelope at all'.b) })
  ck('short key refused', throws? { CipherBird.recipe.with_key("\x00".b * 31) })
  ck('empty layer list refused', throws? { CipherBird.recipe.with_layers([]) })

  # Extension points
  pl = CipherBird::ProtectionLayer
  ck('built-in ids pinned',
     [pl::XCHACHA20_POLY1305, pl::AES256_GCM, pl::COMMITTING, pl::MOLECULAR].map(&:id) == [1, 2, 3, 4] &&
     CipherBird::PassphraseKeySource.new('x').id == 1 && CipherBird::Ed25519Signature.new.id == 1 &&
     CipherBird::HybridSignature.new.id == 2)

  pl.register(MyLayer.new)
  cenv = CipherBird.recipe.with_key(key).with_layers([MyLayer.new]).seal(secret)
  ck('custom layer round-trips via the registry', CipherBird.recipe.with_key(key).open(cenv) == secret)

  pl.register(BeltAndBraces.new)
  br = CipherBird.recipe.with_key(key).with_layers([BeltAndBraces.new])
  benv = br.seal(secret)
  ck('cascade subclass mixes three ciphers as one layer', CipherBird.recipe.with_key(key).open(benv) == secret)
  bbad = benv.dup
  bbad.setbyte(bbad.bytesize - 1, bbad.getbyte(bbad.bytesize - 1) ^ 1)
  ck('cascade fails closed on tamper', throws? { br.open(bbad) })

  nested = CipherBird::CascadeLayer.new(202, 'nested', [BeltAndBraces.new, pl::COMMITTING])
  pl.register(nested)
  nenv = CipherBird.recipe.with_key(key).with_layers([pl::XCHACHA20_POLY1305, nested]).seal(secret)
  ck('cascades nest, mixed with built-ins', CipherBird.recipe.with_key(key).open(nenv) == secret)

  ck('reserved layer id refused at register', throws? { pl.register(Impostor.new) })
  ck('reserved layer id refused at add_layer', throws? { CipherBird.recipe.with_key(key).add_layer(Impostor.new) })
  ck('reserved scheme id refused', throws? { CipherBird.recipe.with_key(key).signed_with(FakeEd25519.new) })
  pl.register(MyLayer.new)
  ck('re-registering an id under another wire_name refused',
     throws? { pl.register(CipherBird::CascadeLayer.new(200, 'other', [pl::XCHACHA20_POLY1305])) })

  e1 = CipherBird.recipe.with_key(key).with_layers([MyLayer.new]).seal(secret)
  e2 = CipherBird.recipe.with_key(key)
                .with_layers([CipherBird::CascadeLayer.new(203, 'renamed', [pl::XCHACHA20_POLY1305])]).seal(secret)
  ck('wire_name feeds the key derivation', e1.bytesize == e2.bytesize && e1 != e2)

  token = CipherBird.random_bytes(32)
  tenv2 = CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key_source(TokenSource.new(token)).seal(secret)
  ck('custom key source round-trips',
     CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key_source(TokenSource.new(token)).open(tenv2) == secret)
  ck('wrong token rejected', throws? do
    CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key_source(TokenSource.new(CipherBird.random_bytes(32))).open(tenv2)
  end)
  ck('header pins the source id', throws? { CipherBird.recipe(CipherBird::SecurityProfile::HIGH).with_key(key).open(tenv2) })
  ck('narrowing key source refused', throws? { CipherBird.recipe.with_key_source(WeakSource.new).seal(secret) })

  spk, ssk = CipherBird.ed25519_keygen
  senv3 = CipherBird.recipe.with_key(key).signed_with(PrefixedEd25519.new(sk: ssk)).seal(secret)
  ck('custom signature scheme round-trips',
     CipherBird.recipe.with_key(key).verified_with(PrefixedEd25519.new(pk: spk)).open(senv3) == secret)
  ck('key-only verifier cannot serve a custom scheme',
     throws? { CipherBird.recipe.with_key(key).verified_by(spk).open(senv3) })
  ck('unverified custom-signed envelope refused', throws? { CipherBird.recipe.with_key(key).open(senv3) })
  ck('verifier with the wrong scheme id refused', throws? do
    CipherBird.recipe.with_key(key).verified_with(CipherBird::Ed25519Signature.new(public_key: spk)).open(senv3)
  end)

  hr = CipherBird.recipe.with_key(key).signed_by(hsk, CipherBird::SignatureAlgorithm::HYBRID).verified_by(hpk)
  ck('built-in shorthand with key-only verifier', hr.open(hr.seal(secret)) == secret)

  d = CipherBird.recipe.with_key_source(TokenSource.new(token)).with_layers([BeltAndBraces.new]).describe
  ck('describe names custom parts', d.include?('token') && d.include?('belt-and-braces'))
end

puts "\n#{$pass} passed, #{$fail} failed — recipes #{$fail.zero? ? 'OK' : 'FAILED'}"
exit($fail.zero? ? 0 : 1)
