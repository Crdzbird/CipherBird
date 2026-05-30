Gem::Specification.new do |s|
  s.name        = 'cryptolib'
  s.version     = '3.0.0'
  s.summary     = 'CryptoLib for Ruby — classical + post-quantum + hybrid primitives via FFI.'
  s.description = 'Ruby FFI bindings to CryptoLib (hashing, AEAD, asymmetric, ML-KEM/ML-DSA/SLH-DSA, hybrid KEM, BLS, keyring). Bundled native library, no manual setup.'
  s.authors     = ['CryptoLib']
  s.email       = ['licensing@example.com']
  s.license     = 'MIT'
  s.required_ruby_version = '>= 3.0'

  s.files = Dir['lib/**/*'] + Dir['lib/cryptolib/native/**/*']
  s.require_paths = ['lib']

  s.add_dependency 'ffi', '~> 1.16'
end
