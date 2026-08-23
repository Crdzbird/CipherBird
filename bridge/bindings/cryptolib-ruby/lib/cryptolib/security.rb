# Security profiles and composable recipes.
#
# SecurityProfile sets every algorithm parameter consistently, so "use the
# strongest thing available" is one word rather than a dozen constants.
#
# Recipe stacks the library's protections in combination: derive a key, cascade
# several AEADs, sign, add error correction, hide the result in a carrier.
#
# Composition only — every step is an existing, vetted operation. What the recipe
# adds is the plumbing that is easy to get wrong by hand:
#
# * Every layer gets its OWN key, via HKDF with a distinct info string. A key is
#   never reused across two layers.
# * The header describing the recipe is authenticated as AAD by EVERY layer, so
#   the descriptor cannot be altered without every layer failing.
# * Order is fixed and not caller-selectable: sign -> encrypt (inner to outer) ->
#   error-correct -> conceal. Opening reverses it exactly.
# * Everything fails closed.
#
# The envelope is a library-native format, and is identical across every
# CryptoLib binding: one sealed here opens in Dart, Go, Node, Swift, Java or
# Python.

module CryptoLib
  # One authenticated-encryption layer in a Recipe cascade.
  module ProtectionLayer
    # XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.
    XCHACHA20_POLY1305 = 1
    # AES-256-GCM. A different cipher family from ChaCha.
    AES256_GCM = 2
    # Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.
    COMMITTING = 3
    # A full MolecularVault (cascade + committing) nested as one layer.
    MOLECULAR = 4

    # Names used in each layer's HKDF info string. Pinned explicitly: they are
    # part of the wire format, so renaming a constant must not change how keys
    # are derived — envelopes are opened by other language bindings too.
    WIRE_NAME = {
      XCHACHA20_POLY1305 => 'xchacha20Poly1305',
      AES256_GCM => 'aes256Gcm',
      COMMITTING => 'committing',
      MOLECULAR => 'molecular'
    }.freeze
  end

  # Origin-authentication algorithm for a Recipe.
  module SignatureAlgorithm
    # No signature. The AEAD still guarantees integrity, but not who sent it.
    NONE = 0
    # Ed25519.
    ED25519 = 1
    # Ed25519 + ML-DSA-65. A forgery needs breaking both families.
    HYBRID = 2
  end

  # Forward-error-correction scheme applied to a finished envelope.
  module FecScheme
    NONE = 0
    REPETITION3 = 1
    REPETITION5 = 2
    HAMMING74 = 3
  end

  # A coherent set of algorithm parameters, from ordinary to maximal. Every
  # field moves together, so a maximal KEM cannot be paired with an
  # interactive-cost KDF.
  class SecurityProfile
    BALANCED = :balanced
    HIGH = :high
    MAXIMUM = :maximum

    PARAMS = {
      balanced: { ml_kem_level: 1, ml_dsa_level: 1, slh_dsa_level: 1, slh_dsa_hash: 0,
                  sealed_tier: 0, kdf_preset: 0, argon2_ops: 2, argon2_memory: 64 * 1024 * 1024,
                  cascade: [ProtectionLayer::XCHACHA20_POLY1305] },
      high:     { ml_kem_level: 1, ml_dsa_level: 1, slh_dsa_level: 3, slh_dsa_hash: 0,
                  sealed_tier: 0, kdf_preset: 1, argon2_ops: 3, argon2_memory: 256 * 1024 * 1024,
                  cascade: [ProtectionLayer::XCHACHA20_POLY1305, ProtectionLayer::AES256_GCM] },
      maximum:  { ml_kem_level: 2, ml_dsa_level: 2, slh_dsa_level: 4, slh_dsa_hash: 1,
                  sealed_tier: 1, kdf_preset: 1, argon2_ops: 4, argon2_memory: 512 * 1024 * 1024,
                  cascade: [ProtectionLayer::XCHACHA20_POLY1305, ProtectionLayer::AES256_GCM,
                            ProtectionLayer::COMMITTING] }
    }.freeze

    # Every parameter for a profile, as a frozen hash.
    def self.params(profile) = PARAMS.fetch(profile)
  end

  # A composable protection pipeline.
  #
  #   r = CryptoLib.maximum_security.with_passphrase('correct horse battery staple')
  #   back = r.open(r.seal(secret))
  #
  # Builder methods return self so calls chain. Not thread-safe.
  class Recipe
    MAGIC = 'CLRC'.b.freeze
    FEC_MAGIC = 'CLFC'.b.freeze
    VERSION = 1
    SALT_LEN = 16
    SOURCE_NAME = { 0 => 'raw', 1 => 'passphrase', 2 => 'keyFile' }.freeze

    attr_reader :profile

    def initialize(profile = SecurityProfile::BALANCED)
      p = SecurityProfile.params(profile)
      @profile = profile
      @layers = p[:cascade].dup
      @source = 0
      @sign_algorithm = SignatureAlgorithm::NONE
      @fec = FecScheme::NONE
      @argon_ops = p[:argon2_ops]
      @argon_memory = p[:argon2_memory]
    end

    # Derive the root key from a passphrase with Argon2id.
    def with_passphrase(passphrase)
      @source = 1
      @passphrase = passphrase
      self
    end

    # Use a 32-byte full-entropy key directly (KEM secret, keyring unlock, token).
    def with_key(key)
      raise ArgumentError, "cryptolib: root key must be exactly 32 bytes, got #{key.bytesize}" unless key.bytesize == 32

      @source = 0
      @raw_key = key.b
      self
    end

    # Derive the root key deterministically from a media file — "the file is the
    # key". The same file always yields the same key on any machine.
    def with_key_file(path)
      @source = 2
      @key_file = path
      self
    end

    # Replace the cascade with exactly these layers, innermost first.
    def with_layers(layers)
      raise ArgumentError, 'cryptolib: a recipe needs at least one layer' if layers.nil? || layers.empty?

      @layers = layers.dup
      self
    end

    # Append one more layer on the outside of the current cascade.
    def add_layer(layer)
      @layers << layer
      self
    end

    # Override the Argon2id cost. Only meaningful with with_passphrase.
    def argon2_cost(ops: nil, memory_bytes: nil)
      @argon_ops = ops unless ops.nil?
      @argon_memory = memory_bytes unless memory_bytes.nil?
      self
    end

    # Sign the plaintext before it is encrypted, so the signature stays
    # confidential and proves who produced it.
    def signed_by(secret_key, algorithm = SignatureAlgorithm::ED25519)
      raise ArgumentError, 'cryptolib: signed_by needs a real algorithm' if algorithm == SignatureAlgorithm::NONE

      @sign_algorithm = algorithm
      @sign_secret = secret_key.b
      self
    end

    # The public key +open+ must verify against. Required whenever the envelope
    # is signed: otherwise there would be a signature and nobody checking it.
    def verified_by(public_key)
      @sign_public = public_key.b
      self
    end

    # Apply forward error correction to the finished envelope.
    def with_fec(scheme)
      @fec = scheme
      self
    end

    # Protect +plaintext+ and return the envelope.
    def seal(plaintext)
      salt = CryptoLib.random_bytes(SALT_LEN)
      header = build_header(salt)
      root = root_key(salt, @argon_ops, @argon_memory)

      body = plaintext.b
      unless @sign_algorithm == SignatureAlgorithm::NONE
        raise 'cryptolib: signing requested without a secret key' if @sign_secret.nil?

        sig = if @sign_algorithm == SignatureAlgorithm::ED25519
                CryptoLib.ed25519_sign(body, @sign_secret)
              else
                CryptoLib.hybrid_sig_sign(body, @sign_secret)
              end
        body = [sig.bytesize].pack('N') + sig + body
      end

      @layers.each_with_index { |layer, i| body = apply_layer(layer, i, root, salt, header, body, true) }
      envelope = header + body
      @fec == FecScheme::NONE ? envelope : wrap_fec(envelope)
    end

    # Recover the plaintext. Raises on a wrong key, an altered byte, or a bad
    # signature.
    def open(envelope)
      inner = unwrap_fec(envelope.b)
      header, layers, salt, sign_algorithm, ops, memory = parse_header(inner)
      root = root_key(salt, ops, memory)

      body = inner[header.bytesize..]
      (layers.length - 1).downto(0) { |i| body = apply_layer(layers[i], i, root, salt, header, body, false) }
      return body if sign_algorithm == SignatureAlgorithm::NONE

      raise 'cryptolib: malformed signed payload' if body.bytesize < 4

      n = body[0, 4].unpack1('N')
      raise 'cryptolib: malformed signed payload' if body.bytesize < 4 + n

      sig = body[4, n]
      plaintext = body[(4 + n)..]
      if @sign_public.nil?
        raise 'cryptolib: envelope is signed but no public key was supplied — ' \
              'call verified_by so the signature is actually checked'
      end
      ok = if sign_algorithm == SignatureAlgorithm::ED25519
             CryptoLib.ed25519_verify(plaintext, sig, @sign_public)
           else
             CryptoLib.hybrid_sig_verify(plaintext, sig, @sign_public)
           end
      raise 'cryptolib: signature verification failed' unless ok

      plaintext
    end

    # Seal and hide the envelope inside a carrier. Defence-in-depth, never the
    # confidentiality boundary — the envelope is already authenticated-encrypted.
    def seal_into_carrier(plaintext, cover_path, output_path)
      CryptoLib.stego_embed(cover_path, seal(plaintext), output_path)
    end

    # Extract and open an envelope written by seal_into_carrier.
    def open_from_carrier(stego_path) = open(CryptoLib.stego_extract(stego_path))

    # Human-readable summary — useful in logs and review.
    def describe
      names = @layers.map { |l| ProtectionLayer::WIRE_NAME[l] }.join(' -> ')
      sig = { 0 => 'none', 1 => 'ed25519', 2 => 'hybrid' }[@sign_algorithm]
      out = +"Recipe(#{@profile})\n  key      : #{SOURCE_NAME[@source]}\n" \
             "  layers   : #{names}\n  signature: #{sig}\n  fec      : #{@fec}\n"
      out << "  argon2id : ops=#{@argon_ops}, mem=#{@argon_memory / (1024 * 1024)}MiB\n" if @source == 1
      out
    end

    private

    def root_key(salt, ops, memory)
      case @source
      when 1
        raise 'cryptolib: no passphrase set' if @passphrase.nil?

        CryptoLib.argon2id_derive(@passphrase, salt, key_len: 32, ops: ops, memory_bytes: memory)
      when 2
        raise 'cryptolib: no key file set' if @key_file.nil?

        CryptoLib.key_from_file_deterministic(@key_file)
      else
        raise 'cryptolib: no key set — call with_key/with_passphrase/with_key_file' if @raw_key.nil?

        @raw_key
      end
    end

    # HKDF under a distinct info string, so no two layers share key material.
    def layer_key(root, salt, index, layer)
      info = "cryptolib/recipe/v1/layer#{index}/#{ProtectionLayer::WIRE_NAME[layer]}"
      CryptoLib.hkdf_derive(root, salt: salt, info: info.b, out_len: 32)
    end

    def apply_layer(layer, index, root, salt, header, data, seal)
      key = layer_key(root, salt, index, layer)
      case layer
      when ProtectionLayer::XCHACHA20_POLY1305
        seal ? CryptoLib.xchacha20_encrypt(data, key, header) : CryptoLib.xchacha20_decrypt(data, key, header)
      when ProtectionLayer::AES256_GCM
        seal ? CryptoLib.aes256gcm_encrypt(data, key, header) : CryptoLib.aes256gcm_decrypt(data, key, header)
      when ProtectionLayer::COMMITTING
        seal ? CryptoLib.committing_encrypt(data, key, header) : CryptoLib.committing_decrypt(data, key, header)
      when ProtectionLayer::MOLECULAR
        seal ? CryptoLib.molecular_seal_with_key(data, key, header) : CryptoLib.molecular_open_with_key(data, key, header)
      else
        raise "cryptolib: unknown protection layer #{layer}"
      end
    end

    def build_header(salt)
      MAGIC + [VERSION, @source, @sign_algorithm, @layers.length].pack('C4') +
        @layers.pack('C*') + salt + [@argon_ops, @argon_memory].pack('NN')
    end

    def parse_header(env)
      raise 'cryptolib: envelope too short' if env.bytesize < 8 + SALT_LEN + 8
      raise 'cryptolib: not a CryptoRecipe envelope' unless env[0, 4] == MAGIC
      raise "cryptolib: unsupported envelope version #{env.getbyte(4)}" unless env.getbyte(4) == VERSION

      source = env.getbyte(5)
      unless source == @source
        raise "cryptolib: envelope was sealed with the #{SOURCE_NAME[source]} key source, " \
              "but this recipe is configured for #{SOURCE_NAME[@source]}"
      end
      sign_algorithm = env.getbyte(6)
      count = env.getbyte(7)
      header_len = 8 + count + SALT_LEN + 8
      raise 'cryptolib: truncated envelope header' if env.bytesize < header_len

      layers = (0...count).map do |i|
        id = env.getbyte(8 + i)
        raise "cryptolib: unknown protection layer id #{id}" unless ProtectionLayer::WIRE_NAME.key?(id)

        id
      end
      salt = env[8 + count, SALT_LEN]
      ops, memory = env[8 + count + SALT_LEN, 8].unpack('NN')
      [env[0, header_len], layers, salt, sign_algorithm, ops, memory]
    end

    def wrap_fec(envelope)
      FEC_MAGIC + [@fec].pack('C') + [envelope.bytesize].pack('N') + CryptoLib.fec_encode(envelope, @fec)
    end

    def unwrap_fec(data)
      return data if data.bytesize < 9 || data[0, 4] != FEC_MAGIC

      CryptoLib.fec_decode(data[9..], data.getbyte(4), data[5, 4].unpack1('N'))
    end
  end

  # Start a Recipe at the given profile's settings.
  def self.recipe(profile = SecurityProfile::BALANCED) = Recipe.new(profile)

  # A Recipe using the strongest option at every choice.
  def self.maximum_security = Recipe.new(SecurityProfile::MAXIMUM)
end
