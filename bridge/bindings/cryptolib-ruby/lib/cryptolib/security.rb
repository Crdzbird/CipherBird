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
  # ── Extension points ───────────────────────────────────────────────────────
  #
  # Three base classes can be subclassed and plugged into a Recipe:
  #   ProtectionLayer  — one authenticated-encryption layer in the cascade.
  #   KeySource        — where the 32-byte root key comes from.
  #   SignatureScheme  — how the plaintext is signed and verified.
  # The library's own implementations subclass the same bases, so a custom one
  # is a first-class citizen. To compose several ciphers into ONE layer,
  # subclass CascadeLayer.
  #
  # What the recipe keeps for itself, whatever you plug in: a layer never
  # chooses its key (it receives a fresh 32-byte key per layer per envelope,
  # HKDF-derived under salt + wire_name); a layer cannot opt out of the AAD; the
  # order is fixed (sign -> encrypt -> correct -> conceal); a KeySource must
  # return exactly 32 bytes; ids 0–127 are reserved — custom parts must use
  # 128–255, enforced so a custom part can never shadow a built-in.
  #
  # Cross-language: built-in ids open in every CryptoLib binding. A custom part
  # opens only where the same id + wire_name + algorithm is registered — and
  # since wire_name feeds the key derivation, a mismatched implementation fails
  # the AEAD tag rather than yielding garbage.

  # Library-private marker carried by the built-in parts, so a subclass cannot
  # claim a reserved id by pretending to be built in.
  module Builtin; end
  private_constant :Builtin

  CUSTOM_ID_RANGE = (128..255).freeze

  def self.require_valid_id!(part, id, what)
    return if part.is_a?(Builtin)
    return if id.is_a?(Integer) && CUSTOM_ID_RANGE.cover?(id)

    raise ArgumentError, "cryptolib: custom #{what} ids must be in 128..255 (0–127 are reserved), got #{id}"
  end

  # One authenticated-encryption layer in a Recipe cascade.
  #
  # Subclass it to add your own layer, then ProtectionLayer.register it (on the
  # opening side too — the envelope stores only the id). Contract: +seal+ must
  # be authenticated encryption that binds +aad+, and +open+ must raise on any
  # modification. The key is fresh per layer per envelope — never reuse it.
  #
  #   class MyLayer < CryptoLib::ProtectionLayer
  #     def id = 200
  #     def wire_name = 'my-xchacha'
  #     def seal(key, aad, pt) = CryptoLib.xchacha20_encrypt(pt, key, aad)
  #     def open(key, aad, ct) = CryptoLib.xchacha20_decrypt(ct, key, aad)
  #   end
  #   CryptoLib::ProtectionLayer.register(MyLayer.new)
  class ProtectionLayer
    # Recorded in the envelope header. Built-ins use 1–4; custom 128–255.
    def id = raise(NotImplementedError, "#{self.class}#id")
    # Feeds this layer's HKDF info string. Part of the wire format.
    def wire_name = raise(NotImplementedError, "#{self.class}#wire_name")
    def seal(_key, _aad, _plaintext) = raise(NotImplementedError, "#{self.class}#seal")
    def open(_key, _aad, _ciphertext) = raise(NotImplementedError, "#{self.class}#open")

    def to_s = wire_name
    def inspect = "#<#{self.class} #{wire_name} id=#{id}>"

    @registry = {}

    class << self
      # Make a custom layer resolvable by id when opening. Re-registering an id
      # under a different wire_name is refused.
      def register(layer)
        CryptoLib.require_valid_id!(layer, layer.id, 'layer')
        existing = ProtectionLayer.registry[layer.id]
        if existing && existing.wire_name != layer.wire_name
          raise ArgumentError, "cryptolib: layer id #{layer.id} is already registered as '#{existing.wire_name}'"
        end

        ProtectionLayer.registry[layer.id] = layer
      end

      def from_id(id)
        ProtectionLayer.registry.fetch(id) do
          raise ArgumentError, "cryptolib: unknown protection layer id #{id} — ProtectionLayer.register it before opening"
        end
      end

      def registry = ProtectionLayer.instance_variable_get(:@registry)
    end

    # The four library layers. Each is a real AEAD from the C ABI.
    class BuiltinLayer < ProtectionLayer
      include Builtin
      attr_reader :id, :wire_name

      def initialize(id, wire_name, enc, dec)
        @id = id
        @wire_name = wire_name
        @enc = enc
        @dec = dec
        freeze
      end

      def seal(key, aad, plaintext) = CryptoLib.public_send(@enc, plaintext, key, aad)
      def open(key, aad, ciphertext) = CryptoLib.public_send(@dec, ciphertext, key, aad)
    end
    private_constant :BuiltinLayer

    # XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.
    XCHACHA20_POLY1305 = BuiltinLayer.new(1, 'xchacha20Poly1305', :xchacha20_encrypt, :xchacha20_decrypt)
    # AES-256-GCM. A different cipher family from ChaCha.
    AES256_GCM = BuiltinLayer.new(2, 'aes256Gcm', :aes256gcm_encrypt, :aes256gcm_decrypt)
    # Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.
    COMMITTING = BuiltinLayer.new(3, 'committing', :committing_encrypt, :committing_decrypt)
    # A full MolecularVault (cascade + committing) nested as one layer.
    MOLECULAR = BuiltinLayer.new(4, 'molecular', :molecular_seal_with_key, :molecular_open_with_key)

    [XCHACHA20_POLY1305, AES256_GCM, COMMITTING, MOLECULAR].each { |l| @registry[l.id] = l }
  end

  # A layer that is itself a mixture of layers — the way to compose several
  # encryptions into one custom type. Subclass it, or instantiate it directly:
  #
  #   class BeltAndBraces < CryptoLib::CascadeLayer
  #     def initialize = super(201, 'belt-and-braces', [CryptoLib::ProtectionLayer::XCHACHA20_POLY1305, MyLayer.new])
  #   end
  #
  # Each inner layer receives its own sub-key, HKDF-derived from this layer's
  # key under the inner index and wire_name, so nesting never collapses two
  # ciphers onto one key. The AAD is bound by every inner layer. Cascades nest.
  class CascadeLayer < ProtectionLayer
    attr_reader :id, :wire_name, :layers

    def initialize(id, wire_name, layers)
      raise ArgumentError, "cryptolib: CascadeLayer '#{wire_name}' has no layers" if layers.nil? || layers.empty?

      @id = id
      @wire_name = wire_name
      @layers = layers.dup.freeze
    end

    def seal(key, aad, plaintext)
      body = plaintext
      @layers.each_with_index { |l, i| body = l.seal(sub_key(key, i), aad, body) }
      body
    end

    def open(key, aad, ciphertext)
      body = ciphertext
      (@layers.length - 1).downto(0) { |i| body = @layers[i].open(sub_key(key, i), aad, body) }
      body
    end

    private

    def sub_key(key, i)
      CryptoLib.hkdf_derive(key, salt: ''.b, info: "#{@wire_name}/#{i}/#{@layers[i].wire_name}".b, out_len: 32)
    end
  end

  # Where a Recipe's 32-byte root key comes from. Subclass it for a hardware
  # token, a KMS, a keyring unlock — anything that can produce the same 32 bytes
  # again when opening. The recipe refuses any other length.
  class KeySource
    # Recorded in the envelope header. Built-ins use 0–2; custom 128–255.
    def id = raise(NotImplementedError, "#{self.class}#id")
    def label = raise(NotImplementedError, "#{self.class}#label")
    # +salt+ is fresh per envelope; ops/memory are the recipe's Argon2id cost.
    def derive_root(_salt, _argon2_ops, _argon2_memory) = raise(NotImplementedError, "#{self.class}#derive_root")
  end

  # A 32-byte full-entropy key used as-is (KEM secret, keyring unlock, token).
  class RawKeySource < KeySource
    include Builtin

    def initialize(key)
      raise ArgumentError, "cryptolib: root key must be exactly 32 bytes, got #{key.bytesize}" unless key.bytesize == 32

      @key = key.b.freeze
    end

    def id = 0
    def label = 'raw'
    def derive_root(_salt, _ops, _memory) = @key
  end

  # A passphrase stretched with Argon2id at the recipe's cost.
  class PassphraseKeySource < KeySource
    include Builtin

    def initialize(passphrase) = @passphrase = passphrase
    def id = 1
    def label = 'passphrase'

    def derive_root(salt, ops, memory)
      CryptoLib.argon2id_derive(@passphrase, salt, key_len: 32, ops: ops, memory_bytes: memory)
    end
  end

  # The key derived deterministically from a media file — "the file is the key".
  # Uses the reproducible entropy path; key_from_file mixes in fresh system
  # entropy and so could never reopen its own envelope.
  class KeyFileSource < KeySource
    include Builtin

    def initialize(path) = @path = path
    def id = 2
    def label = 'keyFile'
    def derive_root(_salt, _ops, _memory) = CryptoLib.key_from_file_deterministic(@path)
  end

  # How a Recipe signs and verifies the plaintext. Subclass it for another
  # algorithm; a scheme holding only a public key should raise from +sign+.
  # The signature is applied before encryption, so it stays confidential.
  # Custom schemes are verified only through Recipe#verified_with.
  class SignatureScheme
    # Recorded in the envelope header. Built-ins use 1–2; custom 128–255.
    def id = raise(NotImplementedError, "#{self.class}#id")
    def label = raise(NotImplementedError, "#{self.class}#label")
    def sign(_message) = raise(NotImplementedError, "#{self.class}#sign")
    def verify(_message, _signature) = raise(NotImplementedError, "#{self.class}#verify")
  end

  # Ed25519. Pass +secret_key:+ to sign, +public_key:+ to verify, or both.
  class Ed25519Signature < SignatureScheme
    include Builtin

    def initialize(secret_key: nil, public_key: nil)
      @sk = secret_key&.b
      @pk = public_key&.b
    end

    def id = 1
    def label = 'ed25519'

    def sign(message)
      raise 'cryptolib: Ed25519Signature has no secret key' if @sk.nil?

      CryptoLib.ed25519_sign(message, @sk)
    end

    def verify(message, signature) = !@pk.nil? && CryptoLib.ed25519_verify(message, signature, @pk)
  end

  # Ed25519 + ML-DSA-65. A forgery needs breaking both families.
  class HybridSignature < SignatureScheme
    include Builtin

    def initialize(secret_key: nil, public_key: nil)
      @sk = secret_key&.b
      @pk = public_key&.b
    end

    def id = 2
    def label = 'hybrid'

    def sign(message)
      raise 'cryptolib: HybridSignature has no secret key' if @sk.nil?

      CryptoLib.hybrid_sig_sign(message, @sk)
    end

    def verify(message, signature) = !@pk.nil? && CryptoLib.hybrid_sig_verify(message, signature, @pk)
  end

  # Built-in scheme selector for the Recipe#signed_by shorthand.
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
  # Every part is replaceable with your own subclass — see ProtectionLayer,
  # KeySource and SignatureScheme. Builder methods return self so calls chain.
  # Not thread-safe.
  class Recipe
    MAGIC = 'CLRC'.b.freeze
    FEC_MAGIC = 'CLFC'.b.freeze
    VERSION = 1
    SALT_LEN = 16

    attr_reader :profile

    def initialize(profile = SecurityProfile::BALANCED)
      p = SecurityProfile.params(profile)
      @profile = profile
      @layers = p[:cascade].dup
      @source = nil
      @signer = nil
      @verifier = nil
      @verifier_key = nil
      @fec = FecScheme::NONE
      @argon_ops = p[:argon2_ops]
      @argon_memory = p[:argon2_memory]
    end

    # Use any KeySource — a built-in or your own subclass.
    def with_key_source(source)
      raise TypeError, 'cryptolib: with_key_source expects a KeySource' unless source.is_a?(KeySource)

      CryptoLib.require_valid_id!(source, source.id, 'key source')
      @source = source
      self
    end

    # Derive the root key from a passphrase with Argon2id.
    def with_passphrase(passphrase) = with_key_source(PassphraseKeySource.new(passphrase))

    # Use a 32-byte full-entropy key directly (KEM secret, keyring unlock, token).
    def with_key(key) = with_key_source(RawKeySource.new(key))

    # Derive the root key deterministically from a media file — "the file is the
    # key". The same file always yields the same key on any machine.
    def with_key_file(path) = with_key_source(KeyFileSource.new(path))

    # Replace the cascade with exactly these layers, innermost first.
    def with_layers(layers)
      raise ArgumentError, 'cryptolib: a recipe needs at least one layer' if layers.nil? || layers.empty?

      layers.each { |l| check_layer(l) }
      @layers = layers.dup
      self
    end

    # Append one more layer on the outside of the current cascade.
    def add_layer(layer)
      check_layer(layer)
      @layers << layer
      self
    end

    # Override the Argon2id cost. Only meaningful with with_passphrase.
    def argon2_cost(ops: nil, memory_bytes: nil)
      @argon_ops = ops unless ops.nil?
      @argon_memory = memory_bytes unless memory_bytes.nil?
      self
    end

    # Sign with any SignatureScheme — a built-in or your own subclass.
    def signed_with(scheme)
      raise TypeError, 'cryptolib: signed_with expects a SignatureScheme' unless scheme.is_a?(SignatureScheme)

      CryptoLib.require_valid_id!(scheme, scheme.id, 'signature scheme')
      @signer = scheme
      self
    end

    # Verify with any SignatureScheme. Required for a custom scheme.
    def verified_with(scheme)
      raise TypeError, 'cryptolib: verified_with expects a SignatureScheme' unless scheme.is_a?(SignatureScheme)

      CryptoLib.require_valid_id!(scheme, scheme.id, 'signature scheme')
      @verifier = scheme
      @verifier_key = nil
      self
    end

    # Sign the plaintext before it is encrypted with a built-in scheme, so the
    # signature stays confidential and proves who produced it.
    def signed_by(secret_key, algorithm = SignatureAlgorithm::ED25519)
      case algorithm
      when SignatureAlgorithm::ED25519 then signed_with(Ed25519Signature.new(secret_key: secret_key))
      when SignatureAlgorithm::HYBRID then signed_with(HybridSignature.new(secret_key: secret_key))
      else raise ArgumentError, 'cryptolib: signed_by needs a real algorithm'
      end
    end

    # The public key +open+ must verify against. Works for either built-in
    # scheme — the envelope records which one. A custom SignatureScheme must be
    # supplied through verified_with.
    def verified_by(public_key)
      @verifier = nil
      @verifier_key = public_key.b
      self
    end

    # Apply forward error correction to the finished envelope.
    def with_fec(scheme)
      @fec = scheme
      self
    end

    # Protect +plaintext+ and return the envelope.
    def seal(plaintext)
      source = require_source
      salt = CryptoLib.random_bytes(SALT_LEN)
      header = build_header(source, salt)
      root = root_key(source, salt, @argon_ops, @argon_memory)

      body = plaintext.b
      unless @signer.nil?
        sig = @signer.sign(body)
        body = [sig.bytesize].pack('N') + sig + body
      end

      @layers.each_with_index { |layer, i| body = apply_layer(layer, i, root, salt, header, body, true) }
      envelope = header + body
      @fec == FecScheme::NONE ? envelope : wrap_fec(envelope)
    end

    # Recover the plaintext. Raises on a wrong key, an altered byte, or a bad
    # signature.
    def open(envelope)
      source = require_source
      inner = unwrap_fec(envelope.b)
      header, layers, salt, signature_id, ops, memory = parse_header(inner, source)
      root = root_key(source, salt, ops, memory)

      body = inner[header.bytesize..]
      (layers.length - 1).downto(0) { |i| body = apply_layer(layers[i], i, root, salt, header, body, false) }
      return body if signature_id.zero?

      raise 'cryptolib: malformed signed payload' if body.bytesize < 4

      n = body[0, 4].unpack1('N')
      raise 'cryptolib: malformed signed payload' if body.bytesize < 4 + n

      sig = body[4, n]
      plaintext = body[(4 + n)..]
      verifier = @verifier || builtin_verifier(signature_id)
      if verifier.nil?
        unless @verifier_key.nil?
          raise "cryptolib: envelope was signed with scheme id #{signature_id}, which is not a built-in — " \
                'supply that SignatureScheme with verified_with'
        end
        raise 'cryptolib: envelope is signed but no verifier was supplied — ' \
              'call verified_by/verified_with so the signature is actually checked'
      end
      unless verifier.id == signature_id
        raise "cryptolib: envelope was signed with scheme id #{signature_id}, " \
              "but the verifier is '#{verifier.label}' (id #{verifier.id})"
      end
      raise 'cryptolib: signature verification failed' unless verifier.verify(plaintext, sig)

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
      names = @layers.map(&:wire_name).join(' -> ')
      out = +"Recipe(#{@profile})\n  key      : #{@source&.label || '(unset)'}\n" \
             "  layers   : #{names}\n  signature: #{@signer&.label || 'none'}\n  fec      : #{@fec}\n"
      if @source.is_a?(PassphraseKeySource)
        out << "  argon2id : ops=#{@argon_ops}, mem=#{@argon_memory / (1024 * 1024)}MiB\n"
      end
      out
    end

    private

    def check_layer(layer)
      raise TypeError, 'cryptolib: layers must be ProtectionLayer instances' unless layer.is_a?(ProtectionLayer)

      CryptoLib.require_valid_id!(layer, layer.id, 'layer')
    end

    def require_source
      raise 'cryptolib: no key set — call with_key/with_passphrase/with_key_file/with_key_source' if @source.nil?

      @source
    end

    def builtin_verifier(id)
      return nil if @verifier_key.nil?

      case id
      when SignatureAlgorithm::ED25519 then Ed25519Signature.new(public_key: @verifier_key)
      when SignatureAlgorithm::HYBRID then HybridSignature.new(public_key: @verifier_key)
      end
    end

    def root_key(source, salt, ops, memory)
      root = source.derive_root(salt, ops, memory)
      unless root.is_a?(String) && root.bytesize == 32
        raise "cryptolib: key source '#{source.label}' produced #{root.respond_to?(:bytesize) ? root.bytesize : 0} bytes; " \
              'the root key must be exactly 32'
      end
      root.b
    end

    # HKDF under a distinct info string, so no two layers share key material.
    def layer_key(root, salt, index, layer)
      info = "cryptolib/recipe/v1/layer#{index}/#{layer.wire_name}"
      CryptoLib.hkdf_derive(root, salt: salt, info: info.b, out_len: 32)
    end

    def apply_layer(layer, index, root, salt, header, data, seal)
      key = layer_key(root, salt, index, layer)
      seal ? layer.seal(key, header, data) : layer.open(key, header, data)
    end

    def build_header(source, salt)
      MAGIC + [VERSION, source.id, @signer&.id || 0, @layers.length].pack('C4') +
        @layers.map(&:id).pack('C*') + salt + [@argon_ops, @argon_memory].pack('NN')
    end

    def parse_header(env, source)
      raise 'cryptolib: envelope too short' if env.bytesize < 8 + SALT_LEN + 8
      raise 'cryptolib: not a CryptoRecipe envelope' unless env[0, 4] == MAGIC
      raise "cryptolib: unsupported envelope version #{env.getbyte(4)}" unless env.getbyte(4) == VERSION

      src_id = env.getbyte(5)
      unless src_id == source.id
        raise "cryptolib: envelope was sealed with key source id #{src_id}, " \
              "but this recipe is configured for '#{source.label}' (id #{source.id})"
      end
      signature_id = env.getbyte(6)
      count = env.getbyte(7)
      header_len = 8 + count + SALT_LEN + 8
      raise 'cryptolib: truncated envelope header' if env.bytesize < header_len

      layers = (0...count).map { |i| ProtectionLayer.from_id(env.getbyte(8 + i)) }
      salt = env[8 + count, SALT_LEN]
      ops, memory = env[8 + count + SALT_LEN, 8].unpack('NN')
      [env[0, header_len], layers, salt, signature_id, ops, memory]
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
