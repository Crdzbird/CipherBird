# CryptoLib for Ruby — FFI bindings over the C ABI.
#
# The native library is bundled in the gem under lib/cryptolib/native/<plat>-<arch>/
# and loaded automatically; consumers never provide a path:
#
#   require 'cryptolib'
#   CryptoLib.init
#   CryptoLib.version                                # => "3.0.0"
#   CryptoLib.sha256('abc').unpack1('H*')
#   pub, sec = CryptoLib.hybrid_kem_keygen
#   ct, ss   = CryptoLib.hybrid_kem_encapsulate(pub)
#   ss2      = CryptoLib.hybrid_kem_decapsulate(ct, sec)

require 'ffi'

module CryptoLib
  VERSION = '3.0.0'

  module Native
    extend FFI::Library

    def self._lib_path
      return ENV['CRYPTOLIB_DYLIB'] if ENV['CRYPTOLIB_DYLIB'] && !ENV['CRYPTOLIB_DYLIB'].empty?
      os = case RbConfig::CONFIG['host_os']
           when /darwin/ then 'darwin'
           when /mingw|mswin|cygwin/ then 'win32'
           else 'linux'
           end
      arch = case RbConfig::CONFIG['host_cpu']
             when /x86_64|amd64/ then 'x86_64'
             when /arm64|aarch64/ then 'arm64'
             else RbConfig::CONFIG['host_cpu']
             end
      ext = case os
            when 'darwin' then 'dylib'
            when 'win32'  then 'dll'
            else 'so'
            end
      File.join(__dir__, 'cryptolib', 'native', "#{os}-#{arch}", "libcryptolib_c.#{ext}")
    end

    ffi_lib _lib_path

    class CryptoBuffer < FFI::Struct
      layout :data, :pointer, :len, :size_t
    end
    class CryptoBufferResult < FFI::Struct
      layout :buf, CryptoBuffer, :error, :pointer
    end
    class CryptoKeyPair < FFI::Struct
      layout :public_key, CryptoBuffer, :secret_key, CryptoBuffer
    end
    class CryptoKemEncapsResult < FFI::Struct
      layout :ciphertext, CryptoBuffer, :shared_secret, CryptoBuffer
    end
    class CryptoResult < FFI::Struct
      layout :ok, :int, :error, :pointer
    end

    attach_function :cryptolib_init,    [], :int
    attach_function :cryptolib_version, [], :string
    attach_function :cryptolib_random_bytes, [:size_t], CryptoBufferResult.by_value
    attach_function :cryptolib_sha256,  [:pointer, :size_t], CryptoBufferResult.by_value
    attach_function :cryptolib_hybrid_kem_keygen,      [], CryptoKeyPair.by_value
    attach_function :cryptolib_hybrid_kem_encapsulate, [:pointer, :size_t, :pointer], CryptoKemEncapsResult.by_value
    attach_function :cryptolib_hybrid_kem_decapsulate, [:pointer, :size_t, :pointer, :size_t], CryptoBufferResult.by_value
    attach_function :cryptolib_buffer_free,     [:pointer], :void
    attach_function :cryptolib_keypair_free,    [:pointer], :void
    attach_function :cryptolib_kem_encaps_free, [:pointer], :void
    attach_function :cryptolib_str_free,        [:pointer], :void

    # Primitives the composable Recipe pipeline is built from.
    AEAD = [:pointer, :size_t, :pointer, :size_t, :pointer, :size_t].freeze
    attach_function :cryptolib_argon2id_derive, [:string, :pointer, :size_t, :size_t, :uint64, :size_t], CryptoBufferResult.by_value
    attach_function :cryptolib_hkdf_derive, [:pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :size_t], CryptoBufferResult.by_value
    attach_function :cryptolib_xchacha20_encrypt, AEAD, CryptoBufferResult.by_value
    attach_function :cryptolib_xchacha20_decrypt, AEAD, CryptoBufferResult.by_value
    attach_function :cryptolib_aes256gcm_encrypt, AEAD, CryptoBufferResult.by_value
    attach_function :cryptolib_aes256gcm_decrypt, AEAD, CryptoBufferResult.by_value
    attach_function :cryptolib_committing_encrypt, AEAD, CryptoBufferResult.by_value
    attach_function :cryptolib_committing_decrypt, AEAD, CryptoBufferResult.by_value
    attach_function :cryptolib_molecular_seal_with_key, AEAD, CryptoBufferResult.by_value
    attach_function :cryptolib_molecular_open_with_key, AEAD, CryptoBufferResult.by_value
    attach_function :cryptolib_ed25519_keygen, [], CryptoKeyPair.by_value
    attach_function :cryptolib_ed25519_keygen_from_seed, [:pointer, :size_t], CryptoKeyPair.by_value
    attach_function :cryptolib_ed25519_sign, [:pointer, :size_t, :pointer, :size_t], CryptoBufferResult.by_value
    attach_function :cryptolib_ed25519_verify, [:pointer, :size_t, :pointer, :size_t, :pointer, :size_t], :int
    attach_function :cryptolib_hybrid_sig_keygen, [], CryptoKeyPair.by_value
    attach_function :cryptolib_hybrid_sig_sign, [:pointer, :size_t, :pointer, :size_t], CryptoBufferResult.by_value
    attach_function :cryptolib_hybrid_sig_verify, [:pointer, :size_t, :pointer, :size_t, :pointer, :size_t], :int
    attach_function :cryptolib_entropy_from_file_deterministic, [:string, :pointer], :pointer
    attach_function :cryptolib_entropy_symmetric_key, [:pointer], CryptoBufferResult.by_value
    attach_function :cryptolib_entropy_free, [:pointer], :void
    attach_function :cryptolib_stego_embed, [:string, :pointer, :size_t, :string], CryptoResult.by_value
    attach_function :cryptolib_stego_extract, [:string], CryptoBufferResult.by_value
    attach_function :cryptolib_fec_encode, [:pointer, :size_t, :int], CryptoBufferResult.by_value
    attach_function :cryptolib_fec_decode, [:pointer, :size_t, :int, :size_t], CryptoBufferResult.by_value
  end

  # ── Helpers ────────────────────────────────────────────────────────────────
  def self._read_buf(cb)
    return ''.b if cb[:data].null? || cb[:len].zero?
    cb[:data].read_bytes(cb[:len])
  end

  def self._consume(r)
    if (r[:buf][:data].null? || r[:buf][:len].zero?) && !r[:error].null?
      msg = r[:error].read_string_to_null
      Native.cryptolib_str_free(r[:error])
      raise msg
    end
    out = _read_buf(r[:buf])
    buf_ptr = FFI::MemoryPointer.new(Native::CryptoBuffer, 1)
    buf_ptr.write_bytes(r[:buf].to_ptr.read_bytes(Native::CryptoBuffer.size))
    Native.cryptolib_buffer_free(buf_ptr)
    out
  end

  def self._u8p(bytes)
    p = FFI::MemoryPointer.new(:uint8, bytes.bytesize)
    p.write_bytes(bytes)
    p
  end

  # ── Public API ─────────────────────────────────────────────────────────────
  def self.init
    raise 'cryptolib_init failed' unless Native.cryptolib_init.zero?
  end

  def self.version
    Native.cryptolib_version
  end

  def self.random_bytes(n)
    _consume(Native.cryptolib_random_bytes(n))
  end

  def self.sha256(msg)
    bytes = msg.b
    _consume(Native.cryptolib_sha256(_u8p(bytes), bytes.bytesize))
  end

  def self.hybrid_kem_keygen
    kp = Native.cryptolib_hybrid_kem_keygen
    pub = _read_buf(kp[:public_key]); sec = _read_buf(kp[:secret_key])
    kp_ptr = FFI::MemoryPointer.new(Native::CryptoKeyPair, 1)
    kp_ptr.write_bytes(kp.to_ptr.read_bytes(Native::CryptoKeyPair.size))
    Native.cryptolib_keypair_free(kp_ptr)
    [pub, sec]
  end

  def self.hybrid_kem_encapsulate(public_key)
    err = FFI::MemoryPointer.new(:pointer)
    p = _u8p(public_key)
    r = Native.cryptolib_hybrid_kem_encapsulate(p, public_key.bytesize, err)
    err_ptr = err.read_pointer
    unless err_ptr.null?
      msg = err_ptr.read_string_to_null
      Native.cryptolib_str_free(err_ptr)
      raise msg
    end
    ct = _read_buf(r[:ciphertext]); ss = _read_buf(r[:shared_secret])
    r_ptr = FFI::MemoryPointer.new(Native::CryptoKemEncapsResult, 1)
    r_ptr.write_bytes(r.to_ptr.read_bytes(Native::CryptoKemEncapsResult.size))
    Native.cryptolib_kem_encaps_free(r_ptr)
    [ct, ss]
  end

  def self.hybrid_kem_decapsulate(ct, sec)
    cp = _u8p(ct); sp = _u8p(sec)
    _consume(Native.cryptolib_hybrid_kem_decapsulate(cp, ct.bytesize, sp, sec.bytesize))
  end

  # ── Primitives used by Recipe ──────────────────────────────────────────────

  def self._keypair(kp)
    pub = _read_buf(kp[:public_key]); sec = _read_buf(kp[:secret_key])
    ptr = FFI::MemoryPointer.new(Native::CryptoKeyPair, 1)
    ptr.write_bytes(kp.to_ptr.read_bytes(Native::CryptoKeyPair.size))
    Native.cryptolib_keypair_free(ptr)
    [pub, sec]
  end

  # Stretch a passphrase into a key with Argon2id.
  def self.argon2id_derive(password, salt, key_len: 32, ops: 2, memory_bytes: 67_108_864)
    s = salt.b
    _consume(Native.cryptolib_argon2id_derive(password, _u8p(s), s.bytesize, key_len, ops, memory_bytes))
  end

  # One-shot HKDF: extract + expand to +out_len+ bytes.
  def self.hkdf_derive(ikm, salt: ''.b, info: ''.b, out_len: 32)
    i = ikm.b; s = salt.b; f = info.b
    _consume(Native.cryptolib_hkdf_derive(_u8p(i), i.bytesize, _u8p(s), s.bytesize,
                                          _u8p(f), f.bytesize, out_len))
  end

  def self._aead(fn, data, key, aad)
    d = data.b; k = key.b; a = aad.b
    _consume(Native.send(fn, _u8p(d), d.bytesize, _u8p(k), k.bytesize, _u8p(a), a.bytesize))
  end

  def self.xchacha20_encrypt(pt, key, aad = ''.b) = _aead(:cryptolib_xchacha20_encrypt, pt, key, aad)
  def self.xchacha20_decrypt(ct, key, aad = ''.b) = _aead(:cryptolib_xchacha20_decrypt, ct, key, aad)
  def self.aes256gcm_encrypt(pt, key, aad = ''.b) = _aead(:cryptolib_aes256gcm_encrypt, pt, key, aad)
  def self.aes256gcm_decrypt(ct, key, aad = ''.b) = _aead(:cryptolib_aes256gcm_decrypt, ct, key, aad)
  def self.committing_encrypt(pt, key, aad = ''.b) = _aead(:cryptolib_committing_encrypt, pt, key, aad)
  def self.committing_decrypt(ct, key, aad = ''.b) = _aead(:cryptolib_committing_decrypt, ct, key, aad)
  def self.molecular_seal_with_key(pt, key, aad = ''.b) = _aead(:cryptolib_molecular_seal_with_key, pt, key, aad)
  def self.molecular_open_with_key(ct, key, aad = ''.b) = _aead(:cryptolib_molecular_open_with_key, ct, key, aad)

  # Ed25519 keypair from the OS CSPRNG => [public, secret].
  def self.ed25519_keygen = _keypair(Native.cryptolib_ed25519_keygen)

  # Ed25519 keypair derived deterministically from a 32-byte seed.
  def self.ed25519_keygen_from_seed(seed)
    s = seed.b
    _keypair(Native.cryptolib_ed25519_keygen_from_seed(_u8p(s), s.bytesize))
  end

  # Ed25519 signature. +secret_key+ is the 64-byte secret, not the seed.
  def self.ed25519_sign(msg, secret_key)
    m = msg.b; s = secret_key.b
    _consume(Native.cryptolib_ed25519_sign(_u8p(m), m.bytesize, _u8p(s), s.bytesize))
  end

  def self.ed25519_verify(msg, sig, public_key)
    m = msg.b; g = sig.b; p = public_key.b
    Native.cryptolib_ed25519_verify(_u8p(m), m.bytesize, _u8p(g), g.bytesize, _u8p(p), p.bytesize) == 1
  end

  # Ed25519 + ML-DSA-65 keypair: a forgery needs breaking both families.
  def self.hybrid_sig_keygen = _keypair(Native.cryptolib_hybrid_sig_keygen)

  def self.hybrid_sig_sign(msg, secret_key)
    m = msg.b; s = secret_key.b
    _consume(Native.cryptolib_hybrid_sig_sign(_u8p(m), m.bytesize, _u8p(s), s.bytesize))
  end

  def self.hybrid_sig_verify(msg, sig, public_key)
    m = msg.b; g = sig.b; p = public_key.b
    Native.cryptolib_hybrid_sig_verify(_u8p(m), m.bytesize, _u8p(g), g.bytesize, _u8p(p), p.bytesize) == 1
  end

  # Derive a 32-byte key deterministically from a media file — "the file is the
  # key". Reproducible on any machine; nothing is stored.
  #
  # Uses the deterministic entropy path deliberately: key_from_file mixes in
  # fresh system entropy and so could never reopen its own envelope.
  def self.key_from_file_deterministic(path)
    err = FFI::MemoryPointer.new(:pointer)
    h = Native.cryptolib_entropy_from_file_deterministic(path, err)
    e = err.read_pointer
    unless e.null?
      msg = e.read_string_to_null
      Native.cryptolib_str_free(e)
      raise msg
    end
    raise 'cryptolib: entropy handle allocation failed' if h.null?
    begin
      _consume(Native.cryptolib_entropy_symmetric_key(h))
    ensure
      Native.cryptolib_entropy_free(h)
    end
  end

  # Hide +payload+ inside a media carrier.
  def self.stego_embed(cover_path, payload, output_path)
    p = payload.b
    r = Native.cryptolib_stego_embed(cover_path, _u8p(p), p.bytesize, output_path)
    return if r[:ok] == 1
    msg = r[:error].null? ? 'stego embed failed' : r[:error].read_string_to_null
    Native.cryptolib_str_free(r[:error]) unless r[:error].null?
    raise msg
  end

  # Recover a payload hidden by stego_embed.
  def self.stego_extract(stego_path) = _consume(Native.cryptolib_stego_extract(stego_path))

  # Forward-error-correct +data+ under a FecScheme value.
  def self.fec_encode(data, scheme)
    d = data.b
    _consume(Native.cryptolib_fec_encode(_u8p(d), d.bytesize, scheme))
  end

  # Reverse fec_encode, recovering +original_length+ bytes.
  def self.fec_decode(data, scheme, original_length)
    d = data.b
    _consume(Native.cryptolib_fec_decode(_u8p(d), d.bytesize, scheme, original_length))
  end
end

require_relative 'cryptolib/security'
