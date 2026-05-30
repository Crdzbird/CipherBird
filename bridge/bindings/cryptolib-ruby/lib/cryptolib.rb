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
end
