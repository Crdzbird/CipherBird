#pragma once

#include <sodium.h>

#include <climits>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace crypto {

// ─────────────────────────────────────────────────────────────────────────────
// SecureBuffer — memory-safe container for secrets.
// Zeroes memory on destruction via sodium_memzero (compiler-proof).
// Non-copyable: secrets must never be duplicated carelessly.
// ─────────────────────────────────────────────────────────────────────────────
/// Branchless nibble to hex so the conversion does no secret-dependent table
/// lookup (avoids a cache-timing side channel when hex-encoding secrets).
[[nodiscard]] inline std::string hex_encode(std::span<const uint8_t> bytes) {
    auto nib = [](int n) -> char {
        return static_cast<char>(n + '0' + (((9 - n) >> 31) & 0x27));
    };
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) { out += nib(b >> 4); out += nib(b & 0x0f); }
    return out;
}

/// A buffer whose contents are public by construction: digests of data the
/// caller already holds, ciphertexts, signatures, public keys, envelopes.
/// It lives in plain memory with no page lock and no wipe. Anything whose
/// value depends on a secret (keys, shared secrets, KDF and MAC outputs,
/// decrypted plaintext) uses SecureBuffer.
class PublicBuffer {
public:
    PublicBuffer() = default;
    explicit PublicBuffer(std::size_t n) : data_(n, 0) {}
    explicit PublicBuffer(std::vector<uint8_t> v) : data_(std::move(v)) {}
    PublicBuffer(const uint8_t* p, std::size_t n) : data_(p, p + n) {}

    [[nodiscard]] uint8_t*       data()        noexcept { return data_.data(); }
    [[nodiscard]] const uint8_t* data()  const noexcept { return data_.data(); }
    [[nodiscard]] std::size_t    size()  const noexcept { return data_.size(); }
    [[nodiscard]] bool           empty() const noexcept { return data_.empty(); }
    [[nodiscard]] std::span<uint8_t>       span()       noexcept { return data_; }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept { return data_; }
    [[nodiscard]] auto begin() const noexcept { return data_.begin(); }
    [[nodiscard]] auto end()   const noexcept { return data_.end(); }
    [[nodiscard]] const std::vector<uint8_t>& bytes() const noexcept { return data_; }
    [[nodiscard]] std::vector<uint8_t> release() noexcept { return std::move(data_); }
    void resize(std::size_t n) { data_.resize(n); }
    [[nodiscard]] std::string to_hex() const { return hex_encode(data_); }
    [[nodiscard]] std::string to_string() const {
        return { reinterpret_cast<const char*>(data_.data()), data_.size() };
    }
    [[nodiscard]] bool operator==(const PublicBuffer& o) const noexcept { return data_ == o.data_; }

private:
    std::vector<uint8_t> data_;
};

/// The public output of a hash.
using Digest = PublicBuffer;

namespace detail {
/// Whether a byte count can be handed to an API that takes a C int length.
[[nodiscard]] inline bool fits_int(std::size_t n) noexcept {
    return n <= static_cast<std::size_t>(INT_MAX);
}
} // namespace detail

class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t n) : data_(n, 0) { lock_mem(); }
    SecureBuffer(const uint8_t* p, std::size_t n) : data_(p, p + n) { lock_mem(); }
    explicit SecureBuffer(std::vector<uint8_t> v) : data_(std::move(v)) { lock_mem(); }

    ~SecureBuffer() { unlock_mem(); }  // sodium_munlock zeroes then unlocks

    SecureBuffer(const SecureBuffer&)            = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& o) noexcept
        : data_(std::move(o.data_)), locked_len_(o.locked_len_) {
        o.locked_len_ = 0;  // ownership of the locked pages transfers to *this
    }

    SecureBuffer& operator=(SecureBuffer&& o) noexcept {
        if (this != &o) {
            unlock_mem();  // wipe + unlock current contents before old alloc is freed
            data_ = std::move(o.data_);
            locked_len_ = o.locked_len_;
            o.locked_len_ = 0;
        }
        return *this;
    }

    [[nodiscard]] uint8_t*       data()        noexcept { return data_.data(); }
    [[nodiscard]] const uint8_t* data()  const noexcept { return data_.data(); }
    [[nodiscard]] std::size_t    size()  const noexcept { return data_.size(); }
    [[nodiscard]] bool           empty() const noexcept { return data_.empty(); }

    [[nodiscard]] std::span<uint8_t>       span()       noexcept { return data_; }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept { return data_; }

    void resize(std::size_t n) {
        if (n <= data_.size()) {
            // Shrinking: zero the bytes being dropped before they become inaccessible.
            // No reallocation, so the existing lock still covers the buffer.
            if (n < data_.size())
                sodium_memzero(data_.data() + n, data_.size() - n);
            data_.resize(n);
        } else if (n > data_.capacity()) {
            // Growing past capacity: reallocation would free old memory unzeroed.
            // Lock the new buffer, copy, then wipe+unlock the old before it frees.
            std::vector<uint8_t> new_buf(n, 0);
            sodium_mlock(new_buf.data(), new_buf.size());
            if (!data_.empty()) {
                std::memcpy(new_buf.data(), data_.data(), data_.size());
                unlock_mem();  // wipe + unlock old allocation
            }
            data_ = std::move(new_buf);
            locked_len_ = data_.size();
        } else {
            // Growing within existing capacity: no reallocation. Re-lock so the
            // grown region is covered and locked_len_ tracks the live size.
            data_.resize(n, 0);
            sodium_mlock(data_.data(), data_.size());
            locked_len_ = data_.size();
        }
    }

    void zeroize() noexcept {
        if (!data_.empty()) {
            sodium_memzero(data_.data(), data_.size());
        }
    }

#if defined(CRYPTOLIB_TESTING) || defined(CRYPTOLIB_ALLOW_SECRET_TEXT)
    /// Test builds and demos only: a secret rendered as text leaves an
    /// unwiped copy in a std::string, so production code has no such helper.
    [[nodiscard]] std::string to_hex() const { return hex_encode(data_); }

    [[nodiscard]] std::string to_string() const {
        return { reinterpret_cast<const char*>(data_.data()), data_.size() };
    }
#endif

private:
    // Best-effort page locking so secret bytes are not written to swap.
    // sodium_mlock also marks the region MADV_DONTDUMP. Failures (e.g.
    // RLIMIT_MEMLOCK) are tolerated: zeroization on destruction still happens
    // via sodium_munlock, which wipes before unlocking even if mlock never
    // succeeded. PERF: this adds a syscall per allocation — acceptable for a
    // secret container, but note SecureBuffer is also used for non-secret
    // outputs (e.g. hash digests) in this library.
    void lock_mem() noexcept {
        if (!data_.empty()) {
            sodium_mlock(data_.data(), data_.size());
            locked_len_ = data_.size();
        }
    }
    void unlock_mem() noexcept {
        if (!data_.empty())
            sodium_munlock(data_.data(),
                           locked_len_ ? locked_len_ : data_.size());
        locked_len_ = 0;
    }

    std::vector<uint8_t> data_;
    std::size_t          locked_len_ = 0;  // bytes passed to sodium_mlock
};

// ─────────────────────────────────────────────────────────────────────────────
// Result<T> — all crypto operations return this; failures are never silent.
// ─────────────────────────────────────────────────────────────────────────────
struct CryptoError { std::string message; };

template<typename T>
class Result {
public:
    static Result ok(T v)            { Result r; r.val_ = std::move(v); return r; }
    static Result err(std::string m) { Result r; r.err_ = CryptoError{std::move(m)}; return r; }

    [[nodiscard]] bool is_ok()  const noexcept { return  val_.has_value(); }
    [[nodiscard]] bool is_err() const noexcept { return  err_.has_value(); }

    [[nodiscard]] T& value() {
        if (is_err()) throw std::runtime_error(err_->message);
        return *val_;
    }
    [[nodiscard]] const T& value() const {
        if (is_err()) throw std::runtime_error(err_->message);
        return *val_;
    }
    [[nodiscard]] const CryptoError& error() const {
        if (!err_.has_value())
            throw std::logic_error("Result::error() called on ok result");
        return *err_;
    }

    [[nodiscard]] T value_or(T default_val) const {
        return is_ok() ? *val_ : std::move(default_val);
    }

private:
    std::optional<T>           val_;
    std::optional<CryptoError> err_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Result<void> specialisation — for operations that return success/failure only.
// Usage: return Result<void>::ok();  or  return Result<void>::err("msg");
// ─────────────────────────────────────────────────────────────────────────────
template<>
class Result<void> {
public:
    static Result ok()             { Result r; r.ok_ = true; return r; }
    static Result err(std::string m) { Result r; r.ok_ = false; r.err_ = CryptoError{std::move(m)}; return r; }

    [[nodiscard]] bool is_ok()  const noexcept { return  ok_; }
    [[nodiscard]] bool is_err() const noexcept { return !ok_; }

    [[nodiscard]] const CryptoError& error() const {
        if (!err_.has_value())
            throw std::logic_error("Result<void>::error() called on ok result");
        return *err_;
    }

private:
    bool                       ok_ = false;
    std::optional<CryptoError> err_;
};

using Bytes = std::vector<uint8_t>;

} // namespace crypto
