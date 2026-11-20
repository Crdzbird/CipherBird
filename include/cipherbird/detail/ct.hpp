#pragma once
/**
 * Constant-time verification hooks. Under the Valgrind probe
 * (CIPHERBIRD_CT_VALGRIND) secrets are marked undefined so memcheck reports
 * every branch that depends on them. An authentication verdict and the
 * length it unlocks are public by construction, so the library declares
 * them defined right where they are decided; everything before that point
 * stays under observation. Outside the probe these calls compile to nothing.
 */
#include <cstddef>
#if defined(CIPHERBIRD_CT_VALGRIND) && defined(__has_include)
#  if __has_include(<valgrind/memcheck.h>)
#    include <valgrind/memcheck.h>
#    define CIPHERBIRD_CT_HAVE_MEMCHECK 1
#  endif
#endif

namespace crypto::detail {

/// Declare [n] bytes at [p] public: a verdict already decided in constant time.
inline void ct_declassify(const void* p, std::size_t n) noexcept {
#ifdef CIPHERBIRD_CT_HAVE_MEMCHECK
    VALGRIND_MAKE_MEM_DEFINED(p, n);
#else
    (void)p; (void)n;
#endif
}

}
