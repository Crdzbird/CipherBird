cmake_minimum_required(VERSION 4.1)
project(cipherbird VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Cross-compile detection ────────────────────────────────────────────────
# When building for iOS (or any cross-compile target), we expect the caller to
# pass -DCIPHERBIRD_DEPS_ROOT=<path> pointing at a third_party/<slice>/ directory
# containing include/ and lib/ with all deps pre-built as static archives.
# Otherwise we fall back to Homebrew / pkg-config discovery for native macOS.

option(CIPHERBIRD_STATIC "Build cipherbird_c as a STATIC archive (for XCFramework)" OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(CIPHERBIRD_STATIC ON CACHE BOOL "Force STATIC on iOS" FORCE)
endif()

# ─── Dependency discovery (two modes) ───────────────────────────────────────
if(DEFINED CIPHERBIRD_DEPS_ROOT)
    message(STATUS "cipherbird: using pre-built deps at ${CIPHERBIRD_DEPS_ROOT}")

    set(SODIUM_INCLUDE_DIRS "${CIPHERBIRD_DEPS_ROOT}/include")
    set(SODIUM_LIBRARIES    "${CIPHERBIRD_DEPS_ROOT}/lib/libsodium.a")
    set(SODIUM_LIBRARY_DIRS "${CIPHERBIRD_DEPS_ROOT}/lib")

    set(BLAKE3_INCLUDE_DIRS "${CIPHERBIRD_DEPS_ROOT}/include")
    set(BLAKE3_LIBRARIES    "${CIPHERBIRD_DEPS_ROOT}/lib/libblake3.a")
    set(BLAKE3_LIBRARY_DIRS "${CIPHERBIRD_DEPS_ROOT}/lib")

    set(OQS_INCLUDE_DIR     "${CIPHERBIRD_DEPS_ROOT}/include")
    set(OQS_LIBRARY         "${CIPHERBIRD_DEPS_ROOT}/lib/liboqs.a")
    set(OPENSSL_INCLUDE_DIRS "${CIPHERBIRD_DEPS_ROOT}/include")
    set(OPENSSL_LIBRARIES   "${CIPHERBIRD_DEPS_ROOT}/lib/libcrypto.a")
    set(OPENSSL_LIBRARY_DIRS "${CIPHERBIRD_DEPS_ROOT}/lib")

    set(BLST_INCLUDE_DIR    "${CIPHERBIRD_DEPS_ROOT}/include")
    set(BLST_LIBRARY        "${CIPHERBIRD_DEPS_ROOT}/lib/libblst.a")

    set(SECP256K1_INCLUDE_DIR "${CIPHERBIRD_DEPS_ROOT}/include")
    set(SECP256K1_LIBRARY     "${CIPHERBIRD_DEPS_ROOT}/lib/libsecp256k1.a")

    set(CIPHERBIRD_DEPS_PREBUILT ON)
else()
    # Native macOS path: Homebrew + pkg-config discovery (version-agnostic).
    # pkg-config tells us the current Cellar path regardless of point-release
    # bumps (e.g. libsodium 1.0.21 -> 1.0.22), so we don't hard-code versions.
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.21)

    set(CIPHERBIRD_DEPS_PREBUILT OFF)
endif()

# ─── Optional dependencies (ON by default) ──────────────────────────────────
# Build profile. "full" is everything. "bank" (assessment r2, M8 and M4) drops
# the untrusted-media parsers (steganography, media entropy) and the
# library-native combiners (MolecularVault, the triple hybrids, sntrup, the
# X25519+ML-KEM combiner, Flagship, the legacy Suite and Session) and makes
# the standards-track X-Wing and HPKE with ML-KEM the defaults. "fips" (C3)
# keeps only operations the OpenSSL FIPS Provider performs in approved mode:
# every libsodium-backed primitive is compiled out and libsodium remains
# linked only for sodium_mlock and sodium_memzero.
set(CIPHERBIRD_PROFILE "full" CACHE STRING "Build profile: full, bank or fips")
set_property(CACHE CIPHERBIRD_PROFILE PROPERTY STRINGS full bank fips)
if(NOT CIPHERBIRD_PROFILE MATCHES "^(full|bank|fips)$")
    message(FATAL_ERROR "CIPHERBIRD_PROFILE must be full, bank or fips (got ${CIPHERBIRD_PROFILE})")
endif()
message(STATUS "cipherbird: build profile ${CIPHERBIRD_PROFILE}")

option(CIPHERBIRD_BLAKE3 "Enable BLAKE3 hash (requires libblake3)" ON)
option(CIPHERBIRD_PQ     "Enable post-quantum algorithms (requires liboqs)" ON)
option(CIPHERBIRD_PQ_BACKEND_OPENSSL "Back ML-KEM/ML-DSA/SLH-DSA with OpenSSL EVP (FIPS-track) instead of liboqs; liboqs retained for other algorithms. Byte-compatible encodings." OFF)
option(CIPHERBIRD_BLS    "Enable BLS12-381 aggregate signatures (requires blst)" ON)
option(CIPHERBIRD_SECP256K1 "Enable secp256k1 ECDSA for EVM/BTC interop (requires libsecp256k1 w/ recovery module)" ON)

if(CIPHERBIRD_PROFILE STREQUAL "fips")
    # Nothing outside the validated provider: no liboqs, blst, secp256k1 or BLAKE3.
    set(CIPHERBIRD_PQ OFF CACHE BOOL "" FORCE)
    set(CIPHERBIRD_BLS OFF CACHE BOOL "" FORCE)
    set(CIPHERBIRD_SECP256K1 OFF CACHE BOOL "" FORCE)
    set(CIPHERBIRD_BLAKE3 OFF CACHE BOOL "" FORCE)
endif()
if(CIPHERBIRD_PROFILE STREQUAL "bank" AND NOT CIPHERBIRD_PQ)
    message(FATAL_ERROR "The bank profile needs CIPHERBIRD_PQ=ON (X-Wing and HPKE with ML-KEM)")
endif()

if(CIPHERBIRD_BLAKE3 AND NOT CIPHERBIRD_DEPS_PREBUILT)
    pkg_check_modules(BLAKE3 REQUIRED libblake3)
endif()

if(CIPHERBIRD_PQ AND NOT CIPHERBIRD_DEPS_PREBUILT)
    pkg_check_modules(OQS_PC liboqs)
    if(OQS_PC_FOUND)
        set(OQS_INCLUDE_DIR "${OQS_PC_INCLUDE_DIRS}")
        set(OQS_LIBRARY    "${OQS_PC_LINK_LIBRARIES}")
    else()
        # Fall back to generic search (Homebrew /opt/homebrew/lib etc.)
        find_library(OQS_LIBRARY oqs PATHS /opt/homebrew/lib /usr/local/lib REQUIRED)
        find_path(OQS_INCLUDE_DIR oqs/oqs.h PATHS /opt/homebrew/include /usr/local/include REQUIRED)
    endif()
    # We use OpenSSL's libcrypto only (EVP: AES-256-GCM-SIV, ML-KEM/ML-DSA/SLH-DSA).
    # We never use libssl (TLS/X.509) — linking it would pull an entire network
    # protocol stack as pure attack surface, so we depend on libcrypto alone.
    pkg_check_modules(OPENSSL REQUIRED libcrypto)
endif()
if(CIPHERBIRD_PROFILE STREQUAL "fips" AND NOT CIPHERBIRD_DEPS_PREBUILT)
    # The provider-backed layer talks to libcrypto 3.x only; the validated
    # fips module is loaded at run time from CIPHERBIRD_FIPS_MODULE_DIR.
    pkg_check_modules(OPENSSL REQUIRED libcrypto>=3.0)
endif()

if(CIPHERBIRD_BLS AND NOT CIPHERBIRD_DEPS_PREBUILT)
    find_library(BLST_LIBRARY blst PATHS /opt/homebrew/lib /usr/local/lib REQUIRED)
    find_path(BLST_INCLUDE_DIR blst/blst.h PATHS /opt/homebrew/include /usr/local/include REQUIRED)
endif()

if(CIPHERBIRD_SECP256K1 AND NOT CIPHERBIRD_DEPS_PREBUILT)
    pkg_check_modules(SECP256K1_PC libsecp256k1)
    if(SECP256K1_PC_FOUND)
        set(SECP256K1_INCLUDE_DIR "${SECP256K1_PC_INCLUDE_DIRS}")
        set(SECP256K1_LIBRARY    "${SECP256K1_PC_LINK_LIBRARIES}")
    else()
        find_library(SECP256K1_LIBRARY secp256k1 PATHS /opt/homebrew/lib /usr/local/lib REQUIRED)
        find_path(SECP256K1_INCLUDE_DIR secp256k1_recovery.h PATHS /opt/homebrew/include /usr/local/include REQUIRED)
    endif()
endif()

# ─── Header-only interface library ───────────────────────────────────────────
add_library(cipherbird INTERFACE)
add_library(crypto::cipherbird ALIAS cipherbird)

target_include_directories(cipherbird INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(cipherbird INTERFACE ${SODIUM_LIBRARIES})
if(NOT CIPHERBIRD_DEPS_PREBUILT AND SODIUM_LIBRARY_DIRS)
    target_link_directories(cipherbird INTERFACE ${SODIUM_LIBRARY_DIRS})
endif()

if(CIPHERBIRD_BLAKE3)
    target_compile_definitions(cipherbird INTERFACE CIPHERBIRD_HAS_BLAKE3=1)
    target_include_directories(cipherbird INTERFACE ${BLAKE3_INCLUDE_DIRS})
    target_link_libraries(cipherbird INTERFACE ${BLAKE3_LIBRARIES})
    if(NOT CIPHERBIRD_DEPS_PREBUILT)
        target_link_directories(cipherbird INTERFACE ${BLAKE3_LIBRARY_DIRS})
    endif()
endif()

if(CIPHERBIRD_PQ)
    target_compile_definitions(cipherbird INTERFACE CIPHERBIRD_HAS_PQ=1 CIPHERBIRD_HAS_OPENSSL=1)
    target_include_directories(cipherbird INTERFACE ${OQS_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIRS})
    target_link_libraries(cipherbird INTERFACE ${OQS_LIBRARY} ${OPENSSL_LIBRARIES})
    if(NOT CIPHERBIRD_DEPS_PREBUILT)
        target_link_directories(cipherbird INTERFACE ${OPENSSL_LIBRARY_DIRS})
    endif()
    if(CIPHERBIRD_PQ_BACKEND_OPENSSL)
        target_compile_definitions(cipherbird INTERFACE CIPHERBIRD_PQ_BACKEND_OPENSSL=1)
        message(STATUS "PQC backend: OpenSSL EVP (liboqs retained for non-standardized algorithms)")
    else()
        message(STATUS "PQC backend: liboqs (default)")
    endif()
endif()

# The same profile definitions reach the header-only target and the C bridge.
if(CIPHERBIRD_PROFILE STREQUAL "full")
    set(_CIPHERBIRD_PROFILE_DEFS CIPHERBIRD_HAS_SODIUM_CRYPTO=1
        CIPHERBIRD_HAS_STEGO=1 CIPHERBIRD_HAS_MEDIA_ENTROPY=1 CIPHERBIRD_HAS_NATIVE_COMBINERS=1)
elseif(CIPHERBIRD_PROFILE STREQUAL "bank")
    set(_CIPHERBIRD_PROFILE_DEFS CIPHERBIRD_HAS_SODIUM_CRYPTO=1 CIPHERBIRD_PROFILE_BANK=1)
else()
    set(_CIPHERBIRD_PROFILE_DEFS CIPHERBIRD_PROFILE_FIPS=1 CIPHERBIRD_HAS_FIPS_PROVIDER=1 CIPHERBIRD_HAS_OPENSSL=1)
endif()
target_compile_definitions(cipherbird INTERFACE ${_CIPHERBIRD_PROFILE_DEFS})

option(CIPHERBIRD_PASETO_TEST_NONCE "Test builds only: export the deterministic-nonce PASETO v4.local encrypt" OFF)
if(CIPHERBIRD_PASETO_TEST_NONCE AND NOT CIPHERBIRD_PROFILE STREQUAL "full")
    message(FATAL_ERROR "CIPHERBIRD_PASETO_TEST_NONCE is a test option and is refused in the ${CIPHERBIRD_PROFILE} profile")
endif()
if(CIPHERBIRD_PASETO_TEST_NONCE)
    message(WARNING "cipherbird: CIPHERBIRD_PASETO_TEST_NONCE is ON; this build exports a deterministic-nonce encrypt and must not ship")
    list(APPEND _CIPHERBIRD_PROFILE_DEFS CIPHERBIRD_PASETO_TEST_NONCE=1)
    target_compile_definitions(cipherbird INTERFACE CIPHERBIRD_PASETO_TEST_NONCE=1)
endif()
if(CIPHERBIRD_PROFILE STREQUAL "fips")
    target_include_directories(cipherbird INTERFACE ${OPENSSL_INCLUDE_DIRS})
    target_link_libraries(cipherbird INTERFACE ${OPENSSL_LIBRARIES})
    if(NOT CIPHERBIRD_DEPS_PREBUILT)
        target_link_directories(cipherbird INTERFACE ${OPENSSL_LIBRARY_DIRS})
    endif()
endif()

if(CIPHERBIRD_BLS)
    target_compile_definitions(cipherbird INTERFACE CIPHERBIRD_HAS_BLS=1)
    target_include_directories(cipherbird INTERFACE ${BLST_INCLUDE_DIR})
    target_link_libraries(cipherbird INTERFACE ${BLST_LIBRARY})
endif()

if(CIPHERBIRD_SECP256K1)
    target_compile_definitions(cipherbird INTERFACE CIPHERBIRD_HAS_SECP256K1=1)
    target_include_directories(cipherbird INTERFACE ${SECP256K1_INCLUDE_DIR})
    target_link_libraries(cipherbird INTERFACE ${SECP256K1_LIBRARY})
    if(NOT CIPHERBIRD_DEPS_PREBUILT AND SECP256K1_PC_LIBRARY_DIRS)
        target_link_directories(cipherbird INTERFACE ${SECP256K1_PC_LIBRARY_DIRS})
    endif()
endif()

# ─── Gate examples + tests: skip when cross-compiling or building static ─────
set(_CIPHERBIRD_HOST_BUILD ON)
if(CMAKE_CROSSCOMPILING OR CIPHERBIRD_STATIC)
    set(_CIPHERBIRD_HOST_BUILD OFF)
endif()

# ─── Sanitizers (ASan + UBSan) — opt-in for tests/fuzzers ────────────────────
# Crypto code parses untrusted input (stego format parsers); sanitizers are the
# primary line of defence against the memory-safety bugs that unit tests miss.
option(CIPHERBIRD_SANITIZE "Build tests/examples with AddressSanitizer + UBSan" OFF)
option(CIPHERBIRD_TSAN "Build tests with ThreadSanitizer (mutually exclusive with ASan)" OFF)
set(CIPHERBIRD_SANITIZE_FLAGS "")
if(CIPHERBIRD_SANITIZE AND CIPHERBIRD_TSAN)
    message(FATAL_ERROR "CIPHERBIRD_SANITIZE (ASan) and CIPHERBIRD_TSAN are mutually exclusive.")
endif()
if(CIPHERBIRD_SANITIZE)
    set(CIPHERBIRD_SANITIZE_FLAGS
        -fsanitize=address,undefined
        -fno-sanitize-recover=all
        -fno-omit-frame-pointer
        -g)
    message(STATUS "cipherbird: AddressSanitizer + UBSan ENABLED for host targets")
elseif(CIPHERBIRD_TSAN)
    set(CIPHERBIRD_SANITIZE_FLAGS -fsanitize=thread -fno-omit-frame-pointer -g)
    message(STATUS "cipherbird: ThreadSanitizer ENABLED for host targets")
endif()

# ─── Proof-of-concept ─────────────────────────────────────────────────────────
option(CIPHERBIRD_BUILD_EXAMPLE "Build PoC example" ${_CIPHERBIRD_HOST_BUILD})
if(CIPHERBIRD_BUILD_EXAMPLE AND NOT CIPHERBIRD_PROFILE STREQUAL "full")
    message(STATUS "cipherbird: examples are built in the full profile only")
    set(CIPHERBIRD_BUILD_EXAMPLE OFF)
endif()
# Profile showcases: the bank walk-through builds in the full and bank
# profiles, the fips walk-through only in the fips profile.
option(CIPHERBIRD_BUILD_SHOWCASES "Build the per-profile showcase programs" ${_CIPHERBIRD_HOST_BUILD})
if(CIPHERBIRD_BUILD_SHOWCASES AND CIPHERBIRD_PROFILE MATCHES "^(full|bank)$")
    add_executable(cipherbird_showcase_bank example/showcase_bank.cpp)
    target_compile_options(cipherbird_showcase_bank PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cipherbird_showcase_bank PRIVATE crypto::cipherbird)
endif()
if(CIPHERBIRD_BUILD_SHOWCASES AND CIPHERBIRD_PROFILE STREQUAL "fips")
    add_executable(cipherbird_showcase_fips example/showcase_fips.cpp)
    target_compile_options(cipherbird_showcase_fips PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cipherbird_showcase_fips PRIVATE crypto::cipherbird)
endif()
if(CIPHERBIRD_BUILD_EXAMPLE)
    # The demos print keys on purpose; production code has no such helpers.
    add_compile_definitions(CIPHERBIRD_ALLOW_SECRET_TEXT=1)
    add_executable(cipherbird_poc example/main.cpp)
    target_compile_options(cipherbird_poc PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cipherbird_poc PRIVATE crypto::cipherbird)

    add_executable(cipherbird_usage example/usage.cpp)
    target_compile_options(cipherbird_usage PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cipherbird_usage PRIVATE crypto::cipherbird)

    add_executable(cipherbird_demo example/demo.cpp)
    target_compile_options(cipherbird_demo PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cipherbird_demo PRIVATE crypto::cipherbird)

    add_executable(cipherbird_showcase example/showcase.cpp)
    target_compile_options(cipherbird_showcase PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_compile_definitions(cipherbird_showcase PRIVATE
        CIPHERBIRD_PROJECT_DIR="${CMAKE_SOURCE_DIR}")
    target_link_libraries(cipherbird_showcase PRIVATE crypto::cipherbird)

    add_executable(cipherbird_recipes example/recipes.cpp)
    target_compile_options(cipherbird_recipes PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cipherbird_recipes PRIVATE crypto::cipherbird)

    add_executable(cipherbird_stego_advanced example/stego_advanced.cpp)
    target_compile_options(cipherbird_stego_advanced PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cipherbird_stego_advanced PRIVATE crypto::cipherbird)
endif()

# ─── Tests ───────────────────────────────────────────────────────────────────
option(CIPHERBIRD_BUILD_TESTS "Build test suite" ${_CIPHERBIRD_HOST_BUILD})
if(CIPHERBIRD_BUILD_TESTS)
    file(GLOB TEST_SOURCES tests/test_*.cpp)
    set(_STEGO_TESTS stego_image stego_audio stego_video stego_engine stego_keyed stego_keyed_formats
        stego_fec stego_analysis stego_encrypted stego_fuzz physical_seal oprf_image_seal hpke_stego_seal
        vault_stego entropy_stego asym_stego)
    set(_MEDIA_TESTS media_entropy entropy_health entropy_live)
    set(_COMBINER_TESTS molecular_vault triple_hybrid_kem triple_sig sntrup_x25519 suite flagship hybrid session cb1_token)
    set(_EXCLUDED_TESTS "")
    if(NOT CIPHERBIRD_PROFILE STREQUAL "full")
        list(APPEND _EXCLUDED_TESTS ${_STEGO_TESTS} ${_MEDIA_TESTS} ${_COMBINER_TESTS})
    endif()
    if(CIPHERBIRD_PROFILE STREQUAL "fips")
        file(GLOB _SODIUM_TESTS tests/test_*.cpp)
        foreach(_src ${_SODIUM_TESTS})
            get_filename_component(_n ${_src} NAME_WE)
            string(REGEX REPLACE "^test_" "" _n ${_n})
            if(NOT _n MATCHES "^(main|types|c_abi_init|fips.*)$")
                list(APPEND _EXCLUDED_TESTS ${_n})
            endif()
        endforeach()
    endif()
    foreach(_n ${_EXCLUDED_TESTS})
        list(REMOVE_ITEM TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_${_n}.cpp)
    endforeach()
    # The C ABI translation unit is compiled into the test binary with the
    # testing hook enabled so its failure paths can be exercised.
    add_executable(cipherbird_tests ${TEST_SOURCES} bridge/cipherbird_c.cpp)
    target_compile_definitions(cipherbird_tests PRIVATE CIPHERBIRD_TESTING=1
        CIPHERBIRD_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    target_include_directories(cipherbird_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/bridge)
    target_compile_options(cipherbird_tests PRIVATE -Wall -Wextra -Wno-unused-parameter -O2
        ${CIPHERBIRD_SANITIZE_FLAGS})
    target_link_options(cipherbird_tests PRIVATE ${CIPHERBIRD_SANITIZE_FLAGS})
    target_link_libraries(cipherbird_tests PRIVATE crypto::cipherbird)
endif()

# The seed corpus generator for fuzz_stego (any compiler, full profile).
if(CIPHERBIRD_BUILD_TESTS AND CIPHERBIRD_PROFILE STREQUAL "full")
    add_executable(fuzz_corpus_gen tests/fuzz/make_corpus.cpp)
    target_compile_options(fuzz_corpus_gen PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(fuzz_corpus_gen PRIVATE crypto::cipherbird)
endif()

# ─── Fuzzers (libFuzzer, clang only) ─────────────────────────────────────────
# The stego parsers consume untrusted files; libFuzzer + ASan/UBSan is the
# primary tool for finding the memory-safety bugs unit tests miss.
#   cmake -B build-fuzz -DCIPHERBIRD_FUZZ=ON && cmake --build build-fuzz
#   ./build-fuzz/fuzz_stego -max_total_time=120
#
# NOTE: Apple's Xcode Clang does NOT ship the libFuzzer runtime
# (libclang_rt.fuzzer_osx.a). On macOS, build with LLVM clang, e.g.:
#   brew install llvm
#   cmake -B build-fuzz -DCIPHERBIRD_FUZZ=ON \
#         -DCMAKE_CXX_COMPILER=$(brew --prefix llvm)/bin/clang++
# Linux clang ships libFuzzer out of the box.
option(CIPHERBIRD_FUZZ "Build libFuzzer targets (LLVM clang only)" OFF)
if(CIPHERBIRD_FUZZ AND _CIPHERBIRD_HOST_BUILD)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "CIPHERBIRD_FUZZ requires Clang (libFuzzer).")
    endif()
    message(STATUS "cipherbird: building libFuzzer targets (needs LLVM clang runtime)")
    foreach(_fz fuzz_packet fuzz_stego fuzz_diff_aead fuzz_paseto_v4 fuzz_cb1)
        add_executable(${_fz} tests/fuzz/${_fz}.cpp)
        target_compile_options(${_fz} PRIVATE
            -g -O1 -fsanitize=fuzzer,address,undefined)
        target_compile_definitions(${_fz} PRIVATE CIPHERBIRD_FUZZING=1)
        target_link_options(${_fz} PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_libraries(${_fz} PRIVATE crypto::cipherbird)
    endforeach()
endif()

# ─── Constant-time verification probe (run under Valgrind/ctgrind) ──────────
option(CIPHERBIRD_CT_VALGRIND "Build the constant-time probe (run under Valgrind)" OFF)
if(CIPHERBIRD_CT_VALGRIND AND _CIPHERBIRD_HOST_BUILD)
    add_executable(ct_probe tests/ct/ct_probe.cpp)
    target_compile_options(ct_probe PRIVATE -g -O1)
    target_compile_definitions(ct_probe PRIVATE CIPHERBIRD_CT_VALGRIND=1)
    target_link_libraries(ct_probe PRIVATE crypto::cipherbird)
endif()

# ─── C FFI bridge: SHARED on host, STATIC for iOS/XCFramework ───────────────
option(CIPHERBIRD_BUILD_BRIDGE "Build C FFI library" ON)
if(CIPHERBIRD_BUILD_BRIDGE)
    if(CIPHERBIRD_STATIC)
        add_library(cipherbird_c STATIC bridge/cipherbird_c.cpp)
    else()
        add_library(cipherbird_c SHARED bridge/cipherbird_c.cpp)
    endif()

    target_include_directories(cipherbird_c PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${SODIUM_INCLUDE_DIRS}
    )
    target_link_libraries(cipherbird_c PRIVATE ${SODIUM_LIBRARIES})
    if(NOT CIPHERBIRD_DEPS_PREBUILT AND SODIUM_LIBRARY_DIRS)
        target_link_directories(cipherbird_c PRIVATE ${SODIUM_LIBRARY_DIRS})
    endif()
    target_compile_definitions(cipherbird_c PRIVATE CIPHERBIRD_BUILD_SHARED ${_CIPHERBIRD_PROFILE_DEFS})
    if(CIPHERBIRD_PROFILE STREQUAL "fips")
        target_include_directories(cipherbird_c PRIVATE ${OPENSSL_INCLUDE_DIRS})
        target_link_libraries(cipherbird_c PRIVATE ${OPENSSL_LIBRARIES})
        if(NOT CIPHERBIRD_DEPS_PREBUILT)
            target_link_directories(cipherbird_c PRIVATE ${OPENSSL_LIBRARY_DIRS})
        endif()
    endif()
    target_compile_options(cipherbird_c PRIVATE -Wall -Wextra -O2)

    set_target_properties(cipherbird_c PROPERTIES
        OUTPUT_NAME cipherbird_c
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )

    # Shared-lib-only properties — meaningless for static archives
    if(NOT CIPHERBIRD_STATIC)
        set_target_properties(cipherbird_c PROPERTIES
            VERSION ${PROJECT_VERSION}
            SOVERSION 3
            MACOSX_RPATH ON
        )
    endif()

    if(CIPHERBIRD_BLAKE3)
        target_compile_definitions(cipherbird_c PRIVATE CIPHERBIRD_HAS_BLAKE3=1)
        target_include_directories(cipherbird_c PRIVATE ${BLAKE3_INCLUDE_DIRS})
        target_link_libraries(cipherbird_c PRIVATE ${BLAKE3_LIBRARIES})
        if(NOT CIPHERBIRD_DEPS_PREBUILT)
            target_link_directories(cipherbird_c PRIVATE ${BLAKE3_LIBRARY_DIRS})
        endif()
    endif()
    if(CIPHERBIRD_PQ)
        # OpenSSL comes in with the PQ stack (liboqs depends on it); expose it to
        # the bridge so AES-256-GCM-SIV and MolecularVault are available too.
        target_compile_definitions(cipherbird_c PRIVATE CIPHERBIRD_HAS_PQ=1 CIPHERBIRD_HAS_OPENSSL=1)
        target_include_directories(cipherbird_c PRIVATE ${OQS_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIRS})
        target_link_libraries(cipherbird_c PRIVATE ${OQS_LIBRARY} ${OPENSSL_LIBRARIES})
        if(NOT CIPHERBIRD_DEPS_PREBUILT)
            target_link_directories(cipherbird_c PRIVATE ${OPENSSL_LIBRARY_DIRS})
        endif()
    endif()
    if(CIPHERBIRD_BLS)
        target_compile_definitions(cipherbird_c PRIVATE CIPHERBIRD_HAS_BLS=1)
        target_include_directories(cipherbird_c PRIVATE ${BLST_INCLUDE_DIR})
        target_link_libraries(cipherbird_c PRIVATE ${BLST_LIBRARY})
    endif()
    if(CIPHERBIRD_SECP256K1)
        target_compile_definitions(cipherbird_c PRIVATE CIPHERBIRD_HAS_SECP256K1=1)
        target_include_directories(cipherbird_c PRIVATE ${SECP256K1_INCLUDE_DIR})
        target_link_libraries(cipherbird_c PRIVATE ${SECP256K1_LIBRARY})
        if(NOT CIPHERBIRD_DEPS_PREBUILT AND SECP256K1_PC_LIBRARY_DIRS)
            target_link_directories(cipherbird_c PRIVATE ${SECP256K1_PC_LIBRARY_DIRS})
        endif()
    endif()

    # ── Security hardening for the shipped library ──────────────────────────
    # Exploit-mitigation compile flags, feature-detected so unsupported ones on a
    # given compiler/arch are skipped rather than failing the build.
    include(CheckCXXCompilerFlag)
    set(_cl_harden)
    foreach(_flag -fstack-protector-strong -fstack-clash-protection -fcf-protection=full)
        string(MAKE_C_IDENTIFIER "HAVE_CL${_flag}" _var)
        check_cxx_compiler_flag("${_flag}" ${_var})
        if(${${_var}})
            list(APPEND _cl_harden ${_flag})
        endif()
    endforeach()
    target_compile_options(cipherbird_c PRIVATE ${_cl_harden})
    # FORTIFY needs an optimized build (we ship -O2); re-arm cleanly.
    target_compile_options(cipherbird_c PRIVATE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)

    if(NOT CIPHERBIRD_STATIC)  # link-hardening applies to the shared object
        if(APPLE)
            # Export ONLY the cipherbird_* C ABI; hide all statically-linked
            # dependency symbols (liboqs/blst/…) → minimal surface.
            target_link_options(cipherbird_c PRIVATE
                "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/bridge/exported_symbols.txt")
        else()
            # ELF: full RELRO, non-exec stack, and restrict exports to the C ABI.
            target_link_options(cipherbird_c PRIVATE
                -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
                "-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/bridge/version_script.map")
        endif()
    endif()
endif()

include(GNUInstallDirs)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
