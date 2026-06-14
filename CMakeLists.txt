cmake_minimum_required(VERSION 4.1)
project(cryptolib VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Cross-compile detection ────────────────────────────────────────────────
# When building for iOS (or any cross-compile target), we expect the caller to
# pass -DCRYPTOLIB_DEPS_ROOT=<path> pointing at a third_party/<slice>/ directory
# containing include/ and lib/ with all deps pre-built as static archives.
# Otherwise we fall back to Homebrew / pkg-config discovery for native macOS.

option(CRYPTOLIB_STATIC "Build cryptolib_c as a STATIC archive (for XCFramework)" OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(CRYPTOLIB_STATIC ON CACHE BOOL "Force STATIC on iOS" FORCE)
endif()

# ─── Dependency discovery (two modes) ───────────────────────────────────────
if(DEFINED CRYPTOLIB_DEPS_ROOT)
    message(STATUS "cryptolib: using pre-built deps at ${CRYPTOLIB_DEPS_ROOT}")

    set(SODIUM_INCLUDE_DIRS "${CRYPTOLIB_DEPS_ROOT}/include")
    set(SODIUM_LIBRARIES    "${CRYPTOLIB_DEPS_ROOT}/lib/libsodium.a")
    set(SODIUM_LIBRARY_DIRS "${CRYPTOLIB_DEPS_ROOT}/lib")

    set(BLAKE3_INCLUDE_DIRS "${CRYPTOLIB_DEPS_ROOT}/include")
    set(BLAKE3_LIBRARIES    "${CRYPTOLIB_DEPS_ROOT}/lib/libblake3.a")
    set(BLAKE3_LIBRARY_DIRS "${CRYPTOLIB_DEPS_ROOT}/lib")

    set(OQS_INCLUDE_DIR     "${CRYPTOLIB_DEPS_ROOT}/include")
    set(OQS_LIBRARY         "${CRYPTOLIB_DEPS_ROOT}/lib/liboqs.a")
    set(OPENSSL_INCLUDE_DIRS "${CRYPTOLIB_DEPS_ROOT}/include")
    set(OPENSSL_LIBRARIES   "${CRYPTOLIB_DEPS_ROOT}/lib/libcrypto.a")
    set(OPENSSL_LIBRARY_DIRS "${CRYPTOLIB_DEPS_ROOT}/lib")

    set(BLST_INCLUDE_DIR    "${CRYPTOLIB_DEPS_ROOT}/include")
    set(BLST_LIBRARY        "${CRYPTOLIB_DEPS_ROOT}/lib/libblst.a")

    set(SECP256K1_INCLUDE_DIR "${CRYPTOLIB_DEPS_ROOT}/include")
    set(SECP256K1_LIBRARY     "${CRYPTOLIB_DEPS_ROOT}/lib/libsecp256k1.a")

    set(CRYPTOLIB_DEPS_PREBUILT ON)
else()
    # Native macOS path: Homebrew + pkg-config discovery (version-agnostic).
    # pkg-config tells us the current Cellar path regardless of point-release
    # bumps (e.g. libsodium 1.0.21 -> 1.0.22), so we don't hard-code versions.
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)

    set(CRYPTOLIB_DEPS_PREBUILT OFF)
endif()

# ─── Optional dependencies (ON by default) ──────────────────────────────────
option(CRYPTOLIB_BLAKE3 "Enable BLAKE3 hash (requires libblake3)" ON)
option(CRYPTOLIB_PQ     "Enable post-quantum algorithms (requires liboqs)" ON)
option(CRYPTOLIB_BLS    "Enable BLS12-381 aggregate signatures (requires blst)" ON)
option(CRYPTOLIB_SECP256K1 "Enable secp256k1 ECDSA for EVM/BTC interop (requires libsecp256k1 w/ recovery module)" ON)

if(CRYPTOLIB_BLAKE3 AND NOT CRYPTOLIB_DEPS_PREBUILT)
    pkg_check_modules(BLAKE3 REQUIRED libblake3)
endif()

if(CRYPTOLIB_PQ AND NOT CRYPTOLIB_DEPS_PREBUILT)
    pkg_check_modules(OQS_PC liboqs)
    if(OQS_PC_FOUND)
        set(OQS_INCLUDE_DIR "${OQS_PC_INCLUDE_DIRS}")
        set(OQS_LIBRARY    "${OQS_PC_LINK_LIBRARIES}")
    else()
        # Fall back to generic search (Homebrew /opt/homebrew/lib etc.)
        find_library(OQS_LIBRARY oqs PATHS /opt/homebrew/lib /usr/local/lib REQUIRED)
        find_path(OQS_INCLUDE_DIR oqs/oqs.h PATHS /opt/homebrew/include /usr/local/include REQUIRED)
    endif()
    # liboqs depends on OpenSSL for AES/SHA primitives
    pkg_check_modules(OPENSSL REQUIRED openssl)
endif()

if(CRYPTOLIB_BLS AND NOT CRYPTOLIB_DEPS_PREBUILT)
    find_library(BLST_LIBRARY blst PATHS /opt/homebrew/lib /usr/local/lib REQUIRED)
    find_path(BLST_INCLUDE_DIR blst/blst.h PATHS /opt/homebrew/include /usr/local/include REQUIRED)
endif()

if(CRYPTOLIB_SECP256K1 AND NOT CRYPTOLIB_DEPS_PREBUILT)
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
add_library(cryptolib INTERFACE)
add_library(crypto::cryptolib ALIAS cryptolib)

target_include_directories(cryptolib INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(cryptolib INTERFACE ${SODIUM_LIBRARIES})
if(NOT CRYPTOLIB_DEPS_PREBUILT AND SODIUM_LIBRARY_DIRS)
    target_link_directories(cryptolib INTERFACE ${SODIUM_LIBRARY_DIRS})
endif()

if(CRYPTOLIB_BLAKE3)
    target_compile_definitions(cryptolib INTERFACE CRYPTOLIB_HAS_BLAKE3=1)
    target_include_directories(cryptolib INTERFACE ${BLAKE3_INCLUDE_DIRS})
    target_link_libraries(cryptolib INTERFACE ${BLAKE3_LIBRARIES})
    if(NOT CRYPTOLIB_DEPS_PREBUILT)
        target_link_directories(cryptolib INTERFACE ${BLAKE3_LIBRARY_DIRS})
    endif()
endif()

if(CRYPTOLIB_PQ)
    target_compile_definitions(cryptolib INTERFACE CRYPTOLIB_HAS_PQ=1 CRYPTOLIB_HAS_OPENSSL=1)
    target_include_directories(cryptolib INTERFACE ${OQS_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIRS})
    target_link_libraries(cryptolib INTERFACE ${OQS_LIBRARY} ${OPENSSL_LIBRARIES})
    if(NOT CRYPTOLIB_DEPS_PREBUILT)
        target_link_directories(cryptolib INTERFACE ${OPENSSL_LIBRARY_DIRS})
    endif()
endif()

if(CRYPTOLIB_BLS)
    target_compile_definitions(cryptolib INTERFACE CRYPTOLIB_HAS_BLS=1)
    target_include_directories(cryptolib INTERFACE ${BLST_INCLUDE_DIR})
    target_link_libraries(cryptolib INTERFACE ${BLST_LIBRARY})
endif()

if(CRYPTOLIB_SECP256K1)
    target_compile_definitions(cryptolib INTERFACE CRYPTOLIB_HAS_SECP256K1=1)
    target_include_directories(cryptolib INTERFACE ${SECP256K1_INCLUDE_DIR})
    target_link_libraries(cryptolib INTERFACE ${SECP256K1_LIBRARY})
    if(NOT CRYPTOLIB_DEPS_PREBUILT AND SECP256K1_PC_LIBRARY_DIRS)
        target_link_directories(cryptolib INTERFACE ${SECP256K1_PC_LIBRARY_DIRS})
    endif()
endif()

# ─── Gate examples + tests: skip when cross-compiling or building static ─────
set(_CRYPTOLIB_HOST_BUILD ON)
if(CMAKE_CROSSCOMPILING OR CRYPTOLIB_STATIC)
    set(_CRYPTOLIB_HOST_BUILD OFF)
endif()

# ─── Sanitizers (ASan + UBSan) — opt-in for tests/fuzzers ────────────────────
# Crypto code parses untrusted input (stego format parsers); sanitizers are the
# primary line of defence against the memory-safety bugs that unit tests miss.
option(CRYPTOLIB_SANITIZE "Build tests/examples with AddressSanitizer + UBSan" OFF)
option(CRYPTOLIB_TSAN "Build tests with ThreadSanitizer (mutually exclusive with ASan)" OFF)
set(CRYPTOLIB_SANITIZE_FLAGS "")
if(CRYPTOLIB_SANITIZE AND CRYPTOLIB_TSAN)
    message(FATAL_ERROR "CRYPTOLIB_SANITIZE (ASan) and CRYPTOLIB_TSAN are mutually exclusive.")
endif()
if(CRYPTOLIB_SANITIZE)
    set(CRYPTOLIB_SANITIZE_FLAGS
        -fsanitize=address,undefined
        -fno-sanitize-recover=all
        -fno-omit-frame-pointer
        -g)
    message(STATUS "cryptolib: AddressSanitizer + UBSan ENABLED for host targets")
elseif(CRYPTOLIB_TSAN)
    set(CRYPTOLIB_SANITIZE_FLAGS -fsanitize=thread -fno-omit-frame-pointer -g)
    message(STATUS "cryptolib: ThreadSanitizer ENABLED for host targets")
endif()

# ─── Proof-of-concept ─────────────────────────────────────────────────────────
option(CRYPTOLIB_BUILD_EXAMPLE "Build PoC example" ${_CRYPTOLIB_HOST_BUILD})
if(CRYPTOLIB_BUILD_EXAMPLE)
    add_executable(cryptolib_poc example/main.cpp)
    target_compile_options(cryptolib_poc PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cryptolib_poc PRIVATE crypto::cryptolib)

    add_executable(cryptolib_usage example/usage.cpp)
    target_compile_options(cryptolib_usage PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cryptolib_usage PRIVATE crypto::cryptolib)

    add_executable(cryptolib_demo example/demo.cpp)
    target_compile_options(cryptolib_demo PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_link_libraries(cryptolib_demo PRIVATE crypto::cryptolib)

    add_executable(cryptolib_showcase example/showcase.cpp)
    target_compile_options(cryptolib_showcase PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
    target_compile_definitions(cryptolib_showcase PRIVATE
        CRYPTOLIB_PROJECT_DIR="${CMAKE_SOURCE_DIR}")
    target_link_libraries(cryptolib_showcase PRIVATE crypto::cryptolib)
endif()

# ─── Tests ───────────────────────────────────────────────────────────────────
option(CRYPTOLIB_BUILD_TESTS "Build test suite" ${_CRYPTOLIB_HOST_BUILD})
if(CRYPTOLIB_BUILD_TESTS)
    file(GLOB TEST_SOURCES tests/test_*.cpp)
    add_executable(cryptolib_tests ${TEST_SOURCES})
    target_include_directories(cryptolib_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_compile_options(cryptolib_tests PRIVATE -Wall -Wextra -Wno-unused-parameter -O2
        ${CRYPTOLIB_SANITIZE_FLAGS})
    target_link_options(cryptolib_tests PRIVATE ${CRYPTOLIB_SANITIZE_FLAGS})
    target_link_libraries(cryptolib_tests PRIVATE crypto::cryptolib)
endif()

# ─── Fuzzers (libFuzzer, clang only) ─────────────────────────────────────────
# The stego parsers consume untrusted files; libFuzzer + ASan/UBSan is the
# primary tool for finding the memory-safety bugs unit tests miss.
#   cmake -B build-fuzz -DCRYPTOLIB_FUZZ=ON && cmake --build build-fuzz
#   ./build-fuzz/fuzz_stego -max_total_time=120
#
# NOTE: Apple's Xcode Clang does NOT ship the libFuzzer runtime
# (libclang_rt.fuzzer_osx.a). On macOS, build with LLVM clang, e.g.:
#   brew install llvm
#   cmake -B build-fuzz -DCRYPTOLIB_FUZZ=ON \
#         -DCMAKE_CXX_COMPILER=$(brew --prefix llvm)/bin/clang++
# Linux clang ships libFuzzer out of the box.
option(CRYPTOLIB_FUZZ "Build libFuzzer targets (LLVM clang only)" OFF)
if(CRYPTOLIB_FUZZ AND _CRYPTOLIB_HOST_BUILD)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "CRYPTOLIB_FUZZ requires Clang (libFuzzer).")
    endif()
    message(STATUS "cryptolib: building libFuzzer targets (needs LLVM clang runtime)")
    foreach(_fz fuzz_packet fuzz_stego fuzz_diff_aead)
        add_executable(${_fz} tests/fuzz/${_fz}.cpp)
        target_compile_options(${_fz} PRIVATE
            -g -O1 -fsanitize=fuzzer,address,undefined)
        target_link_options(${_fz} PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_libraries(${_fz} PRIVATE crypto::cryptolib)
    endforeach()
endif()

# ─── Constant-time verification probe (run under Valgrind/ctgrind) ──────────
option(CRYPTOLIB_CT_VALGRIND "Build the constant-time probe (run under Valgrind)" OFF)
if(CRYPTOLIB_CT_VALGRIND AND _CRYPTOLIB_HOST_BUILD)
    add_executable(ct_probe tests/ct/ct_probe.cpp)
    target_compile_options(ct_probe PRIVATE -g -O1)
    target_link_libraries(ct_probe PRIVATE crypto::cryptolib)
endif()

# ─── C FFI bridge: SHARED on host, STATIC for iOS/XCFramework ───────────────
option(CRYPTOLIB_BUILD_BRIDGE "Build C FFI library" ON)
if(CRYPTOLIB_BUILD_BRIDGE)
    if(CRYPTOLIB_STATIC)
        add_library(cryptolib_c STATIC bridge/cryptolib_c.cpp)
    else()
        add_library(cryptolib_c SHARED bridge/cryptolib_c.cpp)
    endif()

    target_include_directories(cryptolib_c PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${SODIUM_INCLUDE_DIRS}
    )
    target_link_libraries(cryptolib_c PRIVATE ${SODIUM_LIBRARIES})
    if(NOT CRYPTOLIB_DEPS_PREBUILT AND SODIUM_LIBRARY_DIRS)
        target_link_directories(cryptolib_c PRIVATE ${SODIUM_LIBRARY_DIRS})
    endif()
    target_compile_definitions(cryptolib_c PRIVATE CRYPTOLIB_BUILD_SHARED)
    target_compile_options(cryptolib_c PRIVATE -Wall -Wextra -O2)

    set_target_properties(cryptolib_c PROPERTIES
        OUTPUT_NAME cryptolib_c
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )

    # Shared-lib-only properties — meaningless for static archives
    if(NOT CRYPTOLIB_STATIC)
        set_target_properties(cryptolib_c PROPERTIES
            VERSION ${PROJECT_VERSION}
            SOVERSION 3
            MACOSX_RPATH ON
        )
    endif()

    if(CRYPTOLIB_BLAKE3)
        target_compile_definitions(cryptolib_c PRIVATE CRYPTOLIB_HAS_BLAKE3=1)
        target_include_directories(cryptolib_c PRIVATE ${BLAKE3_INCLUDE_DIRS})
        target_link_libraries(cryptolib_c PRIVATE ${BLAKE3_LIBRARIES})
        if(NOT CRYPTOLIB_DEPS_PREBUILT)
            target_link_directories(cryptolib_c PRIVATE ${BLAKE3_LIBRARY_DIRS})
        endif()
    endif()
    if(CRYPTOLIB_PQ)
        target_compile_definitions(cryptolib_c PRIVATE CRYPTOLIB_HAS_PQ=1)
        target_include_directories(cryptolib_c PRIVATE ${OQS_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIRS})
        target_link_libraries(cryptolib_c PRIVATE ${OQS_LIBRARY} ${OPENSSL_LIBRARIES})
        if(NOT CRYPTOLIB_DEPS_PREBUILT)
            target_link_directories(cryptolib_c PRIVATE ${OPENSSL_LIBRARY_DIRS})
        endif()
    endif()
    if(CRYPTOLIB_BLS)
        target_compile_definitions(cryptolib_c PRIVATE CRYPTOLIB_HAS_BLS=1)
        target_include_directories(cryptolib_c PRIVATE ${BLST_INCLUDE_DIR})
        target_link_libraries(cryptolib_c PRIVATE ${BLST_LIBRARY})
    endif()
    if(CRYPTOLIB_SECP256K1)
        target_compile_definitions(cryptolib_c PRIVATE CRYPTOLIB_HAS_SECP256K1=1)
        target_include_directories(cryptolib_c PRIVATE ${SECP256K1_INCLUDE_DIR})
        target_link_libraries(cryptolib_c PRIVATE ${SECP256K1_LIBRARY})
        if(NOT CRYPTOLIB_DEPS_PREBUILT AND SECP256K1_PC_LIBRARY_DIRS)
            target_link_directories(cryptolib_c PRIVATE ${SECP256K1_PC_LIBRARY_DIRS})
        endif()
    endif()
endif()

include(GNUInstallDirs)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
