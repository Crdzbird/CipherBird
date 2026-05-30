# Minimal iOS toolchain for cryptolib.
#
# Usage:
#   cmake -B build/ios \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
#     -DIOS_PLATFORM=OS               # OS | SIMULATOR | MAC
#
# IOS_PLATFORM values:
#   OS         — iOS device      (iphoneos SDK, arm64)
#   SIMULATOR  — iOS simulator   (iphonesimulator SDK, arm64+x86_64 fat)
#   MAC        — macOS           (macosx SDK, arm64+x86_64 fat)

set(CMAKE_SYSTEM_NAME iOS)
# iOS CMake by default builds static libs unless told otherwise — we want that.
set(CMAKE_SYSTEM_VERSION 15.0)

if(NOT DEFINED IOS_PLATFORM)
    set(IOS_PLATFORM OS)
endif()

if(IOS_PLATFORM STREQUAL "OS")
    set(CMAKE_OSX_SYSROOT iphoneos)
    set(CMAKE_OSX_ARCHITECTURES "arm64")
    set(CMAKE_OSX_DEPLOYMENT_TARGET 15.0)
    set(CMAKE_SYSTEM_PROCESSOR arm64)
elseif(IOS_PLATFORM STREQUAL "SIMULATOR")
    # Apple Silicon Macs only — the simulator runs arm64 natively.
    # x86_64 simulator support would require per-arch builds + lipo, which
    # liboqs doesn't cleanly support in a single CMake invocation. Rosetta
    # handles any x86_64-only app binaries, so this is a non-issue in practice.
    set(CMAKE_OSX_SYSROOT iphonesimulator)
    set(CMAKE_OSX_ARCHITECTURES "arm64")
    set(CMAKE_OSX_DEPLOYMENT_TARGET 15.0)
    set(CMAKE_SYSTEM_PROCESSOR arm64)
elseif(IOS_PLATFORM STREQUAL "MAC")
    set(CMAKE_SYSTEM_NAME Darwin)
    set(CMAKE_OSX_SYSROOT macosx)
    set(CMAKE_OSX_ARCHITECTURES "arm64")
    set(CMAKE_OSX_DEPLOYMENT_TARGET 14.0)
    set(CMAKE_SYSTEM_PROCESSOR arm64)
else()
    message(FATAL_ERROR "IOS_PLATFORM must be OS, SIMULATOR, or MAC (got '${IOS_PLATFORM}')")
endif()

# Disable bitcode (Apple deprecated it)
set(CMAKE_XCODE_ATTRIBUTE_ENABLE_BITCODE NO)

# Always build position-independent for static libs that get linked into
# executables, frameworks, or extensions.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Keep internal symbols hidden so only CRYPTO_API-marked functions export.
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

# When cross-compiling, only search target sysroot for libs/includes, host
# tools for programs (so cmake itself, ninja, xcrun still work).
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

message(STATUS "iOS toolchain: platform=${IOS_PLATFORM} sdk=${CMAKE_OSX_SYSROOT} archs=${CMAKE_OSX_ARCHITECTURES}")
