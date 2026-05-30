cmake_minimum_required(VERSION 4.1)
project(cryptolib_bridge VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ─── libsodium ────────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
link_directories(/opt/homebrew/Cellar/libsodium/1.0.21/lib)
pkg_check_modules(SODIUM REQUIRED libsodium)

# ─── Shared library: libcryptolib_c ───────────────────────────────────────────
add_library(cryptolib_c SHARED cryptolib_c.cpp)
target_include_directories(cryptolib_c PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(cryptolib_c PRIVATE ${SODIUM_LIBRARIES})
target_compile_definitions(cryptolib_c PRIVATE CRYPTOLIB_BUILD_SHARED)
target_compile_options(cryptolib_c PRIVATE -Wall -Wextra -O2)

# Set output name and SONAME
set_target_properties(cryptolib_c PROPERTIES
    OUTPUT_NAME cryptolib_c
    VERSION ${PROJECT_VERSION}
    SOVERSION 3
    # macOS framework-friendly
    MACOSX_RPATH ON
    INSTALL_RPATH "@loader_path"
    # Hide internal symbols
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# ─── Install ──────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS cryptolib_c
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES cryptolib_c.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
