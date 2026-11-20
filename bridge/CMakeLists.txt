cmake_minimum_required(VERSION 4.1)
project(cipherbird_bridge VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ─── libsodium ────────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
link_directories(/opt/homebrew/Cellar/libsodium/1.0.21/lib)
pkg_check_modules(SODIUM REQUIRED libsodium)

# ─── Shared library: libcipherbird_c ───────────────────────────────────────────
add_library(cipherbird_c SHARED cipherbird_c.cpp)
target_include_directories(cipherbird_c PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(cipherbird_c PRIVATE ${SODIUM_LIBRARIES})
target_compile_definitions(cipherbird_c PRIVATE CIPHERBIRD_BUILD_SHARED)
target_compile_options(cipherbird_c PRIVATE -Wall -Wextra -O2)

# Set output name and SONAME
set_target_properties(cipherbird_c PROPERTIES
    OUTPUT_NAME cipherbird_c
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
install(TARGETS cipherbird_c
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES cipherbird_c.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
