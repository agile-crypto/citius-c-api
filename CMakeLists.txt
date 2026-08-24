cmake_minimum_required(VERSION 3.20)
project(agilecrypto
    VERSION 1.0.0
    DESCRIPTION "Abstract Cryptographic API — C binding"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "" FORCE)
endif()

option(AGC_BUILD_TESTS "Build the CTest suite" ON)
option(AGC_BUILD_EXAMPLES "Build the example programs" ON)
option(AGC_ENABLE_PROPOSED_EXTENSIONS "Build agc_ext.h — RPCs not yet in the proto (see docs/PROTO_RFCS.md)" OFF)

include(GNUInstallDirs)

# ----------------------------------------------------------------------------
# Core library. Sources are appended to by each reconciliation commit rather
# than globbed, so a file that fails to compile fails the specific commit that
# introduced it rather than silently vanishing from the build.
# ----------------------------------------------------------------------------
set(AGC_LIB_SOURCES
    src/core/version.c
    src/core/agc_types.c
    src/core/error.c
    src/core/memory.c
    src/core/ctx.c
    src/core/session.c
    src/core/iter.c
    src/wire/protobuf_wire.c
    src/wire/metadata_codec.c
    src/stub/stub_random.c
    src/stub/stub_crypto.c
    src/store/keystore.c
    src/store/policystore.c
    src/store/providerstore.c
    src/services/key.c
    src/services/crypto.c
    src/services/stream.c
    src/services/establish.c
    src/services/policy.c
    src/services/discovery.c
    src/services/provider.c
)

add_library(agilecrypto SHARED ${AGC_LIB_SOURCES})

target_include_directories(agilecrypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/agc>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/agc>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(agilecrypto PROPERTIES
    C_VISIBILITY_PRESET hidden
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

target_compile_options(agilecrypto PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Debug>:-g -O0>
)

if(AGC_ENABLE_PROPOSED_EXTENSIONS)
    target_compile_definitions(agilecrypto PUBLIC AGC_ENABLE_PROPOSED_EXTENSIONS=1)
endif()

find_package(Threads REQUIRED)
target_link_libraries(agilecrypto PRIVATE Threads::Threads)

# Whitebox test double: the SAME sources, built as a static library with
# default (non-hidden) visibility and src/ on the include path, so tests that
# need an internal-only symbol (agc_internal.h) -- e.g. constructing an
# agc_metadata directly to check the wire codec against real protobuf output
# -- can link against it instead of the real installed shared library.
# Never installed; exists purely for tests/.
if(AGC_BUILD_TESTS)
    add_library(agilecrypto_whitebox STATIC ${AGC_LIB_SOURCES})
    target_include_directories(agilecrypto_whitebox
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/include/agc
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/wire
    )
    target_link_libraries(agilecrypto_whitebox PRIVATE Threads::Threads)
    target_compile_options(agilecrypto_whitebox PRIVATE -Wall -Wextra -Wpedantic)
    if(AGC_ENABLE_PROPOSED_EXTENSIONS)
        target_compile_definitions(agilecrypto_whitebox PUBLIC AGC_ENABLE_PROPOSED_EXTENSIONS=1)
    endif()
endif()

# ----------------------------------------------------------------------------
# pkg-config
# ----------------------------------------------------------------------------
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/agilecrypto.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/agilecrypto.pc
    @ONLY
)

install(TARGETS agilecrypto
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/agc/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/agc FILES_MATCHING PATTERN "*.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/agilecrypto.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# ----------------------------------------------------------------------------
if(AGC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(AGC_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
