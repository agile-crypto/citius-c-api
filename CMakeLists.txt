cmake_minimum_required(VERSION 3.25)

project(citius_c_api
    VERSION 0.1.0
    DESCRIPTION "Pure-C cryptographic API mirroring the Citius ProtoBuf API"
    LANGUAGES C
)

# ---------------------------------------------------------------------------
# Language standard
# ---------------------------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------
option(CITIUS_BUILD_EXAMPLES "Build example programs"  OFF)
option(CITIUS_INSTALL_PKGCONFIG "Install pkg-config file" ON)

# ---------------------------------------------------------------------------
# Compiler warnings
# ---------------------------------------------------------------------------
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

# ---------------------------------------------------------------------------
# Public include directory
# ---------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# ---------------------------------------------------------------------------
# Stub provider library
# ---------------------------------------------------------------------------
add_subdirectory(src/stub)

# ---------------------------------------------------------------------------
# Examples (opt-in)
# ---------------------------------------------------------------------------
if(CITIUS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# pkg-config file
# ---------------------------------------------------------------------------
if(CITIUS_INSTALL_PKGCONFIG)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/citius.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/citius.pc
        @ONLY
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/citius.pc
        DESTINATION lib/pkgconfig
    )
endif()

# ---------------------------------------------------------------------------
# Install rules
# ---------------------------------------------------------------------------
install(DIRECTORY include/citius
    DESTINATION include
)

install(TARGETS citius_stub_provider
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)
