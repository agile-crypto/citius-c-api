cmake_minimum_required(VERSION 3.20)

# citius-c-api is the C contract: the agc_* headers, their generator and the
# conformance checks. It builds no library; implementations (citius-rust:
# libagilecrypto) ship the binary and install these headers with it.

# One version source: the API version the headers declare (agc_abi.h).
file(STRINGS include/agc/agc_abi.h _agc_version_lines
     REGEX "^#define AGC_API_VERSION_(MAJOR|MINOR|PATCH) [0-9]+")
foreach(_part MAJOR MINOR PATCH)
    string(REGEX MATCH "AGC_API_VERSION_${_part} ([0-9]+)" _ "${_agc_version_lines}")
    set(_agc_${_part} "${CMAKE_MATCH_1}")
endforeach()

project(agc_headers
    VERSION ${_agc_MAJOR}.${_agc_MINOR}.${_agc_PATCH}
    DESCRIPTION "citius C API headers (agc_*)"
    LANGUAGES C)

include(CheckLanguage)
check_language(CXX)
if(CMAKE_CXX_COMPILER)
    enable_language(CXX)
endif()

option(AGC_BUILD_TESTS "Build the header and conformance checks" ON)

include(GNUInstallDirs)

add_library(agc_headers INTERFACE)
add_library(agc::headers ALIAS agc_headers)
target_include_directories(agc_headers INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/agc>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/agc>)

configure_file(cmake/agc-headers.pc.in ${CMAKE_CURRENT_BINARY_DIR}/agc-headers.pc @ONLY)
install(DIRECTORY include/agc/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/agc FILES_MATCHING PATTERN "*.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/agc-headers.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(AGC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
