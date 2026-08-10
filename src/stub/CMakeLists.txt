cmake_minimum_required(VERSION 3.25)

# citius_stub_provider — zero-filling stub implementation of citius_provider_ops_t
# Sources are added here; the target is defined as STATIC.

add_library(citius_stub_provider STATIC
    stub_provider.c
)

target_include_directories(citius_stub_provider PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
