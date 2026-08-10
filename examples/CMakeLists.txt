cmake_minimum_required(VERSION 3.25)

# ---------------------------------------------------------------------------
# Examples — standalone programs that demonstrate the Citius C API.
#
# Build together with the top-level project (included from top CMakeLists.txt
# when CITIUS_BUILD_EXAMPLES is ON), or standalone:
#
#   cmake -S examples -B build-examples \
#         -DCMAKE_PREFIX_PATH=<install-prefix>
#   cmake --build build-examples
# ---------------------------------------------------------------------------

foreach(example encrypt_decrypt sign_verify key_lifecycle)
    add_executable(${example} ${example}.c)
    target_link_libraries(${example} PRIVATE citius_stub_provider)
    target_include_directories(${example} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )
    set_target_properties(${example} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
    )
endforeach()
