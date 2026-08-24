# Example programs (commit 14): each is a small, standalone, buildable and
# runnable demonstration of one slice of the API. Not part of `ctest` --
# they print to stdout for a human, not assertions for CI -- but they DO
# have to build and exit 0, which `add_test` below checks cheaply.

function(agc_add_example name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE agilecrypto)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
endfunction()

agc_add_example(01_encrypt_decrypt)
agc_add_example(02_streaming_sign)
agc_add_example(03_policy_and_discovery)

if(AGC_BUILD_TESTS)
    add_test(NAME example_01_encrypt_decrypt COMMAND 01_encrypt_decrypt)
    add_test(NAME example_02_streaming_sign COMMAND 02_streaming_sign)
    add_test(NAME example_03_policy_and_discovery COMMAND 03_policy_and_discovery)
endif()
