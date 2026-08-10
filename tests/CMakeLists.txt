cmake_minimum_required(VERSION 3.25)

enable_testing()

# Helper include path
set(TEST_HELPERS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/helpers)

# Macro to register a single-file test executable
macro(citius_add_test name source)
    add_executable(${name} ${source})
    target_include_directories(${name} PRIVATE ${TEST_HELPERS_DIR})
    target_link_libraries(${name} PRIVATE citius_stub_provider)
    add_test(NAME ${name} COMMAND ${name})
endmacro()

citius_add_test(test_key_management    test_key_management.c)
citius_add_test(test_encrypt_decrypt   test_encrypt_decrypt.c)
citius_add_test(test_sign_verify       test_sign_verify.c)
citius_add_test(test_streaming         test_streaming.c)
citius_add_test(test_mac_digest        test_mac_digest.c)
citius_add_test(test_key_establishment test_key_establishment.c)
citius_add_test(test_discovery         test_discovery.c)
citius_add_test(test_policy            test_policy.c)
