# Each reconciliation commit appends its own test binary here rather than
# globbing, so an accidentally-omitted test fails visibly instead of silently
# not running.

function(agc_add_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE agilecrypto)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/helpers)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

agc_add_test(test_version test_version.c)
