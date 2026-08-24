# Each reconciliation commit appends its own test binary here rather than
# globbing, so an accidentally-omitted test fails visibly instead of silently
# not running.

find_package(Threads REQUIRED)

function(agc_add_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE agilecrypto Threads::Threads)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/helpers)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

agc_add_test(test_version test_version.c)
agc_add_test(test_types test_types.c)
agc_add_test(test_abi test_abi.c)
agc_add_test(test_scope_params test_scope_params.c)
agc_add_test(test_ctx test_ctx.c)
agc_add_test(test_error test_error.c)
agc_add_test(test_memory test_memory.c)
agc_add_test(test_session test_session.c)
agc_add_test(test_fork test_fork.c)

# Tier 1 vocabulary conformance (RECONCILIATION_PLAN.md §7): the generated
# agc_types.h must carry exactly the proto's enum values, no more, no fewer.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(NAME tier1_vocabulary
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/conformance/tier1_vocabulary.py)
    add_test(NAME tier1c_oneof_tags
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/conformance/tier1c_oneof_tags.py)
endif()
