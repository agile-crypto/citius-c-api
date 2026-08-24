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
agc_add_test(test_types test_types.c)

# Tier 1 vocabulary conformance (RECONCILIATION_PLAN.md §7): the generated
# agc_types.h must carry exactly the proto's enum values, no more, no fewer.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(NAME tier1_vocabulary
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/conformance/tier1_vocabulary.py)
endif()
