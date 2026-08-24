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

# For tests needing an internal-only symbol (agc_internal.h) -- see the
# whitebox target comment in the top-level CMakeLists.txt.
function(agc_add_whitebox_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE agilecrypto_whitebox Threads::Threads)
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
agc_add_test(test_key_management test_key_management.c)
agc_add_test(test_crypto test_crypto.c)
agc_add_test(test_streaming test_streaming.c)
agc_add_test(test_key_establishment test_key_establishment.c)
agc_add_test(test_policy test_policy.c)
agc_add_test(test_discovery test_discovery.c)
agc_add_test(test_provider test_provider.c)
agc_add_whitebox_test(test_protobuf_wire test_protobuf_wire.c)
agc_add_whitebox_test(test_metadata_codec test_metadata_codec.c)

if(AGC_ENABLE_PROPOSED_EXTENSIONS)
    agc_add_test(test_ext test_ext.c)
endif()

# Tier 1 vocabulary conformance (RECONCILIATION_PLAN.md §7): the generated
# agc_types.h must carry exactly the proto's enum values, no more, no fewer.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(NAME tier1_vocabulary
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/conformance/tier1_vocabulary.py)
    add_test(NAME tier1c_oneof_tags
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/conformance/tier1c_oneof_tags.py)

    # Tier 1b/1c (RECONCILIATION_PLAN.md §7, commit 12): RPC<->function
    # surface bijection and request/response field presence, both checked
    # against conformance/rpc_manifest.yaml and conformance/DIVERGENCES.yaml.
    add_test(NAME tier1b_surface
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/conformance/tier1b_surface.py)
    add_test(NAME tier1c_fields
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/conformance/tier1c_fields.py)

    # Cross-implementation check for the hand-written OperationMetadata codec
    # (RECONCILIATION_PLAN.md D11, §9.2): test_metadata_codec writes bytes it
    # encoded to c_encoded_vectors/*.bin; this decodes them with the REAL
    # protobuf library and checks field values, proving the encoder is wire-
    # compatible rather than merely self-consistent. Must run after the C
    # test that produces the files.
    add_test(NAME verify_c_encoded_metadata
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/golden/verify_c_encoded.py)
    set_tests_properties(verify_c_encoded_metadata PROPERTIES DEPENDS test_metadata_codec)
endif()

# Tier 4 ABI stability (RECONCILIATION_PLAN.md §7): skips (exit 0) rather
# than fails when libabigail is not installed or no baseline exists yet
# (pre-1.0) -- see the script header for why that is not a false pass.
add_test(NAME tier4_abi
         COMMAND ${CMAKE_SOURCE_DIR}/conformance/tier4_abi_baseline.sh check)
set_tests_properties(tier4_abi PROPERTIES
    ENVIRONMENT "AGC_ABI_BUILD_DIR=$<TARGET_FILE_DIR:agilecrypto>")
