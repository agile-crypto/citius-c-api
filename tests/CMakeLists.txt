# Checks on the headers themselves; no library is built or linked. The
# behaviour behind the headers is tested by their implementation
# (citius-rust: tests/c, against libagilecrypto).

set(AGC_WARNINGS -Wall -Wextra -Wpedantic -Werror)
file(GLOB AGC_HEADERS RELATIVE ${PROJECT_SOURCE_DIR}/include/agc ${PROJECT_SOURCE_DIR}/include/agc/*.h)

# Every header compiles on its own, as C99, C11 and (if a C++ compiler is
# available) C++11: the build fails on a header that does not.
set(_hdr_dir ${CMAKE_CURRENT_BINARY_DIR}/standalone)
foreach(h ${AGC_HEADERS})
    string(REPLACE ".h" "" n ${h})
    file(WRITE ${_hdr_dir}/${n}.c "#include \"${h}\"\nint agc_standalone_${n};\n")
    file(WRITE ${_hdr_dir}/${n}.cpp "#include \"${h}\"\nint agc_standalone_${n};\n")
    set(_srcs_c ${_srcs_c} ${_hdr_dir}/${n}.c)
    set(_srcs_cxx ${_srcs_cxx} ${_hdr_dir}/${n}.cpp)
endforeach()

foreach(std 99 11)
    add_library(headers_c${std} OBJECT ${_srcs_c})
    target_link_libraries(headers_c${std} PRIVATE agc::headers)
    set_target_properties(headers_c${std} PROPERTIES C_STANDARD ${std} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_compile_options(headers_c${std} PRIVATE ${AGC_WARNINGS})
    set_source_files_properties(${_hdr_dir}/agc_ext.c TARGET_DIRECTORY headers_c${std}
        PROPERTIES COMPILE_DEFINITIONS AGC_ENABLE_PROPOSED_EXTENSIONS=1)
endforeach()

if(CMAKE_CXX_COMPILER)
    add_library(headers_cxx11 OBJECT ${_srcs_cxx})
    target_link_libraries(headers_cxx11 PRIVATE agc::headers)
    set_target_properties(headers_cxx11 PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
    target_compile_options(headers_cxx11 PRIVATE ${AGC_WARNINGS})
    set_source_files_properties(${_hdr_dir}/agc_ext.cpp TARGET_DIRECTORY headers_cxx11
        PROPERTIES COMPILE_DEFINITIONS AGC_ENABLE_PROPOSED_EXTENSIONS=1)
endif()

# Layout and idiom checks that need only the headers (AGC_INIT, presence
# types, bounded arrays), built and run as C99 and C11.
foreach(t test_abi test_scope_params)
    foreach(std 99 11)
        add_executable(${t}_c${std} ${t}.c)
        target_link_libraries(${t}_c${std} PRIVATE agc::headers)
        target_include_directories(${t}_c${std} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/helpers)
        set_target_properties(${t}_c${std} PROPERTIES C_STANDARD ${std} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
        target_compile_options(${t}_c${std} PRIVATE ${AGC_WARNINGS})
        add_test(NAME ${t}_c${std} COMMAND ${t}_c${std})
    endforeach()
endforeach()

# Conformance against the pinned proto descriptor. The checks need the
# Python packages protobuf and pyyaml; without them they are left out with
# a message, rather than registered to fail.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    execute_process(COMMAND ${Python3_EXECUTABLE} -c "import google.protobuf, yaml"
                    RESULT_VARIABLE _agc_py_deps OUTPUT_QUIET ERROR_QUIET)
endif()
if(Python3_FOUND AND _agc_py_deps EQUAL 0)
    foreach(c tier1_vocabulary tier1b_surface tier1c_fields tier1c_oneof_tags)
        add_test(NAME ${c} COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/conformance/${c}.py)
    endforeach()
else()
    message(STATUS "Conformance checks skipped: they need Python 3 with protobuf and pyyaml (pip install protobuf pyyaml)")
endif()

# Tier 4 ABI stability, against an implementation's library: configure with
# -DAGC_ABI_LIB=/path/to/libagilecrypto.so. Skips without it, or without
# libabigail.
set(AGC_ABI_LIB "" CACHE FILEPATH "An implementation's shared library, for the Tier 4 ABI check")
add_test(NAME tier4_abi COMMAND ${PROJECT_SOURCE_DIR}/conformance/tier4_abi_baseline.sh check)
set_tests_properties(tier4_abi PROPERTIES ENVIRONMENT "AGC_ABI_LIB=${AGC_ABI_LIB}")
