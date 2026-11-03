if(NOT PYOBF_NATIVE_BUILD_SMOKE OR NOT TARGET pyobf_native_bootstrap_context
        OR NOT TARGET pyobf_native_cff
        OR NOT PYOBF_NATIVE_BACKEND_ID STREQUAL "windows_user"
        OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang"
        OR NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
    return()
endif()
find_package(Python3 COMPONENTS Interpreter REQUIRED)
find_program(PYOBF_CONTEXT_OPT NAMES opt HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(PYOBF_CONTEXT_LLVM_LINK NAMES llvm-link HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(PYOBF_CONTEXT_OBJDUMP NAMES llvm-objdump HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
get_target_property(context_core pyobf_native_bootstrap_context PYOBF_NATIVE_CONTEXT_CORE_SOURCES)
set(context_link_options "")
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    list(APPEND context_link_options --ipo)
endif()
foreach(profile none O2)
    add_test(NAME pyobf_native_context_cff_${profile}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/context/check_cff.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTEXT_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTEXT_LLVM_LINK}" "${PYOBF_CONTEXT_OBJDUMP}"
            "$<TARGET_FILE:pyobf_native_context_provider>" "${PROJECT_BINARY_DIR}/tests/context"
            "${profile}" ${context_link_options}
            --core ${context_core} --sdk "${PROJECT_SOURCE_DIR}/src/sdk.cpp" ${PYOBF_NATIVE_BACKEND_SDK_SOURCES}
            --backend ${PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES})
    set_tests_properties(pyobf_native_context_cff_${profile} PROPERTIES TIMEOUT 180)
endforeach()
