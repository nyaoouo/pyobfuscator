include_guard(GLOBAL)
if(NOT PYOBF_NATIVE_DEMO_DECOY)
    return()
endif()

add_test(NAME pyobf_native_demo_decoy_package
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_decoy_package.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
        "${CMAKE_CURRENT_BINARY_DIR}" "$<TARGET_FILE:pyobf_native_demo_decoy>")
set_tests_properties(pyobf_native_demo_decoy_package PROPERTIES TIMEOUT 120)
find_program(PYOBF_NATIVE_DECOY_NINJA_EXECUTABLE NAMES ninja HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
add_test(NAME pyobf_native_demo_decoy_build
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_decoy_build.py"
        "${CMAKE_COMMAND}" "${PYOBF_NATIVE_DECOY_NINJA_EXECUTABLE}" "${CMAKE_CXX_COMPILER}"
        "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
        "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(pyobf_native_demo_decoy_build PROPERTIES TIMEOUT 180)
if(decoy_sources STREQUAL decoy_sample_sources)
    add_executable(pyobf_native_demo_decoy_smoke decoy/smoke.cpp)
    target_compile_features(pyobf_native_demo_decoy_smoke PRIVATE cxx_std_17)
    add_test(NAME pyobf_native_demo_decoy_entry
        COMMAND pyobf_native_demo_decoy_smoke "$<TARGET_FILE:pyobf_native_demo_decoy>")
    get_filename_component(decoy_compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set_tests_properties(pyobf_native_demo_decoy_entry PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${decoy_compiler_directory}")
endif()
