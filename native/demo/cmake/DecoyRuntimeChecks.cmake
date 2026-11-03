include_guard(GLOBAL)
if(NOT PYOBF_NATIVE_DEMO_DECOY OR NOT decoy_sources STREQUAL decoy_sample_sources)
    return()
endif()

set(decoy_observed_sources ${session_authored_sources})
foreach(source IN LISTS decoy_runtime_sources)
    get_filename_component(source "${source}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    list(APPEND decoy_observed_sources "${source}")
endforeach()
foreach(profile none O2)
    add_test(NAME pyobf_native_demo_decoy_observed_${profile}
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_decoy_runtime.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${PYOBF_NATIVE_OUTER_DECOY_CFF_CONFIG}" "${CMAKE_CURRENT_BINARY_DIR}" "${release_record_blob}"
            "$<TARGET_FILE:pyobf_native_demo_inner>" "$<TARGET_FILE:pyobf_native_demo_decoy>"
            "${profile}" ${session_ipo} --sources ${decoy_observed_sources})
    set_tests_properties(pyobf_native_demo_decoy_observed_${profile} PROPERTIES TIMEOUT 360)
endforeach()

add_executable(pyobf_native_demo_decoy_runtime_smoke decoy/runtime_smoke.cpp)
target_compile_features(pyobf_native_demo_decoy_runtime_smoke PRIVATE cxx_std_17)
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    target_compile_definitions(pyobf_native_demo_decoy_runtime_smoke PRIVATE PYOBF_DEMO_POST_CODE_HASH=1)
endif()
find_package(Threads REQUIRED)
target_link_libraries(pyobf_native_demo_decoy_runtime_smoke PRIVATE Threads::Threads)
get_target_property(decoy_outer_image pyobf_native_demo_outer_decoy PYOBF_NATIVE_FINAL_IMAGE)
get_target_property(decoy_triggered_image pyobf_native_demo_outer_decoy_triggered PYOBF_NATIVE_FINAL_IMAGE)
if(PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE)
    set(decoy_default_policy allowed)
else()
    set(decoy_default_policy denied)
endif()
add_test(NAME pyobf_native_demo_decoy_runtime
    COMMAND pyobf_native_demo_decoy_runtime_smoke "${decoy_outer_image}" "${decoy_default_policy}")
add_test(NAME pyobf_native_demo_decoy_runtime_triggered
    COMMAND pyobf_native_demo_decoy_runtime_smoke "${decoy_triggered_image}" denied)
get_filename_component(decoy_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
set_tests_properties(pyobf_native_demo_decoy_runtime pyobf_native_demo_decoy_runtime_triggered PROPERTIES
    TIMEOUT 120 ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${decoy_runtime_directory}")
if(PYOBF_NATIVE_DEMO_OUTER_CFF)
    set(decoy_measured_args "")
    if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH OR PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        pyobf_native_demo_measured_arguments(decoy_measured_args pyobf_native_demo_outer_decoy)
    endif()
    add_test(NAME pyobf_native_demo_decoy_outer_failures
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_outer_failures.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py"
            "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer_decoy.combined.ll"
            "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer_decoy.coverage.json"
            "${PYOBF_NATIVE_OUTER_DECOY_CFF_CONFIG}" "$<TARGET_FILE:pyobf_native_demo_decoy_runtime_smoke>"
            "${CMAKE_CURRENT_BINARY_DIR}" "${release_record_blob}" ${outer_failure_args} ${decoy_measured_args} --decoy)
    set_tests_properties(pyobf_native_demo_decoy_outer_failures PROPERTIES TIMEOUT 120
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${decoy_runtime_directory}")
endif()
