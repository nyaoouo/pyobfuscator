include_guard(GLOBAL)

add_test(NAME pyobf_native_demo_post_mixed_private_input
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_post_mixed_binding.py")

add_executable(pyobf_native_demo_payload_binding_probe payload_binding_smoke.cpp)
target_compile_features(pyobf_native_demo_payload_binding_probe PRIVATE cxx_std_17)
target_include_directories(pyobf_native_demo_payload_binding_probe PRIVATE
    "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(pyobf_native_demo_payload_binding_probe PRIVATE
    pyobf_native_bootstrap_context pyobf_native_contribution_provider)
set(binding_reference_check "")
if(payload_binding_reference)
    list(APPEND binding_reference_check --reference "${payload_binding_reference}")
endif()
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    list(APPEND binding_reference_check --scope-material "${payload_scope_material}")
endif()
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    list(APPEND binding_reference_check --mixed-plan "${payload_mixed_plan}"
        --release-material "${release_material}")
endif()
add_test(NAME pyobf_native_demo_payload_binding
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_payload_binding.py"
        "$<TARGET_FILE:pyobf_native_demo_payload_binding_probe>" "$<TARGET_FILE:pyobf_native_demo_inner>"
        "${linked_cff_report}" "${release_plan}" "${path_events_header}" "${CMAKE_CURRENT_BINARY_DIR}"
        --profile "${PYOBF_NATIVE_DEMO_PAYLOAD_BINDING}" ${binding_reference_check})
get_filename_component(binding_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
set_tests_properties(pyobf_native_demo_payload_binding PROPERTIES TIMEOUT 60
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${binding_runtime_directory}")

if(PYOBF_NATIVE_DEMO_PAYLOAD_BINDING STREQUAL "strict" AND
        NOT PYOBF_NATIVE_DEMO_POST_CODE_HASH AND NOT PYOBF_NATIVE_DEMO_ARCHIVE)
    add_test(NAME pyobf_native_demo_owned_return_flow
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_owned_return_flow.py"
            "$<TARGET_FILE:pyobf_native_demo_payload_binding_probe>"
            "$<TARGET_FILE:pyobf_native_demo_inner>"
            "${transformed_ir}" "${cff_report}" "${payload_binding_reference}"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}")
    set_tests_properties(pyobf_native_demo_owned_return_flow PROPERTIES TIMEOUT 120
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${binding_runtime_directory}")
endif()
