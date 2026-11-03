include_guard(GLOBAL)
set(payload_measure_harness "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp")
set(payload_measure_args "")
set(payload_measure_dependencies "")
if(payload_binding_reference)
    add_executable(pyobf_native_demo_measure_payload EXCLUDE_FROM_ALL measure_payload.cpp)
    target_include_directories(pyobf_native_demo_measure_payload PRIVATE
        "${PROJECT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(pyobf_native_demo_measure_payload PRIVATE pyobf_native_contribution_provider)
    list(APPEND payload_measure_args --binding-reference "${payload_binding_reference}"
        --binding-harness "$<TARGET_FILE:pyobf_native_demo_measure_payload>"
        --baseline-source "${PROJECT_SOURCE_DIR}/src/contribution/marker.cpp"
        --include "${PROJECT_SOURCE_DIR}/include")
    list(APPEND payload_measure_dependencies pyobf_native_demo_measure_payload "${payload_binding_reference}")
endif()
add_custom_target(pyobf_native_demo_measure_cff
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
        "${combined_ir}" "$<TARGET_FILE:pyobf_native_demo_inner>" "${payload_measure_harness}"
        "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.measurements.json" ${payload_measure_args}
    DEPENDS "${linked_cff_report}" "${combined_ir}" measure_cff.py "${payload_measure_harness}"
        ${payload_measure_dependencies}
    VERBATIM)
