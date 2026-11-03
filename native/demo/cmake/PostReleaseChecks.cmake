include_guard(GLOBAL)
if(NOT PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    return()
endif()
get_target_property(post_raw pyobf_native_demo_outer PYOBF_NATIVE_UNFINALIZED_TARGET)
get_target_property(post_image pyobf_native_demo_outer PYOBF_NATIVE_FINAL_IMAGE)
get_target_property(post_plan ${post_raw} PYOBF_NATIVE_MEASURED_REFERENCE_PLAN)
get_target_property(post_backend ${post_raw} PYOBF_NATIVE_MEASURED_BACKEND_SOURCES)
get_target_property(post_context_core pyobf_native_bootstrap_context PYOBF_NATIVE_CONTEXT_CORE_SOURCES)
set(post_check_options "")
pyobf_native_demo_post_arguments(post_function_options ${post_raw})
list(APPEND post_check_options ${post_function_options})
if(NOT PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE)
    list(APPEND post_check_options --blocked)
endif()
if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH)
    list(APPEND post_check_options --pre-release)
    set(post_record pyobf_native_demo_measured_record)
else()
    set(post_record pyobf_native_demo_record)
endif()
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    list(APPEND post_check_options --mixed-plan "${payload_mixed_plan}")
endif()
if(PYOBF_NATIVE_DEMO_OUTER_CFF)
    get_target_property(post_object ${post_raw} PYOBF_NATIVE_MEASURED_CFF_OBJECT)
    get_target_property(post_coverage ${post_raw} PYOBF_NATIVE_MEASURED_CFF_REPORT)
    list(APPEND post_check_options --object "${post_object}" --coverage "${post_coverage}")
    if(NOT PYOBF_NATIVE_DEMO_POST_MIXED)
        add_test(NAME pyobf_native_demo_post_role_join
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_post_role_join.py"
                "${post_coverage}" "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.final.json"
                "${post_plan}" "${post_image}"
                "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.release.json" "${release_plan}"
                "$<TARGET_FILE:pyobf_native_demo_inner>" "${linked_cff_report}" "${cff_report}"
                "${payload_binding_reference}" "${payload_scope_material}")
        set_tests_properties(pyobf_native_demo_post_role_join PROPERTIES TIMEOUT 120)
    else()
        add_test(NAME pyobf_native_demo_post_mixed_role_join
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_post_mixed_role_join.py"
                "${post_coverage}" "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.final.json"
                "${post_plan}" "${post_image}"
                "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.release.json" "${release_plan}"
                "$<TARGET_FILE:pyobf_native_demo_inner>" "${linked_cff_report}" "${cff_report}"
                "${payload_binding_reference}" "${payload_scope_material}"
                "${release_material}" "${payload_mixed_plan}")
        set_tests_properties(pyobf_native_demo_post_mixed_role_join PROPERTIES TIMEOUT 120)
    endif()
else()
    if(PYOBF_DEMO_POST_PARENT_KIND EQUAL 3)
        get_target_property(post_object ${post_raw} PYOBF_NATIVE_MEASURED_OBJECT)
        list(APPEND post_check_options --object "${post_object}")
    else()
        get_target_property(post_sources ${post_raw} PYOBF_NATIVE_MEASURED_AUTHORED_SOURCES)
        list(APPEND post_check_options --sources ${post_sources})
    endif()
endif()
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    set(post_mixed_final_options "")
    if(PYOBF_NATIVE_CFF_SOURCE_OPT STREQUAL "none")
        list(APPEND post_mixed_final_options --expect-saved-rsi)
    endif()
    add_test(NAME pyobf_native_demo_post_mixed_final
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/post_mixed_final_cases.py"
            --real-build "${CMAKE_BINARY_DIR}" --objdump "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            ${post_mixed_final_options})
    set_tests_properties(pyobf_native_demo_post_mixed_final PROPERTIES TIMEOUT 120)
else()
    add_test(NAME pyobf_native_demo_post_release
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_post_release.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${post_image}" "$<TARGET_FILE:${post_raw}>"
            "${post_plan}" "${release_material}" "${release_record_blob}" "${payload_binding_reference}" "${payload_scope_material}"
            "$<TARGET_FILE:pyobf_native_demo_inner>" "${linked_cff_report}" "${release_plan}"
            "$<TARGET_OBJECTS:${post_raw}_reference_store>" "$<TARGET_OBJECTS:${post_record}>"
            "${CMAKE_CURRENT_BINARY_DIR}/${post_raw}.references" "${CMAKE_CURRENT_BINARY_DIR}"
            --backend ${post_backend} --foreign-context ${post_context_core} --role "${post_raw}" ${post_check_options})
    set_tests_properties(pyobf_native_demo_post_release PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE)
endif()
if(PYOBF_NATIVE_CFF_SOURCE_OPT STREQUAL "O2")
    add_test(NAME pyobf_native_demo_post_child_optimized
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/llvm/tests/check_post_child_optimized.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${cff_input}" "${transformed_ir}" "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(pyobf_native_demo_post_child_optimized PROPERTIES TIMEOUT 60)
endif()
if(NOT PYOBF_NATIVE_DEMO_POST_MIXED)
    add_test(NAME pyobf_native_demo_post_subjects
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_post_subjects.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${release_material}"
            "${payload_binding_reference}" "${payload_scope_material}" "${transformed_ir}" "${cff_report}"
            "${release_record_blob}" "${CMAKE_CURRENT_BINARY_DIR}" --cmake "${CMAKE_COMMAND}")
    set_tests_properties(pyobf_native_demo_post_subjects PROPERTIES TIMEOUT 180)
endif()
