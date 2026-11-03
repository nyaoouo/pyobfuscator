include_guard(GLOBAL)

add_test(NAME pyobf_native_demo_atomic_artifact
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/check_atomic_artifact.py" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(pyobf_native_demo_atomic_artifact PROPERTIES TIMEOUT 30)

find_program(PYOBF_NATIVE_READOBJ_EXECUTABLE NAMES llvm-readobj HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
set(release_record_ipo "")
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    list(APPEND release_record_ipo --ipo)
endif()
add_test(NAME pyobf_native_demo_release_record
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_release_record.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_READOBJ_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}" ${release_record_ipo})
set_tests_properties(pyobf_native_demo_release_record PROPERTIES TIMEOUT 120)

add_test(NAME pyobf_native_demo_code_subjects
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_code_subjects.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_READOBJ_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(pyobf_native_demo_code_subjects PROPERTIES TIMEOUT 60)

function(pyobf_native_demo_add_release_plan_check)
    get_target_property(raw_target pyobf_native_demo_outer PYOBF_NATIVE_UNFINALIZED_TARGET)
    set(measured_options "")
    if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        pyobf_native_demo_post_arguments(function_options ${raw_target})
        list(APPEND measured_options ${function_options})
        get_target_property(plan ${raw_target} PYOBF_NATIVE_MEASURED_REFERENCE_PLAN)
        list(APPEND measured_options --post-plan "${plan}" --post-reference "${payload_binding_reference}"
            --post-material "${payload_scope_material}")
        if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH)
            list(APPEND measured_options --pre-release)
        endif()
    elseif(PYOBF_NATIVE_DEMO_PRE_CODE_HASH)
        get_target_property(plan ${raw_target} PYOBF_NATIVE_MEASURED_REFERENCE_PLAN)
        list(APPEND measured_options --measured-plan "${plan}")
    endif()
    add_test(NAME pyobf_native_demo_release_plan
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_release_plan.py"
            "${CMAKE_CXX_COMPILER}" "${CMAKE_CURRENT_BINARY_DIR}"
            "$<TARGET_FILE:pyobf_native_demo_inner>" "${linked_cff_report}"
            "$<TARGET_FILE:${raw_target}>" "${demo_outer_image}"
            "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.release.json" ${measured_options})
    set_tests_properties(pyobf_native_demo_release_plan PROPERTIES TIMEOUT 120)
endfunction()
