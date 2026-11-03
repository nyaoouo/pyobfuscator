# Structural/source compositions share the actual CNG and immutable-input checker.
foreach(profile none O2)
    foreach(component common-exit deduplicate-blocks split-blocks all)
        set(normalizer_test pyobf_native_contribution_normalizers_${component}_explicit_${profile})
        add_test(NAME ${normalizer_test}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --normalizers ${component}
                ${contribution_ipo} ${contribution_backend_args}
                --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
        set_tests_properties(${normalizer_test} PROPERTIES TIMEOUT 300)
    endforeach()
    foreach(component common-exit deduplicate-blocks split-blocks all)
        set(normalizer_test pyobf_native_contribution_normalizers_${component}_automatic_${profile})
        add_test(NAME ${normalizer_test}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --normalizers ${component} --automatic
                ${contribution_ipo} ${contribution_backend_args}
                --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
        set_tests_properties(${normalizer_test} PROPERTIES TIMEOUT 300)
    endforeach()
endforeach()
foreach(profile none O2)
    foreach(variant grouped composed)
        set(extra --normalizers all --automatic --grouped)
        if(variant STREQUAL "composed")
            list(APPEND extra --scalars all --composed all --bogus bogus-synthesis --ssa-source)
        endif()
        set(normalizer_test pyobf_native_contribution_normalizers_alias_${variant}_${profile})
        add_test(NAME ${normalizer_test}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" ${extra}
                ${contribution_ipo} ${contribution_backend_args}
                --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
        set_tests_properties(${normalizer_test} PROPERTIES TIMEOUT 300)
    endforeach()
endforeach()
add_test(NAME pyobf_native_contribution_normalizers_composed
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
        "${PROJECT_BINARY_DIR}/tests/contribution" none --normalizers all --scalars all --composed all --grouped
        ${contribution_ipo} ${contribution_backend_args}
        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
set_tests_properties(pyobf_native_contribution_normalizers_composed PROPERTIES TIMEOUT 300)
add_custom_target(pyobf_native_measure_contribution_alias
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
        "${PROJECT_BINARY_DIR}/tests/contribution" none --normalizers all --automatic --grouped
        "--alias-measurements=${PROJECT_BINARY_DIR}/tests/contribution/alias.measurements.json"
        ${contribution_ipo} ${contribution_backend_args}
        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}"
    DEPENDS pyobf_native_cff
    VERBATIM)
