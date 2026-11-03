# Data/contribution cases reuse the CNG source, negative and final-image driver.
foreach(component integer-literals comparison-constants all)
    foreach(profile none O2)
        foreach(mode explicit automatic)
            set(selection "")
            if(mode STREQUAL "automatic")
                set(selection --automatic)
            endif()
            foreach(scope whole hybrid)
                set(scope_args "")
                set(scope_label "")
                if(scope STREQUAL "hybrid")
                    set(scope_args --hybrid)
                    set(scope_label "hybrid_")
                endif()
                set(scalar_test pyobf_native_contribution_scalars_${component}_${scope_label}${mode}_${profile})
                add_test(NAME ${scalar_test}
                    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                        "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --scalars ${component}
                        ${scope_args} ${selection} ${contribution_ipo} ${contribution_backend_args}
                        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
                set_tests_properties(${scalar_test} PROPERTIES TIMEOUT 300)
            endforeach()
        endforeach()
    endforeach()
endforeach()
add_custom_target(pyobf_native_measure_contribution_scalars
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
        "${PROJECT_BINARY_DIR}/tests/contribution" none --scalars all --bogus all --composed all
        --frames both --call-steps --preparations all --ssa-source --grouped --automatic
        "--scalar-measurements=${PROJECT_BINARY_DIR}/tests/contribution/scalar.measurements.json"
        ${contribution_backend_args}
        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}"
    DEPENDS pyobf_native_cff
    VERBATIM)
add_custom_target(pyobf_native_measure_contribution_cost
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
        "${PROJECT_BINARY_DIR}/tests/contribution" none --scalars all --bogus all --composed all
        --frames both --call-steps --preparations all --ssa-source --grouped --automatic
        "--contribution-measurements=${PROJECT_BINARY_DIR}/tests/contribution/contribution.measurements.json"
        ${contribution_backend_args}
        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}"
    DEPENDS pyobf_native_cff
    VERBATIM)
foreach(composition cloned framed)
    set(extra_args --scalars all --hybrid --grouped --automatic --composed all --ssa-source --bogus all)
    set(profile none)
    if(composition STREQUAL "framed")
        set(extra_args --scalars all --hybrid --grouped --automatic --composed all --ssa-source
            --bogus bogus-synthesis --frames both --call-steps --preparations all)
        set(profile O2)
    endif()
    set(scalar_test pyobf_native_contribution_scalars_hybrid_${composition})
    add_test(NAME ${scalar_test}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" ${extra_args}
            ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(${scalar_test} PROPERTIES TIMEOUT 300)
endforeach()
get_target_property(contribution_archive_capability pyobf_native_sdk PYOBF_NATIVE_CAN_ARCHIVE)
if(contribution_archive_capability)
    get_target_property(contribution_archive_sources pyobf_native_sdk PYOBF_NATIVE_ARCHIVE_SOURCES)
    set(contribution_archive_args --archive)
    foreach(source IN LISTS contribution_archive_sources)
        list(APPEND contribution_archive_args "--archive-backend-source=${source}")
    endforeach()
    foreach(profile none O2)
        foreach(mode explicit automatic)
            set(selection "")
            if(mode STREQUAL "automatic")
                set(selection --automatic)
            endif()
            foreach(scope whole hybrid)
                set(scope_args "")
                set(scope_label "")
                if(scope STREQUAL "hybrid")
                    set(scope_args --hybrid)
                    set(scope_label "hybrid_")
                endif()
                set(archive_test pyobf_native_contribution_archive_${scope_label}${mode}_${profile})
                add_test(NAME ${archive_test}
                    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                        "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" ${contribution_archive_args}
                        ${scope_args} ${selection} ${contribution_ipo} ${contribution_backend_args}
                        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
                set_tests_properties(${archive_test} PROPERTIES TIMEOUT 300)
            endforeach()
        endforeach()
    endforeach()
    foreach(composition grouped composed_none composed_O2 hybrid_grouped hybrid_composed_none hybrid_composed_O2)
        set(extra_args --grouped --automatic)
        string(REGEX REPLACE "^hybrid_" "" variant "${composition}")
        if(composition MATCHES "^hybrid_")
            list(APPEND extra_args --hybrid)
        endif()
        set(profile O2)
        if(variant MATCHES "^composed_")
            string(REPLACE "composed_" "" profile "${variant}")
            list(APPEND extra_args --scalars all --bogus all --composed all --frames both
                --call-steps --preparations all --ssa-source)
            if(composition MATCHES "^hybrid_")
                list(APPEND extra_args --hybrid-normalizers all)
            endif()
        endif()
        set(archive_test pyobf_native_contribution_archive_${composition})
        add_test(NAME ${archive_test}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" ${contribution_archive_args}
                ${extra_args} ${contribution_ipo} ${contribution_backend_args}
                --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
        set_tests_properties(${archive_test} PROPERTIES TIMEOUT 300)
    endforeach()
endif()
foreach(profile none O2)
    add_test(NAME pyobf_native_contribution_scalars_composed_${profile}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --scalars all
            --bogus all --composed all --frames both --call-steps --preparations all
            --ssa-source --grouped --automatic ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(pyobf_native_contribution_scalars_composed_${profile} PROPERTIES TIMEOUT 300)
endforeach()
