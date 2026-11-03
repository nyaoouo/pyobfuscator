# Normalizers remain separate strategies; this matrix reuses real CNG/EH execution.
foreach(profile none O2)
    foreach(component common-exit deduplicate-blocks split-blocks all)
        foreach(selection explicit automatic)
            set(extra --hybrid --hybrid-normalizers ${component})
            if(selection STREQUAL "automatic")
                list(APPEND extra --automatic)
            endif()
            set(test pyobf_native_contribution_hybrid_normalizers_${component}_${selection}_${profile})
            add_test(NAME ${test}
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                    "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                    "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                    "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" ${extra}
                    ${contribution_ipo} ${contribution_backend_args}
                    --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
            set_tests_properties(${test} PROPERTIES TIMEOUT 300)
        endforeach()
    endforeach()
    foreach(variant grouped framed composed)
        set(extra --hybrid --hybrid-normalizers all --automatic)
        if(NOT variant STREQUAL "framed")
            list(APPEND extra --grouped)
        endif()
        if(NOT variant STREQUAL "grouped")
            list(APPEND extra --frames both --call-steps)
        endif()
        if(variant STREQUAL "composed")
            list(APPEND extra --scalars all --composed all --bogus bogus-synthesis --ssa-source --preparations all)
        endif()
        set(test pyobf_native_contribution_hybrid_normalizers_${variant}_${profile})
        add_test(NAME ${test}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" ${extra}
                ${contribution_ipo} ${contribution_backend_args}
                --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
        set_tests_properties(${test} PROPERTIES TIMEOUT 300)
    endforeach()
endforeach()
