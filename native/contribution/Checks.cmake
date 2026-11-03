if(NOT PYOBF_NATIVE_BUILD_SMOKE OR NOT TARGET pyobf_native_cff OR NOT TARGET pyobf_native_contribution_provider
        OR NOT PYOBF_NATIVE_BACKEND_ID STREQUAL "windows_user"
        OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang"
        OR NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
    return()
endif()
get_target_property(contribution_core pyobf_native_bootstrap_context PYOBF_NATIVE_CONTEXT_CORE_SOURCES)
get_target_property(contribution_client pyobf_native_contribution_runtime PYOBF_NATIVE_CONTRIBUTION_CLIENT_SOURCE)
get_target_property(contribution_provider pyobf_native_contribution_provider PYOBF_NATIVE_CONTRIBUTION_PROVIDER_SOURCE)
set(contribution_backends ${PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES} ${PYOBF_NATIVE_BACKEND_SHA256_SOURCES})
list(REMOVE_DUPLICATES contribution_backends)
set(contribution_backend_args "")
foreach(source IN LISTS contribution_backends)
    list(APPEND contribution_backend_args "--backend-source=${source}")
endforeach()
set(contribution_ipo "")
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    list(APPEND contribution_ipo --ipo)
endif()
find_program(PYOBF_CONTRIBUTION_OPT NAMES opt HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(PYOBF_CONTRIBUTION_LINK NAMES llvm-link HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(PYOBF_CONTRIBUTION_OBJDUMP NAMES llvm-objdump HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
if(TARGET pyobf_native_measured_scope AND TARGET pyobf_native_code_observer)
    get_target_property(site_scope_core pyobf_native_measured_scope PYOBF_NATIVE_MEASURED_SCOPE_CORE_SOURCES)
    get_target_property(site_measured_core pyobf_native_measured_contribution PYOBF_NATIVE_MEASURED_CONTRIBUTION_CORE_SOURCES)
    get_target_property(site_release_core pyobf_native_measured_release PYOBF_NATIVE_MEASURED_RELEASE_CORE_SOURCES)
    get_target_property(site_observer_core pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_CORE_SOURCES)
    get_target_property(site_observer_backend pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_BACKEND_SOURCES)
    set(mixed_site_core ${site_scope_core} ${site_measured_core} ${site_release_core} ${site_observer_core}
        ${contribution_core} ${contribution_client} ${contribution_provider}
        "${PROJECT_SOURCE_DIR}/src/contribution/gate.cpp"
        "${PROJECT_SOURCE_DIR}/src/contribution/mixed_gate.cpp")
    list(REMOVE_DUPLICATES mixed_site_core)
    get_filename_component(site_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    foreach(profile none O2)
        add_test(NAME pyobf_native_site_scope_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/site_scope_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}" "${site_runtime_directory}"
                "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}"
                --core ${site_scope_core} ${site_measured_core} ${site_release_core} ${site_observer_core}
                --backend ${site_observer_backend})
        set_tests_properties(pyobf_native_site_scope_cff_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_multi_scope_edge_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/multi_scope_edge_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}" "${site_runtime_directory}"
                "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}"
                --core ${site_scope_core} ${site_measured_core} ${site_release_core} ${site_observer_core}
                --backend ${site_observer_backend})
        set_tests_properties(pyobf_native_multi_scope_edge_cff_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_mixed_site_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/mixed_site_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}" "${site_runtime_directory}"
                "${PROJECT_BINARY_DIR}/tests/contribution" ${profile}
                --core ${mixed_site_core}
                --backend ${site_observer_backend} ${contribution_backends})
        set_tests_properties(pyobf_native_mixed_site_cff_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_source_mixed_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/source_mixed_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}" "${site_runtime_directory}"
                "${PROJECT_BINARY_DIR}/tests/contribution" ${profile}
                --foreign-provider "$<TARGET_FILE:pyobf_native_context_provider>"
                --core ${mixed_site_core}
                --backend ${site_observer_backend} ${contribution_backends})
        set_tests_properties(pyobf_native_source_mixed_cff_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_source_mixed_split_root_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/source_mixed_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}" "${site_runtime_directory}"
                "${PROJECT_BINARY_DIR}/tests/contribution" ${profile}
                --split-root-only --foreign-provider "$<TARGET_FILE:pyobf_native_context_provider>"
                --core ${mixed_site_core}
                --backend ${site_observer_backend} ${contribution_backends})
        set_tests_properties(pyobf_native_source_mixed_split_root_${profile} PROPERTIES TIMEOUT 120)
        foreach(shape wrapper compute)
            add_test(NAME pyobf_native_source_mixed_bounded_${shape}_${profile}
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/source_mixed_bounded_edges.py"
                    "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                    "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}" "${site_runtime_directory}"
                    "${PROJECT_BINARY_DIR}/tests/contribution" ${shape} ${profile}
                    --foreign-provider "$<TARGET_FILE:pyobf_native_context_provider>"
                    --core ${mixed_site_core}
                    --backend ${site_observer_backend} ${contribution_backends})
            set_tests_properties(pyobf_native_source_mixed_bounded_${shape}_${profile} PROPERTIES TIMEOUT 300)
        endforeach()
        if(profile STREQUAL "none")
            add_test(NAME pyobf_native_source_builder_receipt_none
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/source_builder_receipt_cases.py"
                    "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                    "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}" "${site_runtime_directory}"
                    "${PROJECT_BINARY_DIR}/tests/contribution" none
                    --core ${mixed_site_core}
                    --backend ${site_observer_backend} ${contribution_backends})
            set_tests_properties(pyobf_native_source_builder_receipt_none PROPERTIES TIMEOUT 300)
            add_test(NAME pyobf_native_source_mixed_original_edges_none
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/source_mixed_original_edges.py"
                    "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                    "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}" "${site_runtime_directory}"
                    "${PROJECT_BINARY_DIR}/tests/contribution" none
                    --foreign-provider "$<TARGET_FILE:pyobf_native_context_provider>"
                    --core ${mixed_site_core}
                    --backend ${site_observer_backend} ${contribution_backends})
            set_tests_properties(pyobf_native_source_mixed_original_edges_none PROPERTIES TIMEOUT 300)
        endif()
    endforeach()
endif()
add_test(NAME pyobf_native_original_edge_plan
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/original_edge_plan.py"
        "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
        "${PROJECT_BINARY_DIR}/tests/contribution")
foreach(profile none O2)
    foreach(source_kind single grouped)
        set(group_args "")
        if(source_kind STREQUAL "grouped")
            set(group_args --grouped)
        endif()
        foreach(scope whole hybrid)
            set(scope_args "")
            if(scope STREQUAL "hybrid")
                set(scope_args --hybrid)
            endif()
            foreach(mode explicit automatic)
                set(selection "")
                if(mode STREQUAL "automatic")
                    set(selection --automatic)
                endif()
                set(layer_test pyobf_native_contribution_layers_${source_kind}_${scope}_${mode}_${profile})
                add_test(NAME ${layer_test}
                    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                        "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --composed all
                        ${group_args} ${scope_args} ${selection} ${contribution_ipo} ${contribution_backend_args}
                        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
                set_tests_properties(${layer_test} PROPERTIES TIMEOUT 300)
            endforeach()
        endforeach()
    endforeach()
endforeach()
foreach(profile none O2)
    foreach(scope whole hybrid)
        set(scope_args "")
        if(scope STREQUAL "hybrid")
            set(scope_args --hybrid)
        endif()
        foreach(mode explicit automatic)
            set(selection "")
            if(mode STREQUAL "automatic")
                set(selection --automatic)
            endif()
            foreach(source_kind single grouped)
                set(group_args "")
                if(source_kind STREQUAL "grouped")
                    set(group_args --grouped)
                endif()
                set(initializer_test pyobf_native_contribution_initializers_${source_kind}_${scope}_${mode}_${profile})
                set(extra_layers "")
                if(source_kind STREQUAL "grouped" AND scope STREQUAL "hybrid" AND mode STREQUAL "automatic" AND profile STREQUAL "O2")
                    set(extra_layers --composed all)
                endif()
                add_test(NAME ${initializer_test}
                    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                        "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --preparations all
                        ${scope_args} ${selection} ${group_args} ${extra_layers} ${contribution_ipo} ${contribution_backend_args}
                        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
                set_tests_properties(${initializer_test} PROPERTIES TIMEOUT 300)
            endforeach()
        endforeach()
    endforeach()
endforeach()
foreach(strategy opaque-choices reachable-junk decoy-transitions)
    set(layer_test pyobf_native_contribution_layer_${strategy})
    add_test(NAME ${layer_test}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "none" --composed ${strategy}
            ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(${layer_test} PROPERTIES TIMEOUT 300)
endforeach()
foreach(initializer indexed-locals reference-routes import-routes)
    set(initializer_test pyobf_native_contribution_initializer_${initializer})
    add_test(NAME ${initializer_test}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "none" --preparations ${initializer}
            ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(${initializer_test} PROPERTIES TIMEOUT 300)
endforeach()
foreach(profile none O2)
    set(local_test pyobf_native_contribution_initializer_hybrid_local_${profile})
    add_test(NAME ${local_test}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --hybrid --preparations indexed-locals
            ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(${local_test} PROPERTIES TIMEOUT 300)
endforeach()
foreach(kind internal external)
    foreach(profile none O2)
        foreach(scope whole hybrid)
            set(scope_args "")
            if(scope STREQUAL "hybrid")
                set(scope_args --hybrid)
            endif()
            foreach(mode explicit automatic)
                set(selection "")
                if(mode STREQUAL "automatic")
                    set(selection --automatic)
                endif()
                set(group_args "")
                if(profile STREQUAL "none")
                    set(group_args --grouped)
                endif()
                set(frame_test pyobf_native_contribution_frames_${kind}_${scope}_${mode}_${profile})
                add_test(NAME ${frame_test}
                    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                        "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --frames ${kind} --call-steps
                        ${scope_args} ${selection} ${group_args} ${contribution_ipo} ${contribution_backend_args}
                        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
                set_tests_properties(${frame_test} PROPERTIES TIMEOUT 300)
            endforeach()
        endforeach()
    endforeach()
endforeach()
foreach(variant plain composed)
    set(frame_test pyobf_native_contribution_frames_both_${variant})
    set(composition --frame-controls)
    set(profile none)
    if(variant STREQUAL "composed")
        set(composition --call-steps --preparations all --composed all --split --grouped --hybrid --automatic)
        set(profile O2)
    endif()
    add_test(NAME ${frame_test}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --frames both ${composition}
            ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(${frame_test} PROPERTIES TIMEOUT 300)
endforeach()
foreach(profile none O2)
    add_test(NAME pyobf_native_contribution_cff_${profile}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_cff.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(pyobf_native_contribution_cff_${profile} PROPERTIES TIMEOUT 180)
    add_test(NAME pyobf_native_contribution_gates_${profile}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(pyobf_native_contribution_gates_${profile} PROPERTIES TIMEOUT 180)
    add_test(NAME pyobf_native_contribution_edges_${profile}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --automatic ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(pyobf_native_contribution_edges_${profile} PROPERTIES TIMEOUT 240)
    foreach(mode explicit automatic)
        set(selection "")
        if(mode STREQUAL "automatic")
            set(selection --automatic)
        endif()
        add_test(NAME pyobf_native_contribution_hybrid_${mode}_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --hybrid ${selection}
                ${contribution_ipo} ${contribution_backend_args}
                --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
        set_tests_properties(pyobf_native_contribution_hybrid_${mode}_${profile} PROPERTIES TIMEOUT 240)
        add_test(NAME pyobf_native_contribution_region_${mode}_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --region ${selection}
                ${contribution_ipo} ${contribution_backend_args}
                --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
        set_tests_properties(pyobf_native_contribution_region_${mode}_${profile} PROPERTIES TIMEOUT 240)
    endforeach()
    foreach(scope whole hybrid region)
        set(scope_args "")
        if(NOT scope STREQUAL "whole")
            set(scope_args --${scope})
        endif()
        foreach(mode explicit automatic)
            set(selection "")
            if(mode STREQUAL "automatic")
                set(selection --automatic)
            endif()
            add_test(NAME pyobf_native_contribution_groups_${scope}_${mode}_${profile}
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                    "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                    "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                    "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --grouped ${scope_args} ${selection}
                    ${contribution_ipo} ${contribution_backend_args}
                    --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
            set_tests_properties(pyobf_native_contribution_groups_${scope}_${mode}_${profile} PROPERTIES TIMEOUT 300)
        endforeach()
    endforeach()
endforeach()
foreach(component bogus-clones bogus-synthesis)
    foreach(profile none O2)
        foreach(scope whole hybrid)
            set(scope_args "")
            if(scope STREQUAL "hybrid")
                set(scope_args --hybrid --grouped)
            endif()
            foreach(mode explicit automatic)
                set(selection "")
                if(mode STREQUAL "automatic")
                    set(selection --automatic)
                endif()
                set(bogus_test pyobf_native_contribution_${component}_${scope}_${mode}_promoted_${profile})
                add_test(NAME ${bogus_test}
                    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
                        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
                        "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" --bogus ${component} --ssa-source
                        ${selection} ${scope_args} ${contribution_ipo} ${contribution_backend_args}
                        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
                set_tests_properties(${bogus_test} PROPERTIES TIMEOUT 300)
            endforeach()
        endforeach()
    endforeach()
endforeach()
add_test(NAME pyobf_native_contribution_bogus-synthesis_whole_automatic_raw_none
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
        "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
        "${PROJECT_BINARY_DIR}/tests/contribution" "none" --bogus bogus-synthesis --automatic
        ${contribution_ipo} ${contribution_backend_args}
        --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
set_tests_properties(pyobf_native_contribution_bogus-synthesis_whole_automatic_raw_none PROPERTIES TIMEOUT 300)
foreach(composition data frames)
    set(extra_args --bogus all --composed all --literals)
    set(profile none)
    if(composition STREQUAL "frames")
        set(extra_args --bogus bogus-synthesis --composed all --frames both --call-steps --preparations all --hybrid)
        set(profile O2)
    endif()
    set(bogus_test pyobf_native_contribution_bogus_composed_${composition})
    add_test(NAME ${bogus_test}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/check_gates.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CONTRIBUTION_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CONTRIBUTION_LINK}" "${PYOBF_CONTRIBUTION_OBJDUMP}"
            "${PROJECT_BINARY_DIR}/tests/contribution" "${profile}" ${extra_args} --ssa-source --grouped --automatic
            ${contribution_ipo} ${contribution_backend_args}
            --sources ${contribution_core} "${contribution_client}" "${contribution_provider}")
    set_tests_properties(${bogus_test} PROPERTIES TIMEOUT 300)
endforeach()
include("${CMAKE_CURRENT_LIST_DIR}/DataChecks.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/NormalizerChecks.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/HybridNormalizerChecks.cmake")
