include(cmake/Configure.cmake)
include(cmake/ReleaseChecks.cmake)

set(path_fold_ipo "")
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    list(APPEND path_fold_ipo --ipo)
endif()
include(cmake/ContributionChecks.cmake)
add_test(NAME pyobf_native_demo_cff_path_fold_sites
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_path_fold_sites.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}" ${path_fold_ipo})
set_tests_properties(pyobf_native_demo_cff_path_fold_sites PROPERTIES TIMEOUT 240)

if(TARGET pyobf_native_cff_path_fold_fixture)
    add_test(NAME pyobf_native_demo_cff_path_fold_contract
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_path_fold.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
                "$<TARGET_FILE:pyobf_native_cff_path_fold_fixture>" "${CMAKE_CURRENT_BINARY_DIR}" ${path_fold_ipo})
endif()

if(TARGET pyobf_native_cff_expression_fixture)
    add_test(NAME pyobf_native_demo_cff_expression_contract
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_expressions.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
                "$<TARGET_FILE:pyobf_native_cff_expression_fixture>" "${CMAKE_CURRENT_BINARY_DIR}")
    get_filename_component(expression_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set_tests_properties(pyobf_native_demo_cff_expression_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${expression_runtime_directory}")
endif()

if(TARGET pyobf_native_cff_scalar_fixture)
    add_test(NAME pyobf_native_demo_cff_scalar_contract
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_scalar_expressions.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
                "$<TARGET_FILE:pyobf_native_cff_scalar_fixture>" "${CMAKE_CURRENT_BINARY_DIR}")
    get_filename_component(scalar_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set_tests_properties(pyobf_native_demo_cff_scalar_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${scalar_runtime_directory}")
endif()

include(cmake/ReleaseMaterial.cmake)
pyobf_native_demo_prepare_material(release_material path_events_header path_events "${CMAKE_CURRENT_BINARY_DIR}/release")
include(cmake/PayloadBinding.cmake)
include(cmake/PostRelease.cmake)
include(cmake/IrPipeline.cmake)
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    add_test(NAME pyobf_native_demo_post_mixed_reference
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_post_mixed_reference.py"
            "${release_material}" "${payload_scope_material}" "${payload_mixed_plan}"
            "${payload_binding_reference}")
    add_test(NAME pyobf_native_demo_post_mixed_edge_plan
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/post_two_edge_plan.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${CMAKE_BINARY_DIR}")
    set_tests_properties(pyobf_native_demo_post_mixed_edge_plan PROPERTIES TIMEOUT 90)
    add_test(NAME pyobf_native_demo_post_mixed_real_plan
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/post_two_real_plan.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${CMAKE_BINARY_DIR}" "${cff_input}")
    set_tests_properties(pyobf_native_demo_post_mixed_real_plan PROPERTIES TIMEOUT 90)
    if(PYOBF_NATIVE_DEMO_G3_SUBJECTS)
        add_test(NAME pyobf_native_demo_g3_builder_subjects
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/builder_subject_cases.py"
                "${CMAKE_BINARY_DIR}")
        set_tests_properties(pyobf_native_demo_g3_builder_subjects PROPERTIES TIMEOUT 120)
        if(PYOBF_NATIVE_DEMO_G3_ENTRY_STATES)
            add_test(NAME pyobf_native_demo_g3_builder_entry_states
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/builder_entry_state_cases.py"
                    "${CMAKE_BINARY_DIR}")
            set_tests_properties(pyobf_native_demo_g3_builder_entry_states PROPERTIES TIMEOUT 120)
            if(PYOBF_NATIVE_DEMO_G3_REPLAY)
                add_test(NAME pyobf_native_demo_g3_builder_replay
                    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/builder_replay_cases.py"
                        "${CMAKE_BINARY_DIR}")
                set_tests_properties(pyobf_native_demo_g3_builder_replay PROPERTIES TIMEOUT 120)
            endif()
            if(PYOBF_NATIVE_DEMO_G3_LOCAL_CALLEES)
                add_test(NAME pyobf_native_demo_g3_builder_local_callees
                    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/builder_local_callee_cases.py"
                        "${CMAKE_BINARY_DIR}")
                set_tests_properties(pyobf_native_demo_g3_builder_local_callees PROPERTIES TIMEOUT 120)
                if(PYOBF_NATIVE_DEMO_G3_HELPER_ARGUMENTS)
                    add_test(NAME pyobf_native_demo_g3_builder_helper_arguments
                        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/builder_helper_argument_cases.py"
                            "${CMAKE_BINARY_DIR}")
                    set_tests_properties(pyobf_native_demo_g3_builder_helper_arguments PROPERTIES TIMEOUT 120)
                endif()
            endif()
            if(PYOBF_NATIVE_DEMO_G3_ORIGINAL_PREDICATES)
                add_test(NAME pyobf_native_demo_g3_original_predicates
                    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/builder_original_predicate_cases.py"
                        "${CMAKE_BINARY_DIR}")
                set_tests_properties(pyobf_native_demo_g3_original_predicates PROPERTIES TIMEOUT 180)
            endif()
        endif()
    endif()
    if(PYOBF_NATIVE_DEMO_G3_PARENT_CALLBACK)
        add_test(NAME pyobf_native_demo_g3_parent_callback
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/parent_callback_cases.py"
                "${CMAKE_BINARY_DIR}")
        set_tests_properties(pyobf_native_demo_g3_parent_callback PROPERTIES TIMEOUT 180)
    endif()
    if(PYOBF_NATIVE_DEMO_G3_OUTER_REPLAY)
        add_test(NAME pyobf_native_demo_g3_outer_builder_replay
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/outer_builder_replay_cases.py"
                "${CMAKE_BINARY_DIR}")
        set_tests_properties(pyobf_native_demo_g3_outer_builder_replay PROPERTIES TIMEOUT 300)
    endif()
endif()

if(PYOBF_NATIVE_DEMO_POST_CODE_HASH AND NOT PYOBF_NATIVE_DEMO_POST_MIXED)
    add_test(NAME pyobf_native_demo_post_child_flow
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_post_child_flow.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${cff_input}" "${transformed_ir}" "${cff_report}" "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(pyobf_native_demo_post_child_flow PROPERTIES TIMEOUT 180)
endif()
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    add_test(NAME pyobf_native_demo_post_mixed_source
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/llvm/tests/check_post_mixed_source.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${requested_ir}" "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(pyobf_native_demo_post_mixed_source PROPERTIES TIMEOUT 90)
endif()

add_library(pyobf_native_demo_inner SHARED "${payload_object}")
set_target_properties(pyobf_native_demo_inner PROPERTIES LINKER_LANGUAGE CXX)
if(PYOBF_NATIVE_DEMO_ARCHIVE OR PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    target_link_libraries(pyobf_native_demo_inner PRIVATE ${PYOBF_NATIVE_BACKEND_LINK_LIBRARIES})
endif()

if(NOT PYOBF_NATIVE_CFF_STRATEGY STREQUAL "relative-tree")
    message(FATAL_ERROR "The native demo needs a linked-binary check for this CFF strategy")
endif()
set(linked_cff_report "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.final.json")
set(post_mixed_final_args "")
set(post_mixed_final_dependencies "")
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    list(APPEND post_mixed_final_args
        --post-mixed-plan "${payload_mixed_plan}"
        --post-mixed-private "${payload_binding_reference}"
        --post-mixed-material "${release_material}"
        --post-mixed-scoped "${payload_scope_material}")
    list(APPEND post_mixed_final_dependencies "${payload_mixed_plan}" "${payload_binding_reference}"
        "${release_material}" "${payload_scope_material}"
        cff_source_mixed_bounded_site_map.py "${PROJECT_SOURCE_DIR}/tools/post_mixed_binding.py")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cff_post_mixed_final.py")
        list(APPEND post_mixed_final_dependencies cff_post_mixed_final.py)
    endif()
    if(PYOBF_NATIVE_DEMO_BUILDER_RECEIPT)
        # The builder invokes this target explicitly after linking the inner DLL.
        # Keep it out of the finalizer DAG so changed inputs cannot refresh trust.
        set(freeze_receipt_command "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_receipt.py" create
            --image "$<TARGET_FILE:pyobf_native_demo_inner>"
            --report "${cff_report}"
            --private "${payload_binding_reference}"
            --plan "${payload_mixed_plan}"
            --input-ir "${cff_input}"
            --object "${payload_object}"
            --output "${PYOBF_NATIVE_DEMO_BUILDER_RECEIPT}")
        set(freeze_receipt_dependencies "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_receipt.py")
        if(PYOBF_NATIVE_DEMO_G3_REPLAY)
            set(builder_replay_record "${CMAKE_BINARY_DIR}/builder.replay.json")
            pyobf_native_compiler_arguments(replay_clang_args)
            list(APPEND replay_clang_args -ffunction-sections -O0 -fno-lto)
            set(freeze_receipt_command "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_replay.py"
                --opt-exe "${PYOBF_NATIVE_OPT_EXECUTABLE}"
                --clang-exe "${CMAKE_CXX_COMPILER}"
                --pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
                --input-ir "${cff_input}"
                --transformed-ir "${transformed_ir}"
                --report "${cff_report}"
                --request-manifest "${request_manifest}"
                --recipe "${payload_binding_recipe}"
                --private "${payload_binding_reference}"
                --plan "${payload_mixed_plan}"
                --object "${payload_object}"
                --image "$<TARGET_FILE:pyobf_native_demo_inner>"
                --replay-record "${builder_replay_record}"
                --receipt "${PYOBF_NATIVE_DEMO_BUILDER_RECEIPT}")
            foreach(replay_arg IN LISTS cff_selection_args PYOBF_DEMO_CFF_MAP_ARGS
                    payload_binding_args mixed_edge_args)
                list(APPEND freeze_receipt_command "--opt-arg=${replay_arg}")
            endforeach()
            list(APPEND freeze_receipt_command
                "--opt-arg=-pyobf-cff-require-decision-flow=${PYOBF_DEMO_CFF_REQUIRE_DECISION_FLOW}")
            foreach(replay_arg IN LISTS replay_clang_args)
                list(APPEND freeze_receipt_command "--clang-arg=${replay_arg}")
            endforeach()
            list(APPEND freeze_receipt_dependencies "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_replay.py"
                "${transformed_ir}" "${request_manifest}" "${payload_binding_recipe}"
                pyobf_native_cff "${PYOBF_NATIVE_OPT_EXECUTABLE}" "${CMAKE_CXX_COMPILER}")
        endif()
        add_custom_target(pyobf_native_demo_freeze_builder_receipt
            COMMAND ${freeze_receipt_command}
            DEPENDS pyobf_native_demo_inner "${cff_report}" "${payload_binding_reference}"
                "${payload_mixed_plan}" "${cff_input}" "${payload_object}"
                ${freeze_receipt_dependencies}
            VERBATIM)
        list(APPEND post_mixed_final_args
            --builder-receipt "${PYOBF_NATIVE_DEMO_BUILDER_RECEIPT}"
            --builder-input-ir "${cff_input}"
            --builder-object "${payload_object}")
        list(APPEND post_mixed_final_dependencies
            "${PYOBF_NATIVE_DEMO_BUILDER_RECEIPT}" "${cff_input}"
            "${payload_object}" cff_builder_receipt.py)
        if(PYOBF_NATIVE_DEMO_G3_SUBJECTS)
            list(APPEND post_mixed_final_args --builder-subjects)
            list(APPEND post_mixed_final_dependencies cff_builder_subjects.py)
            if(PYOBF_NATIVE_DEMO_G3_ENTRY_STATES)
                list(APPEND post_mixed_final_args --builder-entry-states)
                list(APPEND post_mixed_final_dependencies cff_builder_entry_states.py)
                if(PYOBF_NATIVE_DEMO_G3_LOCAL_CALLEES)
                    list(APPEND post_mixed_final_args
                        --builder-local-callees --builder-local-callees-seed "${PYOBF_NATIVE_CFF_SEED}")
                    list(APPEND post_mixed_final_dependencies
                        "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_local_callees.py")
                    if(PYOBF_NATIVE_DEMO_G3_HELPER_ARGUMENTS)
                        list(APPEND post_mixed_final_args --builder-helper-arguments)
                        list(APPEND post_mixed_final_dependencies
                            "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_helper_arguments.py")
                        if(PYOBF_NATIVE_DEMO_G3_BINDING_STATUS_EFFECTS)
                            list(APPEND post_mixed_final_args --builder-binding-status-effects)
                            list(APPEND post_mixed_final_dependencies
                                "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_binding_status_effects.py")
                            add_test(NAME pyobf_native_demo_g3_binding_status_effects
                                COMMAND "${Python3_EXECUTABLE}"
                                    "${PROJECT_SOURCE_DIR}/tests/contribution/builder_binding_status_effects_cases.py"
                                    "${CMAKE_BINARY_DIR}")
                            set_tests_properties(pyobf_native_demo_g3_binding_status_effects PROPERTIES TIMEOUT 300)
                            if(PYOBF_NATIVE_DEMO_G3_CONTEXT_AVAILABILITY_EFFECT)
                                list(APPEND post_mixed_final_args --builder-context-availability-effect)
                                list(APPEND post_mixed_final_dependencies
                                    "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_context_availability.py")
                                add_test(NAME pyobf_native_demo_g3_context_availability_effect
                                    COMMAND "${Python3_EXECUTABLE}"
                                        "${PROJECT_SOURCE_DIR}/tests/contribution/builder_context_availability_cases.py"
                                        "${CMAKE_BINARY_DIR}")
                                set_tests_properties(pyobf_native_demo_g3_context_availability_effect PROPERTIES TIMEOUT 300)
                                if(PYOBF_NATIVE_DEMO_G3_BOUND_CALL)
                                    list(APPEND post_mixed_final_args --builder-bound-call)
                                    list(APPEND post_mixed_final_dependencies
                                        "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_bound_call.py")
                                    add_test(NAME pyobf_native_demo_g3_bound_call
                                        COMMAND "${Python3_EXECUTABLE}"
                                            "${PROJECT_SOURCE_DIR}/tests/contribution/builder_bound_call_cases.py"
                                            "${CMAKE_BINARY_DIR}")
                                    set_tests_properties(pyobf_native_demo_g3_bound_call PROPERTIES TIMEOUT 300)
                                    if(PYOBF_NATIVE_DEMO_G3_RETAIN_LOCAL)
                                        list(APPEND post_mixed_final_args --builder-retain-local)
                                        list(APPEND post_mixed_final_dependencies
                                            "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_retain_local.py")
                                        add_test(NAME pyobf_native_demo_g3_retain_local
                                            COMMAND "${Python3_EXECUTABLE}"
                                                "${PROJECT_SOURCE_DIR}/tests/contribution/builder_retain_local_cases.py"
                                                "${CMAKE_BINARY_DIR}")
                                        set_tests_properties(pyobf_native_demo_g3_retain_local PROPERTIES TIMEOUT 300)
                                        if(PYOBF_NATIVE_DEMO_G3_INVOKE_LOCAL)
                                            list(APPEND post_mixed_final_args --builder-invoke-local)
                                            list(APPEND post_mixed_final_dependencies
                                                "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_invoke_local.py")
                                            add_test(NAME pyobf_native_demo_g3_invoke_local
                                                COMMAND "${Python3_EXECUTABLE}"
                                                    "${PROJECT_SOURCE_DIR}/tests/contribution/builder_invoke_local_cases.py"
                                                    "${CMAKE_BINARY_DIR}")
                                            set_tests_properties(pyobf_native_demo_g3_invoke_local PROPERTIES TIMEOUT 300)
                                        endif()
                                    endif()
                                endif()
                            endif()
                        endif()
                    endif()
                endif()
                if(PYOBF_NATIVE_DEMO_G3_REPLAY)
                    list(APPEND post_mixed_final_args
                        --builder-replay-record "${builder_replay_record}"
                        --builder-transformed-ir "${transformed_ir}"
                        --builder-request-manifest "${request_manifest}"
                        --builder-recipe "${payload_binding_recipe}"
                        --builder-opt-exe "${PYOBF_NATIVE_OPT_EXECUTABLE}"
                        --builder-clang-exe "${CMAKE_CXX_COMPILER}"
                        --builder-pass-plugin "$<TARGET_FILE:pyobf_native_cff>")
                    list(APPEND post_mixed_final_dependencies
                        "${builder_replay_record}" "${transformed_ir}" "${request_manifest}"
                        "${payload_binding_recipe}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
                        "${CMAKE_CXX_COMPILER}" pyobf_native_cff
                        "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_replay.py")
                endif()
                if(PYOBF_NATIVE_DEMO_G3_ORIGINAL_PREDICATES)
                    list(APPEND post_mixed_final_args --builder-original-predicates)
                    list(APPEND post_mixed_final_dependencies
                        "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_original_predicates.py")
                endif()
            endif()
        endif()
    endif()
endif()
if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN)
    set(archive_origin_prefix "${CMAKE_CURRENT_BINARY_DIR}/payload.archive")
    set(archive_origin_roles
        "optimized_ir=${archive_optimized_ir}"
        "archive_plan=${archive_origin_prefix}.plan.json"
        "pending_ir=${archive_origin_prefix}.pending.ll"
        "package=${archive_origin_prefix}.bin"
        "generated_cpp=${archive_origin_prefix}.cpp"
        "bindings=${archive_origin_prefix}.bindings.json"
        "source_requests=${archive_source_requests}"
        "runtime_requested_ir=${archive_origin_prefix}.runtime.requested.ll"
        "runtime_requests=${archive_origin_prefix}.runtime.requests.json"
        "merged_requests=${request_manifest}"
        "linked_ir=${archive_origin_prefix}.linked.ll"
        "prepared_ir=${cff_input}"
        "recipe=${payload_binding_recipe}"
        "opt_exe=${PYOBF_NATIVE_OPT_EXECUTABLE}"
        "llvm_link_exe=${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}"
        "pass_plugin=$<TARGET_FILE:pyobf_native_cff>"
        "pack_tool_source=${PROJECT_SOURCE_DIR}/tools/pack_archive.py"
        "archive_format_source=${PROJECT_SOURCE_DIR}/tools/archive_format.py"
        "merge_requests_source=${PROJECT_SOURCE_DIR}/tools/merge_requests.py"
        "child_replay_record=${builder_replay_record}")
    set(archive_origin_role_args "")
    set(archive_origin_final_args "")
    set(archive_origin_dependencies "")
    foreach(role IN LISTS archive_origin_roles)
        list(APPEND archive_origin_role_args "--role=${role}")
        list(APPEND archive_origin_final_args "--archive-origin-role=${role}")
        string(REGEX REPLACE "^[^=]+=" "" role_path "${role}")
        list(APPEND archive_origin_dependencies "${role_path}")
    endforeach()
    set(archive_origin_opt_args "")
    foreach(option IN LISTS cff_selection_args)
        list(APPEND archive_origin_opt_args "--plan-opt-arg=${option}")
    endforeach()
    add_custom_target(pyobf_native_demo_freeze_archive_origin
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cff_archive_origin.py" freeze
            --record "${PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN_RECORD}"
            ${archive_origin_role_args} ${archive_origin_opt_args}
        DEPENDS ${archive_origin_dependencies}
            "${CMAKE_CURRENT_SOURCE_DIR}/cff_archive_origin.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/cff_archive_origin_contract.py"
        VERBATIM)
    add_test(NAME pyobf_native_demo_g3_archive_origin
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/archive_origin_cases.py"
            "${CMAKE_BINARY_DIR}")
    # This test temporarily mutates and restores shared archive input files.
    set_tests_properties(pyobf_native_demo_g3_archive_origin PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    if(PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR)
        add_custom_target(pyobf_native_demo_freeze_o2_predecessor
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_o2_predecessor.py" freeze
                --record "${PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR_RECORD}"
                --requested-ir "${requested_ir}"
                --optimized-ir "${archive_optimized_ir}"
                --opt-exe "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            DEPENDS "${requested_ir}" "${archive_optimized_ir}"
                "${PYOBF_NATIVE_OPT_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_o2_predecessor.py"
            VERBATIM)
        list(APPEND post_mixed_final_args
            --builder-o2-predecessor-record "${PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR_RECORD}"
            --builder-o2-requested-ir "${requested_ir}"
            --builder-o2-optimized-ir "${archive_optimized_ir}"
            --builder-o2-opt-exe "${PYOBF_NATIVE_OPT_EXECUTABLE}")
        list(APPEND post_mixed_final_dependencies
            "${PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR_RECORD}"
            "${requested_ir}" "${archive_optimized_ir}"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_o2_predecessor.py")
        add_test(NAME pyobf_native_demo_g3_o2_predecessor
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/contribution/builder_o2_predecessor_cases.py"
                "${CMAKE_BINARY_DIR}")
        set_tests_properties(pyobf_native_demo_g3_o2_predecessor PROPERTIES TIMEOUT 300)
    endif()
    if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION)
        list(APPEND post_mixed_final_args --builder-archive-publication)
        list(APPEND post_mixed_final_dependencies
            "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_archive_publication.py")
        add_test(NAME pyobf_native_demo_g3_archive_publication
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/contribution/builder_archive_publication_cases.py"
                "${CMAKE_BINARY_DIR}")
        set_tests_properties(pyobf_native_demo_g3_archive_publication PROPERTIES TIMEOUT 300)
        if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_DECODER_LINKAGE)
            list(APPEND post_mixed_final_args --builder-archive-decoder-linkage)
            list(APPEND post_mixed_final_dependencies
                "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_archive_decoder_linkage.py")
            add_test(NAME pyobf_native_demo_g3_archive_decoder_linkage
                COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/contribution/builder_archive_decoder_linkage_cases.py"
                    "${CMAKE_BINARY_DIR}")
            set_tests_properties(pyobf_native_demo_g3_archive_decoder_linkage PROPERTIES TIMEOUT 300)
            if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_FIRST_USE_ARM)
                list(APPEND post_mixed_final_args --builder-archive-first-use-arm)
                list(APPEND post_mixed_final_dependencies
                    "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_archive_first_use.py")
                add_test(NAME pyobf_native_demo_g3_archive_first_use_arm
                    COMMAND "${Python3_EXECUTABLE}"
                        "${PROJECT_SOURCE_DIR}/tests/contribution/builder_archive_first_use_cases.py"
                        "${CMAKE_BINARY_DIR}")
                set_tests_properties(pyobf_native_demo_g3_archive_first_use_arm PROPERTIES TIMEOUT 300)
                if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_ENTRY_ROUTE)
                    list(APPEND post_mixed_final_args --builder-archive-entry-route)
                    list(APPEND post_mixed_final_dependencies
                        "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_archive_entry_route.py")
                    add_test(NAME pyobf_native_demo_g3_archive_entry_route
                        COMMAND "${Python3_EXECUTABLE}"
                            "${PROJECT_SOURCE_DIR}/tests/contribution/builder_archive_entry_route_cases.py"
                            "${CMAKE_BINARY_DIR}")
                    set_tests_properties(pyobf_native_demo_g3_archive_entry_route PROPERTIES TIMEOUT 300)
                endif()
            endif()
        endif()
        if(PYOBF_NATIVE_DEMO_G3_O2_ORIGINAL_PREDICATES)
            list(APPEND post_mixed_final_args --builder-o2-original-predicates)
            list(APPEND post_mixed_final_dependencies
                "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_o2_original_predicates.py")
            add_test(NAME pyobf_native_demo_g3_o2_original_predicates
                COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/contribution/builder_o2_original_predicate_cases.py"
                    "${CMAKE_BINARY_DIR}")
            set_tests_properties(pyobf_native_demo_g3_o2_original_predicates PROPERTIES TIMEOUT 300)
        endif()
    endif()
    list(APPEND post_mixed_final_args
        --archive-origin-record "${PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN_RECORD}"
        ${archive_origin_final_args})
    list(APPEND post_mixed_final_dependencies
        "${PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN_RECORD}"
        ${archive_origin_dependencies}
        "${CMAKE_CURRENT_SOURCE_DIR}/cff_archive_origin.py"
        "${CMAKE_CURRENT_SOURCE_DIR}/cff_archive_origin_contract.py")
endif()
add_custom_command(
    OUTPUT "${linked_cff_report}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_demo_inner>" "${cff_report}"
            --output "${linked_cff_report}" ${post_mixed_final_args}
    DEPENDS pyobf_native_demo_inner "${cff_report}" ${post_mixed_final_dependencies} check_linked_cff.py cff_transition_evidence.py cff_data_evidence.py cff_archive_evidence.py cff_reference_evidence.py cff_frame_evidence.py cff_preparation_evidence.py cff_local_evidence.py cff_external_evidence.py cff_import_evidence.py cff_path_fold_evidence.py cff_contribution_evidence.py cff_contribution_groups.py
    VERBATIM)

include(cmake/Packaging.cmake)
include(cmake/MeasuredRelease.cmake)
include(cmake/DecoyPipeline.cmake)
include(cmake/DecoyChecks.cmake)

set(bootstrap_sources
    bootstrap/entry.cpp
    bootstrap/config.cpp
    bootstrap/environment.cpp
    bootstrap/release.cpp
    bootstrap/key_material.cpp
    bootstrap/key_expansion.cpp
    bootstrap/failed_release.cpp
    bootstrap/bridge.cpp
    bootstrap/session.cpp
    bootstrap/lifecycle.cpp
    bootstrap/contribution.cpp
    bootstrap/contribution_snapshot.cpp
    "${PROJECT_SOURCE_DIR}/src/contribution/context_derive.cpp"
    bootstrap/support.cpp
    bootstrap/buffer.cpp)
include(cmake/OuterPipeline.cmake)
pyobf_native_demo_add_outer(pyobf_native_demo_outer)
pyobf_native_demo_add_outer(pyobf_native_demo_outer_triggered
    DEFINITIONS PYOBF_DEMO_FORCE_TRIGGERED=1 PYOBF_NATIVE_TEST_DETECTORS=1
    ENVIRONMENT_SOURCES ${PYOBF_NATIVE_BACKEND_TEST_ENVIRONMENT_SOURCES})
include(cmake/DecoyRuntime.cmake)
get_target_property(demo_outer_image pyobf_native_demo_outer PYOBF_NATIVE_FINAL_IMAGE)
get_target_property(demo_triggered_image pyobf_native_demo_outer_triggered PYOBF_NATIVE_FINAL_IMAGE)
pyobf_native_demo_add_release_plan_check()
if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH)
    pyobf_native_demo_add_measured_release_checks()
endif()
include(cmake/PostReleaseChecks.cmake)
include(cmake/PayloadBindingChecks.cmake)
include(cmake/SessionChecks.cmake)
include(cmake/ContributionSessionChecks.cmake)

add_executable(pyobf_native_demo_environment_smoke
    environment_smoke.cpp "${PROJECT_SOURCE_DIR}/src/environment.cpp"
    ${PYOBF_NATIVE_BACKEND_ENVIRONMENT_SOURCES}
    ${PYOBF_NATIVE_BACKEND_TEST_ENVIRONMENT_SOURCES})
target_compile_definitions(pyobf_native_demo_environment_smoke PRIVATE
    PYOBF_NATIVE_TEST_DETECTORS=1)
target_include_directories(pyobf_native_demo_environment_smoke PRIVATE "${PROJECT_SOURCE_DIR}/include")
add_test(NAME pyobf_native_demo_environment_registry
    COMMAND pyobf_native_demo_environment_smoke)

add_executable(pyobf_native_demo_smoke smoke.cpp)
if(PYOBF_NATIVE_DEMO_OUTER_CFF)
    set(outer_failure_args "")
    set(outer_failure_sources ${PYOBF_NATIVE_BACKEND_SYSTEM_SOURCES} ${PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES})
    if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH OR PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        get_target_property(measured_backend pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_BACKEND_SOURCES)
        list(APPEND outer_failure_sources ${measured_backend})
    endif()
    list(REMOVE_DUPLICATES outer_failure_sources)
    foreach(source IN LISTS outer_failure_sources)
        list(APPEND outer_failure_args "--backend-source=${source}")
    endforeach()
    foreach(library IN LISTS PYOBF_NATIVE_BACKEND_LINK_LIBRARIES)
        list(APPEND outer_failure_args "--library=${library}")
    endforeach()
    if(NOT PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE)
        list(APPEND outer_failure_args --blocked)
    endif()
    set(outer_measured_args "")
    if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH OR PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        pyobf_native_demo_measured_arguments(outer_measured_args pyobf_native_demo_outer)
    endif()
    add_test(NAME pyobf_native_demo_outer_cff_failures
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_outer_failures.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py"
                "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.combined.ll"
                "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.coverage.json"
                "${PYOBF_NATIVE_OUTER_CFF_CONFIG}" "$<TARGET_FILE:pyobf_native_demo_smoke>"
                "${CMAKE_CURRENT_BINARY_DIR}" "${release_record_blob}" ${outer_failure_args} ${outer_measured_args})
    get_filename_component(outer_compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set_tests_properties(pyobf_native_demo_outer_cff_failures PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${outer_compiler_directory}")
    if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        set(post_role_input "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.requested.ll")
        if(PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT STREQUAL "O2")
            set(post_role_input "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.optimized.ll")
        endif()
        add_test(NAME pyobf_native_demo_post_role_flow
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_post_role_flow.py"
                "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
                "${post_role_input}" "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.requests.json"
                "${PYOBF_NATIVE_OUTER_CFF_CONFIG}" "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.coverage.json"
                "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer_unfinalized.reference-plan.private.json"
                "${CMAKE_CURRENT_BINARY_DIR}" "${PYOBF_NATIVE_CFF_SEED}")
        set_tests_properties(pyobf_native_demo_post_role_flow PROPERTIES TIMEOUT 300
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${outer_compiler_directory}")
    endif()
endif()
include(cmake/DecoyRuntimeChecks.cmake)
include(cmake/BootstrapMeasurements.cmake)
if(PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE)
    set(demo_policy_test pyobf_native_demo_smoke)
    set(post_smoke_args "")
    if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        list(APPEND post_smoke_args post)
    endif()
    add_test(NAME ${demo_policy_test}
        COMMAND pyobf_native_demo_smoke "${demo_outer_image}" ${post_smoke_args})
else()
    set(demo_policy_test pyobf_native_demo_unavailable_blocked)
    add_test(NAME ${demo_policy_test}
        COMMAND pyobf_native_demo_smoke "${demo_outer_image}" triggered)
endif()
add_test(NAME pyobf_native_demo_cff_coverage_and_shape
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff.py"
            "${transformed_ir}" "${cff_report}"
            "${PYOBF_NATIVE_CFF_STRATEGY}" "${PYOBF_DEMO_CFF_FUNCTIONS}"
            "${PYOBF_DEMO_CFF_MARKERS}" --requests "${request_manifest}")
add_test(NAME pyobf_native_demo_cff_fail_closed
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_failures.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${payload_ir}")
set(marker_fixture_args "")
set(payload_scope_check_args "")
if(PYOBF_NATIVE_DEMO_PAYLOAD_BINDING STREQUAL "strict")
    list(APPEND payload_scope_check_args --strict-payload)
endif()
list(APPEND marker_fixture_args ${payload_scope_check_args})
set(payload_variation_ir "${payload_ir}")
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    list(APPEND marker_fixture_args --post-input "${payload_binding_recipe}" "${payload_binding_reference}")
    list(APPEND payload_scope_check_args --post-input "${payload_binding_recipe}" "${payload_binding_reference}")
    set(payload_variation_ir "${combined_ir}")
endif()
if(PYOBF_NATIVE_DEMO_ASSET)
    list(APPEND marker_fixture_args --asset)
    get_filename_component(asset_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    add_test(NAME pyobf_native_demo_asset
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/check_archive_pipeline.py"
                --probe-demo "$<TARGET_FILE:pyobf_native_demo_inner>" "${PYOBF_NATIVE_DEMO_ASSET}"
                "${asset_runtime_directory}")
endif()
add_test(NAME pyobf_native_demo_cff_markers
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_markers.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${combined_ir}" ${marker_fixture_args})
add_test(NAME pyobf_native_demo_cff_switch
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_switch.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_ssa
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_ssa.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_tiny
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_tiny.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_region
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_region.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_deep_constants
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_deep_constants.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_deep_calls
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_deep_calls.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_deep_decoys
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_deep_decoys.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_optimization_order
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_optimization.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py"
            "${PROJECT_SOURCE_DIR}/include" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_requests
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_requests.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${request_manifest}" "${cff_report}" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_recipes
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_recipes.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_split
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_split.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_normalization
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_normalization.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_transition_depth
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_transition_depth.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_bogus
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_bogus.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_typed_data
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_typed_data.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_references
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_references.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_frames
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_frames.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_nonlocal
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_nonlocal.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_hybrid_eh
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_hybrid_eh.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_hybrid_final
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_hybrid_final.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_frame_abi_retention
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_frame_abi_retention.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_hybrid_project
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_hybrid_project.py"
            "${CMAKE_COMMAND}" "${CMAKE_MAKE_PROGRAM}" "${CMAKE_CXX_COMPILER}"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_hybrid_backend
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_external_backend.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}" --hybrid)
add_test(NAME pyobf_native_demo_cff_hybrid_frames
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_hybrid_frames.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py"
            "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_hybrid_frame_backend
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_external_backend.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}" --hybrid --hybrid-frames)
add_test(NAME pyobf_native_demo_cff_hybrid_import_backend
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_external_backend.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}" --hybrid --hybrid-frames --imports)
add_test(NAME pyobf_native_demo_cff_frame_profiles
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_frame_profiles.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_imports
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_imports.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_import_backend
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_external_backend.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}" --imports)
add_test(NAME pyobf_native_demo_cff_external
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_external.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_external_backend
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_external_backend.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_preparation
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_preparation.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_preparation_edges
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_preparation_edges.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_locals
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_locals.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_local_edges
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_local_edges.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_local_sdk
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_local_sdk.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_variation
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_variation.py"
            "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${payload_variation_ir}" ${payload_scope_check_args})
add_test(NAME pyobf_native_demo_cff_wrong_state
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_wrong_state.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME pyobf_native_demo_cff_linked_shape
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_demo_inner>" "${cff_report}")
add_test(NAME pyobf_native_demo_cff_final_report
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_final_report.py"
            "${linked_cff_report}" "${cff_report}"
            "$<TARGET_FILE:pyobf_native_demo_inner>"
            "${demo_outer_image}"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py"
            "${CMAKE_CURRENT_BINARY_DIR}" --requests "${request_manifest}")
include(cmake/PayloadMeasurements.cmake)
add_custom_target(pyobf_native_demo_measure_marker_cost
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_marker_cost.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/marker_cost.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.marker_cost.json"
    DEPENDS measure_marker_cost.py marker_cost.cpp measure_cff.cpp
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_region
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_region.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.region.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_region.py check_cff_region.py
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_split
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_split.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.split.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_split.py check_cff_split.py measure_cff.cpp
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_normalization
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_normalization.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.normalization.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_normalization.py check_cff_normalization.py measure_cff.cpp
    VERBATIM)
add_test(NAME pyobf_native_demo_blocked_before_decrypt
    COMMAND pyobf_native_demo_smoke
            "${demo_triggered_image}" triggered)
add_custom_target(pyobf_native_demo_measure_cff_misleading
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_misleading.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.misleading.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_misleading.py check_cff_split.py measure_cff.cpp
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_typed_data
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_typed_data.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.typed.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_typed_data.py measure_cff.cpp
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_archive
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_archive.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_archive.cpp"
            "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/payload.archive.measurements.json"
    DEPENDS pyobf_native_cff measure_archive.py archive_measure_build.py archive_measure_input.py measure_archive.cpp
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_references
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_references.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.references.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_references.py measure_cff.cpp check_linked_cff.py cff_reference_evidence.py
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_hybrid
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_hybrid.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.hybrid.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_hybrid.py measure_cff_hybrid.cpp measure_cff_hybrid_fixture.cpp
            measure_cff.py check_linked_cff.py
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_frames
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_frames.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.frames.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_frames.py measure_cff_references.py measure_cff.cpp
            check_linked_cff.py cff_frame_evidence.py cff_reference_evidence.py
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_preparation
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_preparation.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.preparation.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_preparation.py measure_cff_references.py measure_cff.cpp
            check_linked_cff.py cff_preparation_evidence.py cff_frame_evidence.py cff_reference_evidence.py
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_locals
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_locals.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.locals.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_locals.py measure_cff_references.py measure_cff.cpp
            check_linked_cff.py cff_local_evidence.py cff_preparation_evidence.py cff_frame_evidence.py cff_reference_evidence.py
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_imports
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_imports.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.imports.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_imports.py measure_cff_external.py measure_cff_references.py measure_cff.cpp
            check_linked_cff.py cff_reference_evidence.py cff_import_evidence.py cff_frame_evidence.py cff_external_evidence.py
    VERBATIM)
add_custom_target(pyobf_native_demo_measure_cff_external
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff_external.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
            "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/measure_cff.cpp" "${CMAKE_CURRENT_BINARY_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.external.measurements.json"
    DEPENDS pyobf_native_cff measure_cff_external.py measure_cff_references.py measure_cff.cpp
            check_linked_cff.py cff_frame_evidence.py cff_external_evidence.py cff_preparation_evidence.py
    VERBATIM)
get_filename_component(compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
set_tests_properties(${demo_policy_test} PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_environment_registry PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_blocked_before_decrypt PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_wrong_state PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_switch PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_ssa PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_tiny PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_region PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_deep_constants PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_deep_calls PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_deep_decoys PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_optimization_order PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_recipes PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_split PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_normalization PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_transition_depth PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_bogus PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_typed_data PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_references PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_frames PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_preparation PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_preparation_edges PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
set_tests_properties(pyobf_native_demo_cff_hybrid_eh pyobf_native_demo_cff_hybrid_backend pyobf_native_demo_cff_hybrid_frames
    pyobf_native_demo_cff_hybrid_final
    pyobf_native_demo_cff_frame_abi_retention
    pyobf_native_demo_cff_hybrid_project
    pyobf_native_demo_cff_hybrid_frame_backend
    pyobf_native_demo_cff_hybrid_import_backend
    pyobf_native_demo_cff_frame_profiles
    pyobf_native_demo_cff_nonlocal pyobf_native_demo_cff_imports pyobf_native_demo_cff_import_backend
    pyobf_native_demo_cff_external pyobf_native_demo_cff_external_backend
    pyobf_native_demo_cff_locals pyobf_native_demo_cff_local_edges pyobf_native_demo_cff_local_sdk PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
