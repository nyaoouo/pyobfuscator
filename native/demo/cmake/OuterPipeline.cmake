include_guard(GLOBAL)
include("${PROJECT_SOURCE_DIR}/cmake/LLVMCompile.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/OwnerReaders.cmake")

function(pyobf_native_demo_add_outer target)
    cmake_parse_arguments(OUTER "DECOY" "" "DEFINITIONS;ENVIRONMENT_SOURCES" ${ARGN})
    if(OUTER_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Unknown outer pipeline arguments")
    endif()
    set(authored_sources ${bootstrap_sources}
        "${PROJECT_SOURCE_DIR}/src/environment.cpp"
        ${PYOBF_NATIVE_BACKEND_ENVIRONMENT_SOURCES} ${OUTER_ENVIRONMENT_SOURCES})
    set(configuration "${PYOBF_NATIVE_OUTER_CFF_CONFIG}")
    set(outer_dependencies "${payload_blob}" "${CMAKE_CURRENT_BINARY_DIR}/demo_config.hpp")
    set(coverage_options "")
    if(OUTER_DECOY)
        if(NOT PYOBF_NATIVE_DEMO_DECOY)
            message(FATAL_ERROR "An outer-decoy target needs an independent decoy package")
        endif()
        list(APPEND authored_sources ${decoy_runtime_sources})
        list(APPEND OUTER_DEFINITIONS PYOBF_DEMO_ENABLE_DECOY=1)
        list(APPEND outer_dependencies "${decoy_blob}" "${decoy_events_header}" "${decoy_manifest}")
        set(configuration "${PYOBF_NATIVE_OUTER_DECOY_CFF_CONFIG}")
        list(APPEND coverage_options --decoy)
    endif()
    get_target_property(context_core pyobf_native_bootstrap_context PYOBF_NATIVE_CONTEXT_CORE_SOURCES)
    list(APPEND authored_sources ${context_core})
    set(backend_sources ${PYOBF_NATIVE_BACKEND_SYSTEM_SOURCES} ${PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES})
    list(REMOVE_DUPLICATES backend_sources)
    set(raw_target "${target}_unfinalized")
    set(prefix "${CMAKE_CURRENT_BINARY_DIR}/${target}")
    set(record_target pyobf_native_demo_record)
    set(measured_includes "")
    set(owner_source "")
    if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH OR PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
            pyobf_native_demo_prepare_post_reference(${raw_target} reference_plan reference_directory)
            list(APPEND authored_sources "${CMAKE_CURRENT_SOURCE_DIR}/bootstrap/post_preparation.cpp"
                "${CMAKE_CURRENT_SOURCE_DIR}/bootstrap/post_dispatch.cpp")
            list(APPEND outer_dependencies "${payload_post_profile}")
            list(APPEND OUTER_DEFINITIONS PYOBF_DEMO_POST_CODE_HASH=1)
            if(PYOBF_NATIVE_DEMO_POST_MIXED)
                list(APPEND authored_sources "${CMAKE_CURRENT_SOURCE_DIR}/bootstrap/post_owned_dispatch.cpp")
                list(APPEND outer_dependencies "${payload_mixed_header}")
                list(APPEND OUTER_DEFINITIONS PYOBF_DEMO_POST_MIXED=1)
            endif()
            list(APPEND coverage_options --post-measured)
        else()
            pyobf_native_demo_prepare_code_reference(${raw_target} reference_plan reference_directory)
        endif()
        list(APPEND outer_dependencies "${reference_directory}/reference_slots.hpp")
        pyobf_native_owner_readers("${reference_plan}" "${reference_directory}" owner_source)
        list(APPEND authored_sources "${owner_source}")
        list(APPEND outer_dependencies "${reference_directory}/owner_readers.hpp")
        list(APPEND measured_includes "${reference_directory}")
        get_target_property(observer_core pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_CORE_SOURCES)
        get_target_property(observer_backend pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_BACKEND_SOURCES)
        list(APPEND authored_sources ${observer_core})
        if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH)
            list(APPEND OUTER_DEFINITIONS PYOBF_DEMO_PRE_CODE_HASH=1)
            list(APPEND coverage_options --measured)
            get_target_property(measured_core pyobf_native_measured_release PYOBF_NATIVE_MEASURED_RELEASE_CORE_SOURCES)
            list(APPEND authored_sources "${CMAKE_CURRENT_SOURCE_DIR}/bootstrap/code_key.cpp" ${measured_core})
            set(record_target pyobf_native_demo_measured_record)
        endif()
        list(REMOVE_DUPLICATES authored_sources)
        list(APPEND backend_sources ${observer_backend})
        list(REMOVE_DUPLICATES backend_sources)
    endif()
    if(PYOBF_NATIVE_DEMO_OUTER_CFF OR PYOBF_DEMO_POST_PARENT_KIND EQUAL 3)
        set(units "")
        set(index 0)
        foreach(source IN LISTS authored_sources)
            get_filename_component(source "${source}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
            set(unit "${prefix}.${index}.ll")
            pyobf_native_compile_ir(OUTPUT "${unit}" SOURCE "${source}"
                INCLUDES "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}" ${measured_includes}
                DEFINITIONS ${OUTER_DEFINITIONS} DEPENDS ${outer_dependencies})
            list(APPEND units "${unit}")
            math(EXPR index "${index} + 1")
        endforeach()
        set(combined "${prefix}.combined.ll")
        add_custom_command(OUTPUT "${combined}"
            COMMAND "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" -S ${units} -o "${combined}"
            DEPENDS ${units} VERBATIM)
        if(PYOBF_NATIVE_DEMO_OUTER_CFF)
            set(selection "-pyobf-cff-config=${configuration}"
                "-pyobf-cff-seed=${PYOBF_NATIVE_CFF_SEED}" -pyobf-cff-markers=true)
            set(requested "${prefix}.requested.ll")
            set(requests "${prefix}.requests.json")
            add_custom_command(OUTPUT "${requested}" "${requests}"
                COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
                        -passes=pyobf-native-cff-requests ${selection}
                        "-pyobf-cff-requests-output=${requests}" -verify-each -S "${combined}" -o "${requested}"
                DEPENDS "${combined}" "${configuration}" pyobf_native_cff VERBATIM)
            set(input "${requested}")
            if(PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT STREQUAL "O2")
                set(input "${prefix}.optimized.ll")
                add_custom_command(OUTPUT "${input}"
                    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" "-passes=default<O2>" -verify-each
                            -S "${requested}" -o "${input}"
                    DEPENDS "${requested}" VERBATIM)
            endif()
            set(transformed "${prefix}.cff.ll")
            set(report "${prefix}.coverage.json")
            add_custom_command(OUTPUT "${transformed}" "${report}"
                COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
                        -passes=pyobf-native-cff ${selection} "-pyobf-cff-requests-input=${requests}"
                        "-pyobf-cff-report=${report}" -verify-each -S "${input}" -o "${transformed}"
                DEPENDS "${input}" "${requests}" "${configuration}" pyobf_native_cff VERBATIM)
        else()
            set(transformed "${combined}")
            if(PYOBF_DEMO_POST_PARENT_HELPERS)
                set(report "${prefix}.untransformed-ownership.json")
                pyobf_native_untransformed_ownership("${report}" "${transformed}")
            endif()
        endif()
        set(object "${prefix}.obj")
        set(emission "")
        set(plain_runtime "")
        if(PYOBF_DEMO_POST_PARENT_KIND EQUAL 3 OR owner_source)
            list(APPEND emission FUNCTION_SECTIONS)
        endif()
        if(PYOBF_DEMO_POST_PARENT_HELPERS OR (owner_source AND PYOBF_NATIVE_DEMO_OUTER_CFF))
            list(APPEND emission OWNERSHIP_REPORT "${report}")
        endif()
        if(NOT PYOBF_NATIVE_DEMO_OUTER_CFF)
            list(APPEND plain_runtime "${PROJECT_SOURCE_DIR}/src/path_fold/marker.cpp")
        endif()
        pyobf_native_emit_object("${object}" "${transformed}" ${emission})
        add_library(${raw_target} SHARED "${object}" ${plain_runtime} ${backend_sources} "$<TARGET_OBJECTS:${record_target}>")
        set_target_properties(${raw_target} PROPERTIES LINKER_LANGUAGE CXX)
    else()
        add_library(${raw_target} SHARED ${authored_sources} ${backend_sources} ${outer_dependencies} "${path_events_header}"
            "${PROJECT_SOURCE_DIR}/src/path_fold/marker.cpp" "$<TARGET_OBJECTS:${record_target}>")
    endif()
    set_target_properties(${raw_target} PROPERTIES OUTPUT_NAME "${target}"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/unfinalized"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/unfinalized"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/unfinalized")
    target_compile_features(${raw_target} PRIVATE cxx_std_17)
    target_compile_definitions(${raw_target} PRIVATE ${OUTER_DEFINITIONS})
    target_include_directories(${raw_target} PRIVATE
        "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(${raw_target} PRIVATE ${PYOBF_NATIVE_BACKEND_LINK_LIBRARIES})
    if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH OR PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        pyobf_native_reference_storage(${raw_target} "${reference_plan}")
        set(measured_authored "")
        foreach(source IN LISTS authored_sources)
            get_filename_component(source "${source}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
            list(APPEND measured_authored "${source}")
        endforeach()
        set_target_properties(${raw_target} PROPERTIES PYOBF_NATIVE_MEASURED_REFERENCE_PLAN "${reference_plan}"
            PYOBF_NATIVE_MEASURED_AUTHORED_SOURCES "${measured_authored}"
            PYOBF_NATIVE_MEASURED_BACKEND_SOURCES "${backend_sources}")
        if(PYOBF_NATIVE_DEMO_OUTER_CFF OR PYOBF_DEMO_POST_PARENT_KIND EQUAL 3)
            set_target_properties(${raw_target} PROPERTIES PYOBF_NATIVE_MEASURED_OBJECT "${object}")
        endif()
        if(PYOBF_NATIVE_DEMO_OUTER_CFF)
            set_target_properties(${raw_target} PROPERTIES PYOBF_NATIVE_MEASURED_CFF_OBJECT "${object}"
                PYOBF_NATIVE_MEASURED_CFF_REPORT "${report}")
        endif()
        if(PYOBF_DEMO_POST_PARENT_HELPERS)
            set_target_properties(${raw_target} PROPERTIES PYOBF_NATIVE_MEASURED_OWNERSHIP_REPORT "${report}")
        endif()
        if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
            pyobf_native_demo_finalize_post(${target} ${raw_target} "${reference_plan}" final_image release_report)
        else()
            pyobf_native_demo_finalize_measured(${target} ${raw_target} "${reference_plan}" final_image release_report)
        endif()
    else()
        pyobf_native_demo_finalize(${target} ${raw_target} final_image release_report)
    endif()
    if(PYOBF_NATIVE_DEMO_OUTER_CFF)
        set(final_report "${prefix}.final.json")
        set(outer_builder_options "")
        set(outer_builder_dependencies "")
        if(PYOBF_NATIVE_DEMO_OUTER_BUILDER_DIR)
            set(outer_builder_record "${PYOBF_NATIVE_DEMO_OUTER_BUILDER_DIR}/${target}.replay.json")
            set(outer_builder_receipt "${PYOBF_NATIVE_DEMO_OUTER_BUILDER_DIR}/${target}.receipt.json")
            set(outer_builder_roles
                "image=${final_image}" "report=${report}"
                "combined_ir=${combined}" "requested_ir=${requested}"
                "request_manifest=${requests}" "input_ir=${input}"
                "transformed_ir=${transformed}" "object=${object}"
                "inventory=${object}.ownership.json"
                "unfinalized_image=$<TARGET_FILE:${raw_target}>"
                "release_report=${release_report}" "recipe=${configuration}"
                "opt_exe=${PYOBF_NATIVE_OPT_EXECUTABLE}"
                "clang_exe=${CMAKE_CXX_COMPILER}"
                "pass_plugin=$<TARGET_FILE:pyobf_native_cff>"
                "owner_plan=${reference_plan}" "release_plan=${release_plan}"
                "private=${payload_binding_reference}" "scoped=${payload_scope_material}"
                "child_final=${linked_cff_report}"
                "child_image=$<TARGET_FILE:pyobf_native_demo_inner>"
                "release_material=${release_material}" "mixed_plan=${payload_mixed_plan}")
            set(outer_builder_freeze_args "")
            foreach(role IN LISTS outer_builder_roles)
                list(APPEND outer_builder_freeze_args "--role=${role}")
            endforeach()
            foreach(option IN LISTS selection)
                list(APPEND outer_builder_freeze_args "--opt-arg=${option}")
            endforeach()
            pyobf_native_compiler_arguments(outer_replay_clang_args)
            list(APPEND outer_replay_clang_args -ffunction-sections -O0 -fno-lto)
            foreach(option IN LISTS outer_replay_clang_args)
                list(APPEND outer_builder_freeze_args "--clang-arg=${option}")
            endforeach()
            add_custom_target(pyobf_native_demo_freeze_${target}_builder_receipt
                COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cff_outer_builder_replay.py" freeze
                    --source-opt "${PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT}"
                    --record "${outer_builder_record}" --receipt "${outer_builder_receipt}"
                    ${outer_builder_freeze_args}
                DEPENDS "${final_image}" "${release_report}" "${combined}" "${requested}"
                    "${requests}" "${input}" "${transformed}" "${report}"
                    "${object}" "${object}.ownership.json" "${configuration}"
                    pyobf_native_cff pyobf_native_demo_inner "${linked_cff_report}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/cff_outer_builder_replay.py"
                    "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_receipt.py"
                VERBATIM)
            if(PYOBF_NATIVE_DEMO_G3_OUTER_REPLAY)
                list(APPEND outer_builder_options
                    --outer-builder-receipt "${outer_builder_receipt}"
                    --outer-builder-record "${outer_builder_record}")
                foreach(role IN LISTS outer_builder_roles)
                    list(APPEND outer_builder_options "--outer-builder-role=${role}")
                endforeach()
                list(APPEND outer_builder_dependencies
                    "${outer_builder_receipt}" "${outer_builder_record}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/cff_outer_builder_replay.py"
                    "${CMAKE_CURRENT_SOURCE_DIR}/cff_builder_receipt.py")
            endif()
        endif()
        set(owner_options "")
        set(owner_dependencies "")
        if(owner_source)
            list(APPEND coverage_options --owner-plan "${reference_plan}")
            list(APPEND owner_options --owner-object "${object}" --owner-inventory "${object}.ownership.json"
                --owner-plan "${reference_plan}")
            list(APPEND owner_dependencies "${object}" "${object}.ownership.json" "${reference_plan}")
            foreach(tool owner_reader_image owner_creator_image owner_reader_plan function_subject function_inventory generated_ownership
                    coff_layout coff_symbols coff_relocations pe_layout pe_relocations reference_plan reference_identity)
                list(APPEND owner_dependencies "${PROJECT_SOURCE_DIR}/tools/${tool}.py")
            endforeach()
        endif()
        set(post_join_options "")
        set(post_join_dependencies "")
        set(parent_callback_options "")
        set(parent_callback_dependencies "")
        if(PYOBF_NATIVE_DEMO_G3_PARENT_CALLBACK AND NOT OUTER_DECOY)
            if(NOT owner_source)
                message(FATAL_ERROR "G3 parent callback needs an outer owner object")
            endif()
            list(APPEND parent_callback_options --parent-callback)
            list(APPEND parent_callback_dependencies "${object}"
                "${PROJECT_SOURCE_DIR}/tools/parent_callback_image.py")
        endif()
        if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
            list(APPEND post_join_options
                --post-release-report "${release_report}" --post-release-plan "${release_plan}"
                --post-child-image "$<TARGET_FILE:pyobf_native_demo_inner>"
                --post-child-final "${linked_cff_report}" --post-child-raw "${cff_report}"
                --post-private "${payload_binding_reference}" --post-scoped "${payload_scope_material}")
            list(APPEND post_join_dependencies "${release_plan}" pyobf_native_demo_inner "${linked_cff_report}"
                "${cff_report}" "${payload_binding_reference}" "${payload_scope_material}"
                "${PROJECT_SOURCE_DIR}/tools/post_role_join.py" "${PROJECT_SOURCE_DIR}/tools/payload_binding.py"
                "${PROJECT_SOURCE_DIR}/tools/release_plan.py" "${PROJECT_SOURCE_DIR}/tools/reference_slots.py")
            if(PYOBF_NATIVE_DEMO_POST_MIXED)
                list(APPEND post_join_options --post-join-mixed-plan "${payload_mixed_plan}"
                    --post-join-material "${release_material}")
                list(APPEND post_join_dependencies "${payload_mixed_plan}" "${release_material}"
                    "${PROJECT_SOURCE_DIR}/tools/post_mixed_binding.py")
            endif()
        endif()
        add_custom_command(OUTPUT "${final_report}"
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_linked_cff.py"
                    "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${final_image}" "${report}"
                    --output "${final_report}" ${owner_options} ${post_join_options} ${parent_callback_options}
                    ${outer_builder_options}
            DEPENDS "${final_image}" "${release_report}" "${report}" check_linked_cff.py cff_transition_evidence.py
                cff_data_evidence.py cff_archive_evidence.py cff_reference_evidence.py cff_frame_evidence.py
                cff_preparation_evidence.py cff_local_evidence.py cff_external_evidence.py cff_import_evidence.py
                cff_path_fold_evidence.py cff_contribution_evidence.py cff_contribution_groups.py
                cff_source_mixed_original_edges.py cff_source_mixed_bounded_edges.py
                ${owner_dependencies} ${post_join_dependencies} ${parent_callback_dependencies}
                ${outer_builder_dependencies}
            VERBATIM)
        add_custom_target(${target}_cff_verify DEPENDS "${final_report}")
        add_custom_target(${target} ALL DEPENDS "${final_report}" "${final_image}")
        add_test(NAME ${target}_cff_coverage
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_outer.py"
                    "${final_image}" "${report}" "${final_report}" "${requests}"
                    "${configuration}" ${coverage_options})
    else()
        add_custom_target(${target} ALL DEPENDS "${final_image}" "${release_report}")
    endif()
    set_target_properties(${target} PROPERTIES PYOBF_NATIVE_FINAL_IMAGE "${final_image}"
        PYOBF_NATIVE_UNFINALIZED_TARGET "${raw_target}")
endfunction()
