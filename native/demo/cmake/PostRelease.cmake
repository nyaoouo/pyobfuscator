include_guard(GLOBAL)
if(NOT PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    return()
endif()
include("${PROJECT_SOURCE_DIR}/cmake/ReferenceSlots.cmake")
get_target_property(post_observer_core pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_CORE_SOURCES)
get_target_property(post_observer_backend pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_BACKEND_SOURCES)
get_target_property(post_release_core pyobf_native_measured_release PYOBF_NATIVE_MEASURED_RELEASE_CORE_SOURCES)
get_target_property(post_contribution_core pyobf_native_measured_contribution PYOBF_NATIVE_MEASURED_CONTRIBUTION_CORE_SOURCES)
get_target_property(post_scope_core pyobf_native_measured_scope PYOBF_NATIVE_MEASURED_SCOPE_CORE_SOURCES)
set(payload_binding_sources ${post_scope_core} ${post_contribution_core} ${post_release_core} ${post_observer_core}
    "${CMAKE_CURRENT_SOURCE_DIR}/post_payload.cpp")
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    get_target_property(post_owned_client pyobf_native_contribution_runtime PYOBF_NATIVE_CONTRIBUTION_CLIENT_SOURCE)
    list(APPEND payload_binding_sources "${post_owned_client}"
        "${PROJECT_SOURCE_DIR}/src/contribution/mixed_gate.cpp")
endif()
list(APPEND payload_binding_definitions PYOBF_DEMO_POST_CODE_HASH=1)

function(pyobf_native_demo_prepare_post_reference raw_target plan_out directory_out)
    set(plan "${CMAKE_CURRENT_BINARY_DIR}/${raw_target}.reference-plan.private.json")
    set(options "")
    if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH)
        list(APPEND options --pre-release)
    endif()
    if(PYOBF_NATIVE_DEMO_POST_SUBJECTS)
        list(APPEND options --subjects "${PYOBF_NATIVE_DEMO_POST_SUBJECTS}")
    endif()
    if(PYOBF_NATIVE_DEMO_POST_MIXED)
        list(APPEND options --mixed-plan "${payload_mixed_plan}")
    endif()
    add_custom_command(OUTPUT "${plan}"
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/post_reference_plan.py"
            "${release_material}" "${raw_target}" "${payload_binding_reference}" "${payload_scope_material}" "${plan}" ${options}
        DEPENDS "${release_material}" "${payload_binding_reference}" "${payload_scope_material}"
            ${payload_mixed_plan} ${PYOBF_NATIVE_DEMO_POST_SUBJECTS}
            "${PROJECT_SOURCE_DIR}/tools/post_reference_plan.py" "${PROJECT_SOURCE_DIR}/tools/bootstrap_reference_plan.py"
            "${PROJECT_SOURCE_DIR}/tools/post_mixed_binding.py"
            "${PROJECT_SOURCE_DIR}/tools/post_subjects.py"
            "${PROJECT_SOURCE_DIR}/tools/payload_binding.py" "${PROJECT_SOURCE_DIR}/tools/prepare_scope_material.py"
            "${PROJECT_SOURCE_DIR}/tools/reference_plan.py" "${PROJECT_SOURCE_DIR}/tools/reference_identity.py"
            "${PROJECT_SOURCE_DIR}/tools/release_material.py" "${PROJECT_SOURCE_DIR}/tools/release_plan.py"
            "${PROJECT_SOURCE_DIR}/tools/path_fold_reference.py" "${PROJECT_SOURCE_DIR}/tools/atomic_artifact.py" VERBATIM)
    set(${plan_out} "${plan}" PARENT_SCOPE)
    set(${directory_out} "${CMAKE_CURRENT_BINARY_DIR}/${raw_target}.references" PARENT_SCOPE)
endfunction()

function(pyobf_native_demo_finalize_post target raw_target plan final_image_out report_out)
    set(image "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${target}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set(report "${CMAKE_CURRENT_BINARY_DIR}/${target}.release.json")
    set(dependencies "")
    foreach(tool finalize_post_release post_reference_plan post_subjects bootstrap_reference_plan finalize_references measured_scope
            measured_release pe_release_record release_format release_material release_plan payload_binding
            prepare_scope_material path_fold_reference reference_plan reference_identity reference_slots code_reference
            code_subject code_observation coff_symbols coff_layout coff_relocations function_subject function_inventory
            generated_function_subject generated_ownership pe_layout
            pe_relocations pe_data_patch archive_format pack_archive atomic_artifact)
        list(APPEND dependencies "${PROJECT_SOURCE_DIR}/tools/${tool}.py")
    endforeach()
    set(options "")
    if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH)
        list(APPEND options --pre-release)
    endif()
    if(PYOBF_NATIVE_DEMO_POST_SUBJECTS)
        list(APPEND options --subjects "${PYOBF_NATIVE_DEMO_POST_SUBJECTS}")
    endif()
    if(PYOBF_NATIVE_DEMO_POST_MIXED)
        list(APPEND options --mixed-plan "${payload_mixed_plan}")
        list(APPEND dependencies "${payload_mixed_plan}" "${PROJECT_SOURCE_DIR}/tools/post_mixed_binding.py")
    endif()
    pyobf_native_demo_post_objects(bindings ${raw_target})
    foreach(binding IN LISTS bindings)
        list(APPEND options --object "${binding}")
        string(REGEX REPLACE "^[0-9]+=" "" object_path "${binding}")
        list(APPEND dependencies "${object_path}")
    endforeach()
    pyobf_native_demo_post_ownership(manifests reports ${raw_target})
    foreach(kind manifests reports)
        if(kind STREQUAL "manifests")
            set(option --ownership)
        else()
            set(option --ownership-report)
        endif()
        foreach(binding IN LISTS ${kind})
            list(APPEND options ${option} "${binding}")
            string(REGEX REPLACE "^[0-9]+=" "" input "${binding}")
            list(APPEND dependencies "${input}")
        endforeach()
    endforeach()
    add_custom_command(OUTPUT "${image}" "${report}"
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/finalize_post_release.py"
            "$<TARGET_FILE:${raw_target}>" "${plan}" "${release_material}" "${release_record_blob}" "${image}"
            --role "${raw_target}" --private "${payload_binding_reference}" --scoped "${payload_scope_material}"
            --child "$<TARGET_FILE:pyobf_native_demo_inner>" --child-report "${linked_cff_report}"
            --release-plan "${release_plan}" --report "${report}" ${options}
        DEPENDS ${raw_target} "${plan}" "${release_material}" "${release_record_blob}" "${payload_binding_reference}"
            "${payload_scope_material}" pyobf_native_demo_inner "${linked_cff_report}" "${release_plan}"
            ${PYOBF_NATIVE_DEMO_POST_SUBJECTS} ${dependencies} VERBATIM)
    set(${final_image_out} "${image}" PARENT_SCOPE)
    set(${report_out} "${report}" PARENT_SCOPE)
endfunction()
