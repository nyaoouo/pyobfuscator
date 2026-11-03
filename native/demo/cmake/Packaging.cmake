include_guard(GLOBAL)

set(release_plan "${CMAKE_CURRENT_BINARY_DIR}/release-plan.private.json")
set(release_record_blob "${CMAKE_CURRENT_BINARY_DIR}/release-key.record")
set(payload_blob "${CMAKE_CURRENT_BINARY_DIR}/payload_blob.hpp")
set(payload_binding_pack_args "")
if(payload_binding_reference)
    list(APPEND payload_binding_pack_args --contribution-input "${payload_binding_reference}")
endif()
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    list(APPEND payload_binding_pack_args --binding-provider measured-scope-v1 --scope-material "${payload_scope_material}")
endif()
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    list(APPEND payload_binding_pack_args --mixed-plan "${payload_mixed_plan}" --release-material "${release_material}")
endif()
add_custom_command(OUTPUT "${release_plan}"
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/prepare_release.py"
        "$<TARGET_FILE:pyobf_native_demo_inner>" "${linked_cff_report}" "${release_plan}" "${path_events_header}"
        --material "${release_material}"
    DEPENDS "${linked_cff_report}" pyobf_native_demo_inner "${release_material}" "${path_events_header}"
        "${PROJECT_SOURCE_DIR}/tools/prepare_release.py" "${PROJECT_SOURCE_DIR}/tools/release_plan.py"
        "${PROJECT_SOURCE_DIR}/tools/release_material.py"
        "${PROJECT_SOURCE_DIR}/tools/path_fold_reference.py" "${PROJECT_SOURCE_DIR}/tools/atomic_artifact.py"
    VERBATIM)
add_custom_command(OUTPUT "${payload_blob}" "${release_record_blob}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/pack_payload.py"
        "$<TARGET_FILE:pyobf_native_demo_inner>" "${payload_blob}" "${release_record_blob}"
        "${release_plan}" "${path_events_header}" "${linked_cff_report}"
        ${payload_binding_pack_args}
    DEPENDS "${linked_cff_report}" "${release_plan}" "${path_events_header}" ${payload_binding_dependencies} ${payload_scope_material} ${payload_mixed_plan} pack_payload.py
        "${PROJECT_SOURCE_DIR}/tools/release_format.py" "${PROJECT_SOURCE_DIR}/tools/release_plan.py"
        "${PROJECT_SOURCE_DIR}/tools/release_material.py"
        "${PROJECT_SOURCE_DIR}/tools/payload_binding.py"
        "${PROJECT_SOURCE_DIR}/tools/post_mixed_binding.py"
        "${PROJECT_SOURCE_DIR}/tools/prepare_scope_material.py"
        "${PROJECT_SOURCE_DIR}/tools/path_fold_reference.py" "${PROJECT_SOURCE_DIR}/tools/atomic_artifact.py"
    VERBATIM)

add_library(pyobf_native_demo_record OBJECT "${PROJECT_SOURCE_DIR}/backends/windows_user/release_record.cpp")
target_compile_features(pyobf_native_demo_record PRIVATE cxx_std_17)
target_include_directories(pyobf_native_demo_record PRIVATE "${PROJECT_SOURCE_DIR}/src")
set_target_properties(pyobf_native_demo_record PROPERTIES INTERPROCEDURAL_OPTIMIZATION FALSE)
target_compile_options(pyobf_native_demo_record PRIVATE -O0 -fno-lto)

function(pyobf_native_demo_finalize target raw_target final_image_out report_out)
    set(image "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${target}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set(report "${CMAKE_CURRENT_BINARY_DIR}/${target}.release.json")
    add_custom_command(OUTPUT "${image}" "${report}"
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/finalize_release.py"
            "$<TARGET_FILE:${raw_target}>" "${release_record_blob}" "${image}" --report "${report}"
        DEPENDS ${raw_target} "${release_record_blob}"
            "${PROJECT_SOURCE_DIR}/tools/finalize_release.py" "${PROJECT_SOURCE_DIR}/tools/pe_release_record.py"
            "${PROJECT_SOURCE_DIR}/tools/pe_layout.py"
            "${PROJECT_SOURCE_DIR}/tools/pe_data_patch.py"
            "${PROJECT_SOURCE_DIR}/tools/release_format.py" "${PROJECT_SOURCE_DIR}/tools/atomic_artifact.py"
        VERBATIM)
    set(${final_image_out} "${image}" PARENT_SCOPE)
    set(${report_out} "${report}" PARENT_SCOPE)
endfunction()
