include_guard(GLOBAL)
if(NOT PYOBF_NATIVE_DEMO_DECOY)
    return()
endif()
include("${CMAKE_CURRENT_LIST_DIR}/ReleaseMaterial.cmake")

get_filename_component(decoy_demo_source "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
get_filename_component(decoy_native_root "${decoy_demo_source}/.." ABSOLUTE)
include("${decoy_native_root}/cmake/LLVMCompile.cmake")

set(decoy_prefix "${CMAKE_CURRENT_BINARY_DIR}/decoy")
set(decoy_units "")
set(decoy_index 0)
foreach(source IN LISTS decoy_sources)
    set(unit "${decoy_prefix}.${decoy_index}.ll")
    pyobf_native_compile_ir(OUTPUT "${unit}" SOURCE "${source}"
        INCLUDES "${decoy_native_root}/include" "${decoy_demo_source}")
    list(APPEND decoy_units "${unit}")
    math(EXPR decoy_index "${decoy_index} + 1")
endforeach()
set(decoy_combined "${decoy_prefix}.combined.ll")
add_custom_command(OUTPUT "${decoy_combined}"
    COMMAND "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" -S ${decoy_units} -o "${decoy_combined}"
    DEPENDS ${decoy_units} VERBATIM)
set(decoy_selection -pyobf-cff-functions=pyobf_native_inner_entry -pyobf-cff-markers=true
    "-pyobf-cff-seed=${PYOBF_NATIVE_DECOY_CFF_SEED}" "-pyobf-cff-config=${PYOBF_NATIVE_DECOY_CFF_CONFIG}")
set(decoy_requested "${decoy_prefix}.requested.ll")
set(decoy_requests "${decoy_prefix}.requests.json")
add_custom_command(OUTPUT "${decoy_requested}" "${decoy_requests}"
    COMMAND "${Python3_EXECUTABLE}" "${decoy_native_root}/tools/check_decoy_input.py" "${decoy_combined}"
    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
        -passes=pyobf-native-cff-requests ${decoy_selection}
        "-pyobf-cff-requests-output=${decoy_requests}" -verify-each -S "${decoy_combined}" -o "${decoy_requested}"
    DEPENDS "${decoy_combined}" "${PYOBF_NATIVE_DECOY_CFF_CONFIG}" pyobf_native_cff
        "${decoy_native_root}/tools/check_decoy_input.py" "${decoy_native_root}/tools/decoy_contract.py"
        "${decoy_native_root}/tools/release_plan.py" "${decoy_native_root}/tools/release_material.py" VERBATIM)
set(decoy_input "${decoy_requested}")
if(PYOBF_NATIVE_DECOY_CFF_SOURCE_OPT STREQUAL "O2")
    set(decoy_input "${decoy_prefix}.optimized.ll")
    add_custom_command(OUTPUT "${decoy_input}"
        COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" "-passes=default<O2>" -verify-each -S "${decoy_requested}" -o "${decoy_input}"
        DEPENDS "${decoy_requested}" VERBATIM)
endif()
set(decoy_transformed "${decoy_prefix}.cff.ll")
set(decoy_coverage "${decoy_prefix}.coverage.json")
add_custom_command(OUTPUT "${decoy_transformed}" "${decoy_coverage}"
    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
        -passes=pyobf-native-cff ${decoy_selection} "-pyobf-cff-requests-input=${decoy_requests}"
        "-pyobf-cff-report=${decoy_coverage}" -verify-each -S "${decoy_input}" -o "${decoy_transformed}"
    DEPENDS "${decoy_input}" "${decoy_requests}" "${PYOBF_NATIVE_DECOY_CFF_CONFIG}" pyobf_native_cff VERBATIM)
set(decoy_object "${decoy_prefix}.obj")
pyobf_native_emit_object("${decoy_object}" "${decoy_transformed}")
add_library(pyobf_native_demo_decoy SHARED "${decoy_object}")
set_target_properties(pyobf_native_demo_decoy PROPERTIES LINKER_LANGUAGE CXX)
set(decoy_final "${decoy_prefix}.final.json")
add_custom_command(OUTPUT "${decoy_final}"
    COMMAND "${Python3_EXECUTABLE}" "${decoy_demo_source}/check_linked_cff.py"
        "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_demo_decoy>" "${decoy_coverage}"
        --output "${decoy_final}"
    DEPENDS pyobf_native_demo_decoy "${decoy_coverage}"
        "${decoy_demo_source}/check_linked_cff.py" "${decoy_demo_source}/cff_transition_evidence.py"
        "${decoy_demo_source}/cff_data_evidence.py" "${decoy_demo_source}/cff_archive_evidence.py"
        "${decoy_demo_source}/cff_reference_evidence.py" "${decoy_demo_source}/cff_frame_evidence.py"
        "${decoy_demo_source}/cff_preparation_evidence.py" "${decoy_demo_source}/cff_local_evidence.py"
        "${decoy_demo_source}/cff_external_evidence.py" "${decoy_demo_source}/cff_import_evidence.py"
        "${decoy_demo_source}/cff_path_fold_evidence.py" "${decoy_demo_source}/cff_contribution_evidence.py"
        "${decoy_demo_source}/cff_contribution_groups.py" VERBATIM)
set(decoy_plan "${decoy_prefix}.private.json")
pyobf_native_demo_prepare_material(decoy_material decoy_events_header decoy_events "${decoy_prefix}")
add_custom_command(OUTPUT "${decoy_plan}"
    COMMAND "${Python3_EXECUTABLE}" "${decoy_native_root}/tools/prepare_release.py"
        "$<TARGET_FILE:pyobf_native_demo_decoy>" "${decoy_final}" "${decoy_plan}" "${decoy_events_header}"
        --event-namespace decoy_events --material "${decoy_material}"
    DEPENDS "${decoy_final}" "${decoy_material}" "${decoy_events_header}" "${decoy_native_root}/tools/prepare_release.py"
        "${decoy_native_root}/tools/release_plan.py" "${decoy_native_root}/tools/path_fold_reference.py"
        "${decoy_native_root}/tools/release_material.py"
        "${decoy_native_root}/tools/atomic_artifact.py" VERBATIM)
set(decoy_blob "${CMAKE_CURRENT_BINARY_DIR}/decoy_blob.hpp")
set(decoy_manifest "${decoy_prefix}.package.json")
add_custom_command(OUTPUT "${decoy_blob}" "${decoy_manifest}"
    COMMAND "${Python3_EXECUTABLE}" "${decoy_demo_source}/pack_decoy.py"
        "$<TARGET_FILE:pyobf_native_demo_decoy>" "${decoy_coverage}" "${decoy_final}" "${decoy_plan}"
        "${decoy_events_header}" "${decoy_blob}" "${decoy_manifest}"
    DEPENDS "${decoy_final}" "${decoy_plan}" "${decoy_events_header}"
        "${decoy_demo_source}/pack_decoy.py" "${decoy_demo_source}/pack_payload.py"
        "${decoy_native_root}/tools/payload_binding.py"
        "${decoy_native_root}/tools/decoy_contract.py" "${decoy_native_root}/tools/release_plan.py"
        "${decoy_native_root}/tools/release_material.py"
        "${decoy_native_root}/tools/release_format.py" "${decoy_native_root}/tools/path_fold_reference.py"
        "${decoy_native_root}/tools/atomic_artifact.py" VERBATIM)
add_custom_target(pyobf_native_demo_decoy_package ALL DEPENDS "${decoy_blob}" "${decoy_manifest}")
