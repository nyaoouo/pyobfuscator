include("${PROJECT_SOURCE_DIR}/cmake/LLVMCompile.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/ArchivePipeline.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/Assets.cmake")

set(payload_ir "${CMAKE_CURRENT_BINARY_DIR}/payload.ll")
set(combined_ir "${CMAKE_CURRENT_BINARY_DIR}/combined.ll")
set(request_manifest "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.requests.json")
set(requested_ir "${CMAKE_CURRENT_BINARY_DIR}/payload.requested.ll")
set(transformed_ir "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.ll")
set(cff_report "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.coverage.json")
set(payload_object "${CMAKE_CURRENT_BINARY_DIR}/payload.cff.obj")

set(asset_ir_files "")
set(asset_definitions "")
set(asset_dependencies "")
set(extra_runtime_sources "")
if(PYOBF_NATIVE_DEMO_ASSET)
    set(asset_directory "${CMAKE_CURRENT_BINARY_DIR}/assets")
    pyobf_native_embed_asset(asset_source asset_header ID sample FILE "${PYOBF_NATIVE_DEMO_ASSET}"
        DIRECTORY "${asset_directory}")
    set(asset_ir "${CMAKE_CURRENT_BINARY_DIR}/asset.sample.ll")
    pyobf_native_compile_ir(OUTPUT "${asset_ir}" SOURCE "${asset_source}"
        INCLUDES "${PROJECT_SOURCE_DIR}/include" "${asset_directory}" DEPENDS "${asset_header}")
    list(APPEND asset_ir_files "${asset_ir}")
    list(APPEND asset_definitions PYOBF_DEMO_HAS_ASSET=1)
    list(APPEND asset_dependencies "${asset_header}")
    list(APPEND extra_runtime_sources "${PROJECT_SOURCE_DIR}/src/archive/asset_identity.cpp")
endif()
pyobf_native_compile_ir(OUTPUT "${payload_ir}" SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/payload.cpp"
    INCLUDES "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}"
    DEFINITIONS ${asset_definitions} ${payload_binding_definitions}
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/demo_config.hpp" ${asset_dependencies} ${payload_binding_early_dependencies})
set(sdk_ir_files "")
get_target_property(context_core pyobf_native_bootstrap_context PYOBF_NATIVE_CONTEXT_CORE_SOURCES)
set(payload_backend_sources ${PYOBF_NATIVE_BACKEND_SDK_SOURCES} ${PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES})
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    list(APPEND payload_backend_sources ${post_observer_backend})
    list(REMOVE_DUPLICATES payload_backend_sources)
endif()
set(sdk_ir_sources "${PROJECT_SOURCE_DIR}/src/sdk.cpp" ${context_core} ${payload_backend_sources} ${payload_binding_sources})
list(REMOVE_DUPLICATES sdk_ir_sources)
set(sdk_ir_index 0)
foreach(sdk_source IN LISTS sdk_ir_sources)
    set(sdk_ir "${CMAKE_CURRENT_BINARY_DIR}/sdk.${sdk_ir_index}.ll")
    set(sdk_ir_definitions "")
    if(PYOBF_NATIVE_DEMO_POST_MIXED AND sdk_source STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}/post_payload.cpp")
        list(APPEND sdk_ir_definitions PYOBF_DEMO_POST_MIXED=1)
    endif()
    pyobf_native_compile_ir(OUTPUT "${sdk_ir}" SOURCE "${sdk_source}"
        INCLUDES "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}"
        DEFINITIONS ${sdk_ir_definitions}
        DEPENDS ${payload_binding_extra_outputs})
    list(APPEND sdk_ir_files "${sdk_ir}")
    math(EXPR sdk_ir_index "${sdk_ir_index} + 1")
endforeach()
add_custom_command(OUTPUT "${combined_ir}"
    COMMAND "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" -S "${payload_ir}" ${sdk_ir_files} ${asset_ir_files} -o "${combined_ir}"
    DEPENDS "${payload_ir}" ${sdk_ir_files} ${asset_ir_files}
    VERBATIM)

set(cff_selection_args "-pyobf-cff-functions=${PYOBF_DEMO_CFF_FUNCTIONS}"
    ${PYOBF_DEMO_CFF_CONFIG_ARGS} "-pyobf-cff-deep-functions=${PYOBF_DEMO_CFF_DEEP_FUNCTIONS}"
    "-pyobf-cff-seed=${PYOBF_NATIVE_CFF_SEED}" ${PYOBF_DEMO_CFF_REGION_ARGS}
    "-pyobf-cff-markers=${PYOBF_DEMO_CFF_MARKERS}" "-pyobf-cff-strategy=${PYOBF_NATIVE_CFF_STRATEGY}")
add_custom_command(OUTPUT "${request_manifest}" "${requested_ir}"
    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
            -passes=pyobf-native-cff-requests ${cff_selection_args}
            "-pyobf-cff-requests-output=${request_manifest}" -verify-each -S "${combined_ir}" -o "${requested_ir}"
    DEPENDS "${combined_ir}" ${PYOBF_NATIVE_CFF_CONFIG} ${payload_binding_early_dependencies} pyobf_native_cff
    VERBATIM)
set(cff_input "${requested_ir}")
if(PYOBF_NATIVE_CFF_SOURCE_OPT STREQUAL "O2")
    set(cff_input "${CMAKE_CURRENT_BINARY_DIR}/payload.optimized.ll")
    add_custom_command(OUTPUT "${cff_input}"
        COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" "-passes=default<O2>" -verify-each
                -S "${requested_ir}" -o "${cff_input}"
        DEPENDS "${requested_ir}"
        VERBATIM)
endif()
if(PYOBF_NATIVE_DEMO_ARCHIVE)
    set(archive_optimized_ir "${cff_input}")
    set(archive_source_requests "${request_manifest}")
    pyobf_native_archive_pipeline(cff_input request_manifest INPUT "${cff_input}"
        PREFIX "${CMAKE_CURRENT_BINARY_DIR}/payload.archive" REQUESTS "${request_manifest}"
        CFF_ARGS ${cff_selection_args} DEPENDS ${PYOBF_NATIVE_CFF_CONFIG} ${payload_binding_early_dependencies}
        INPUT_BACKEND_SOURCES ${payload_backend_sources} INPUT_RUNTIME_SOURCES ${post_observer_core}
        EXTRA_RUNTIME_SOURCES ${extra_runtime_sources})
endif()
set(mixed_edge_args "")
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    set(mixed_edge_args
        "-pyobf-cff-edge-owners=pyobf_demo_bound_compute,pyobf_demo_protection_wrapper"
        "-pyobf-cff-edge-plan-input=${payload_mixed_plan}")
    add_custom_command(OUTPUT "${payload_mixed_plan}"
        COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
            -passes=pyobf-native-cff-edge-plan ${cff_selection_args}
            "-pyobf-cff-edge-owners=pyobf_demo_bound_compute,pyobf_demo_protection_wrapper"
            "-pyobf-cff-edge-ir-input=${cff_input}"
            "-pyobf-cff-edge-plan-output=${payload_mixed_plan}" -disable-output "${cff_input}"
        DEPENDS "${cff_input}" "${request_manifest}" "${payload_binding_recipe}" pyobf_native_cff
        VERBATIM)
endif()
add_custom_command(OUTPUT "${transformed_ir}" "${cff_report}" ${PYOBF_NATIVE_CFF_PRIVATE_MAP}
    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
            -passes=pyobf-native-cff ${cff_selection_args} ${PYOBF_DEMO_CFF_MAP_ARGS} ${payload_binding_args}
            ${mixed_edge_args}
            "-pyobf-cff-require-decision-flow=${PYOBF_DEMO_CFF_REQUIRE_DECISION_FLOW}"
            "-pyobf-cff-report=${cff_report}" "-pyobf-cff-requests-input=${request_manifest}"
            -verify-each -S "${cff_input}" -o "${transformed_ir}"
    DEPENDS "${cff_input}" "${request_manifest}" ${PYOBF_NATIVE_CFF_CONFIG} ${payload_binding_dependencies} pyobf_native_cff
    VERBATIM)
set(payload_emission "")
if(PYOBF_DEMO_POST_CHILD_KIND EQUAL 3 OR PYOBF_NATIVE_DEMO_G3_SUBJECTS)
    list(APPEND payload_emission FUNCTION_SECTIONS)
endif()
if(PYOBF_DEMO_POST_CHILD_HELPERS)
    list(APPEND payload_emission OWNERSHIP_REPORT "${cff_report}")
endif()
pyobf_native_emit_object("${payload_object}" "${transformed_ir}" ${payload_emission})
