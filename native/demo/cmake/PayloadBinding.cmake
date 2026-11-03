include_guard(GLOBAL)

set(payload_binding_definitions "")
set(payload_binding_sources "")
set(payload_binding_dependencies "")
set(payload_binding_early_dependencies "")
set(payload_binding_args "")
set(payload_mixed_plan "")
set(payload_mixed_header "")
if(PYOBF_NATIVE_DEMO_PAYLOAD_BINDING STREQUAL "decoupled")
    return()
endif()

set(payload_binding_recipe "${CMAKE_CURRENT_BINARY_DIR}/payload.binding.recipe.json")
set(payload_binding_reference "${CMAKE_CURRENT_BINARY_DIR}/payload.binding.private.json")
set(binding_base_args "")
if(PYOBF_NATIVE_CFF_CONFIG)
    list(APPEND binding_base_args --recipe "${PYOBF_NATIVE_CFF_CONFIG}")
endif()
set(payload_binding_extra_outputs "")
set(binding_mixed_args "")
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    set(payload_mixed_plan "${CMAKE_CURRENT_BINARY_DIR}/payload.post-mixed.edges.json")
    set(payload_mixed_header "${CMAKE_CURRENT_BINARY_DIR}/post_mixed_sites.hpp")
    list(APPEND binding_mixed_args --mixed)
endif()
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    set(payload_scope_material "${CMAKE_CURRENT_BINARY_DIR}/payload.scope-material.private.bin")
    set(payload_post_profile "${CMAKE_CURRENT_BINARY_DIR}/post_profile.hpp")
    add_custom_command(OUTPUT "${payload_scope_material}"
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/prepare_scope_material.py" "${payload_scope_material}"
        DEPENDS "${PROJECT_SOURCE_DIR}/tools/prepare_scope_material.py" "${PROJECT_SOURCE_DIR}/tools/atomic_artifact.py" VERBATIM)
    list(APPEND binding_base_args --scope-material "${payload_scope_material}" --post-profile "${payload_post_profile}")
    list(APPEND payload_binding_extra_outputs "${payload_post_profile}")
endif()
set(binding_generation_dependencies "${release_material}" "${CMAKE_CURRENT_BINARY_DIR}/demo_config.hpp"
    ${PYOBF_NATIVE_CFF_CONFIG} ${payload_scope_material}
    "${PROJECT_SOURCE_DIR}/tools/prepare_payload_binding.py" "${PROJECT_SOURCE_DIR}/tools/payload_binding.py"
    "${PROJECT_SOURCE_DIR}/tools/post_mixed_binding.py"
    "${PROJECT_SOURCE_DIR}/tools/release_material.py" "${PROJECT_SOURCE_DIR}/tools/release_plan.py"
    "${PROJECT_SOURCE_DIR}/tools/path_fold_reference.py" "${PROJECT_SOURCE_DIR}/tools/atomic_artifact.py"
    "${PROJECT_SOURCE_DIR}/tools/prepare_scope_material.py")
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    add_custom_command(OUTPUT "${payload_binding_recipe}" "${payload_post_profile}"
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/prepare_payload_binding.py"
            "${release_material}" "${CMAKE_CURRENT_BINARY_DIR}/demo_config.hpp"
            "${payload_binding_recipe}" "${payload_binding_reference}" ${binding_base_args} ${binding_mixed_args} --phase early
        DEPENDS ${binding_generation_dependencies} VERBATIM)
    set(binding_late_args "")
    if(PYOBF_NATIVE_DEMO_POST_MIXED)
        list(APPEND binding_late_args --mixed-plan "${payload_mixed_plan}" --mixed-header "${payload_mixed_header}")
    endif()
    add_custom_command(OUTPUT "${payload_binding_reference}" ${payload_mixed_header}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/prepare_payload_binding.py"
            "${release_material}" "${CMAKE_CURRENT_BINARY_DIR}/demo_config.hpp"
            "${payload_binding_recipe}" "${payload_binding_reference}" ${binding_base_args}
            ${binding_mixed_args} ${binding_late_args} --phase late
        DEPENDS "${payload_binding_recipe}" "${payload_post_profile}" ${payload_mixed_plan}
            ${binding_generation_dependencies} VERBATIM)
else()
    add_custom_command(OUTPUT "${payload_binding_recipe}" "${payload_binding_reference}"
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/prepare_payload_binding.py"
            "${release_material}" "${CMAKE_CURRENT_BINARY_DIR}/demo_config.hpp"
            "${payload_binding_recipe}" "${payload_binding_reference}" ${binding_base_args}
        DEPENDS ${binding_generation_dependencies} VERBATIM)
endif()
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    set(payload_binding_early_dependencies "${payload_binding_recipe}" "${payload_post_profile}")
else()
    set(payload_binding_early_dependencies "${payload_binding_recipe}" "${payload_binding_reference}")
endif()
set(PYOBF_DEMO_CFF_CONFIG_ARGS "-pyobf-cff-config=${payload_binding_recipe}")
set(payload_binding_args "-pyobf-cff-contribution-input=${payload_binding_reference}")
set(payload_binding_dependencies "${payload_binding_recipe}" "${payload_binding_reference}"
    ${payload_mixed_header} ${payload_binding_extra_outputs})
set(payload_binding_definitions PYOBF_DEMO_PAYLOAD_BOUND=1)
if(PYOBF_NATIVE_DEMO_POST_MIXED)
    list(APPEND payload_binding_definitions PYOBF_DEMO_POST_MIXED=1)
endif()
get_target_property(binding_client pyobf_native_contribution_runtime PYOBF_NATIVE_CONTRIBUTION_CLIENT_SOURCE)
set(payload_binding_sources "${binding_client}" "${PROJECT_SOURCE_DIR}/src/contribution/gate.cpp")
