add_executable(pyobf_native_cff_contribution_fixture tests/contribution_fixture.cpp
    cff/contribution_expression.cpp cff/path_fold_emit.cpp cff/transition_encode.cpp
    cff/contribution_mix_plan.cpp cff/contribution_mix_emit.cpp cff/contribution_mix_proof.cpp
    cff/scalar_proof.cpp cff/scalar_mask.cpp)
target_compile_features(pyobf_native_cff_contribution_fixture PRIVATE cxx_std_17)
target_include_directories(pyobf_native_cff_contribution_fixture PRIVATE
    ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff" "${PROJECT_SOURCE_DIR}/src")
if(TARGET LLVM)
    target_link_libraries(pyobf_native_cff_contribution_fixture PRIVATE LLVM)
else()
    llvm_map_components_to_libnames(contribution_libraries Core Support)
    target_link_libraries(pyobf_native_cff_contribution_fixture PRIVATE ${contribution_libraries})
endif()

add_executable(pyobf_native_cff_contribution_contract tests/contribution_contract.cpp
    cff/contribution_validate.cpp cff/contribution_resolve.cpp)
target_compile_features(pyobf_native_cff_contribution_contract PRIVATE cxx_std_17)
target_include_directories(pyobf_native_cff_contribution_contract PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/cff")
add_test(NAME pyobf_native_cff_contribution_contract COMMAND pyobf_native_cff_contribution_contract)
get_filename_component(contribution_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
set_tests_properties(pyobf_native_cff_contribution_contract PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contribution_runtime_directory}")

set(contribution_source_contract_sources cff/contribution_edge_source.cpp cff/region_scope.cpp
    cff/contribution_private.cpp cff/contribution_sources.cpp cff/contribution_source_config.cpp
    cff/contribution_group_queries.cpp
    cff/contribution_validate.cpp cff/contribution_resolve.cpp
    cff/contribution_edge_inventory.cpp cff/contribution_edge_alias.cpp cff/contribution_edge_instrument.cpp cff/contribution_edge_lower.cpp cff/contribution_edge_invoke.cpp cff/contribution_frame_trace.cpp
    cff/contribution_marker.cpp cff/contribution_query.cpp cff/component_seed.cpp cff/site_origin.cpp cff/cfg_origin.cpp cff/switch_lower_edges.cpp cff/hybrid_eh_edges.cpp)
add_executable(pyobf_native_cff_contribution_edge_source_contract
    tests/contribution_edge_source_contract.cpp ${contribution_source_contract_sources})
add_executable(pyobf_native_cff_contribution_edge_invoke_contract
    tests/contribution_invoke_contract.cpp ${contribution_source_contract_sources})
add_executable(pyobf_native_cff_contribution_edge_binding_contract
    tests/contribution_binding_contract.cpp cff/contribution_seal.cpp cff/contribution_route_seal.cpp
    cff/contribution_private.cpp cff/contribution_bind.cpp cff/contribution_proof.cpp cff/contribution_query.cpp cff/component_seed.cpp
    cff/contribution_sources.cpp cff/contribution_source_config.cpp cff/contribution_validate.cpp cff/contribution_resolve.cpp
    cff/contribution_mix_plan.cpp cff/contribution_mix_emit.cpp cff/contribution_mix_proof.cpp
    cff/contribution_group_queries.cpp cff/contribution_group_bind.cpp cff/contribution_group_proof.cpp
    cff/contribution_edge_source.cpp cff/contribution_marker.cpp cff/region_scope.cpp
    cff/transition_layer_descriptor.cpp cff/transition_layers.cpp cff/transition_registry.cpp
    cff/transition_model.cpp cff/transition_model_identity.cpp cff/transition_model_match.cpp
    cff/transition_literal_model.cpp cff/hybrid_scalar_bindings.cpp
    cff/transition_predicate_model.cpp cff/bogus_control_plan.cpp cff/bogus_control_descriptor.cpp cff/bogus_control_proof.cpp cff/contribution_edge_flow.cpp
    cff/opaque_transition.cpp cff/junk_transition.cpp cff/decoy_transition.cpp cff/opaque_expression.cpp cff/junk_expression.cpp cff/site_origin.cpp
    cff/hybrid_flow_plan.cpp cff/hybrid_flow_verify.cpp cff/hybrid_eh_bind.cpp cff/state_binding_proof.cpp cff/state_layout.cpp
    cff/dispatch_tree.cpp cff/dispatch_proof.cpp cff/transition_encode.cpp cff/transition_proof.cpp
    cff/scalar_proof.cpp cff/scalar_mask.cpp cff/path_fold_proof.cpp cff/path_fold_emit.cpp)
add_executable(pyobf_native_cff_contribution_edge_flow_contract
    tests/contribution_edge_flow_contract.cpp cff/contribution_edge_flow.cpp cff/state_binding_proof.cpp cff/state_layout.cpp
    cff/dispatch_tree.cpp cff/dispatch_proof.cpp cff/transition_encode.cpp cff/transition_proof.cpp cff/scalar_proof.cpp cff/scalar_mask.cpp)
add_executable(pyobf_native_cff_contribution_edge_region_contract
    tests/contribution_region_contract.cpp cff/region_scope.cpp cff/region_boundary.cpp cff/region_validation.cpp
    cff/control_validation.cpp cff/contribution_edge_source.cpp cff/contribution_marker.cpp cff/contribution_query.cpp
    cff/contribution_edge_flow.cpp cff/state_binding_proof.cpp cff/state_layout.cpp cff/dispatch_tree.cpp cff/dispatch_proof.cpp
    cff/transition_encode.cpp cff/transition_proof.cpp cff/scalar_proof.cpp cff/scalar_mask.cpp)
foreach(kind source flow invoke binding region)
    set(target pyobf_native_cff_contribution_edge_${kind}_contract)
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_include_directories(${target} PRIVATE ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff" "${PROJECT_SOURCE_DIR}/src")
    if(TARGET LLVM)
        target_link_libraries(${target} PRIVATE LLVM)
    else()
        llvm_map_components_to_libnames(edge_libraries Core Support Analysis)
        target_link_libraries(${target} PRIVATE ${edge_libraries})
    endif()
    add_test(NAME ${target} COMMAND ${target})
    set_tests_properties(${target} PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contribution_runtime_directory}")
endforeach()
