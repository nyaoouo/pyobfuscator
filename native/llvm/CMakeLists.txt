find_package(LLVM CONFIG QUIET)
if(NOT LLVM_FOUND)
    message(FATAL_ERROR
        "PYOBF_NATIVE_BUILD_LLVM_PASS=ON requires LLVM development files; set LLVM_DIR")
endif()

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

add_llvm_pass_plugin(pyobf_native_cff
    archive/pipeline.cpp
    archive/bindings_reader.cpp
    archive/wrapper_verify.cpp
    archive/materialize.cpp
    archive/empty_plan.cpp
    archive/key_address.cpp
    archive/source_report.cpp
    archive/constant_bits.cpp
    archive/collect.cpp
    archive/control_operands.cpp
    archive/use_closure.cpp
    archive/instrument.cpp
    archive/manifest.cpp
    cff/pass.cpp
    cff/pipeline.cpp
    cff/generated_ownership.cpp
    cff/untransformed_inventory.cpp
    cff/owner_reader_bindings.cpp
    cff/owner_reader_flow.cpp
    cff/owner_reader_contract.cpp
    cff/owner_creator_flow.cpp
    cff/owner_post_flow.cpp
    cff/owner_post_child_flow.cpp
    cff/owner_post_mixed_child_flow.cpp
    cff/contribution_private.cpp
    cff/contribution_query.cpp
    cff/contribution_sources.cpp
    cff/contribution_source_config.cpp
    cff/contribution_mix_plan.cpp
    cff/contribution_mix_emit.cpp
    cff/contribution_mix_proof.cpp
    cff/contribution_group_acquire.cpp
    cff/contribution_group_queries.cpp
    cff/contribution_group_bind.cpp
    cff/contribution_group_proof.cpp
    cff/contribution_group_report.cpp
    cff/contribution_options.cpp
    cff/contribution_edge_source.cpp
    cff/contribution_edge_plan.cpp
    cff/contribution_edge_inventory.cpp
    cff/contribution_edge_alias.cpp
    cff/contribution_edge_instrument.cpp
    cff/contribution_edge_lower.cpp
    cff/contribution_edge_invoke.cpp
    cff/contribution_frame_trace.cpp
    cff/contribution_edge_flow.cpp
    cff/contribution_artifacts.cpp
    cff/contribution_marker.cpp
    cff/contribution_acquire.cpp
    cff/contribution_normalize.cpp
    cff/contribution_bind.cpp
    cff/contribution_proof.cpp
    cff/contribution_seal.cpp
    cff/contribution_route_seal.cpp
    cff/selection.cpp
    cff/recipe_config.cpp
    cff/component_registry.cpp
    cff/component_seed.cpp
    cff/cfg_sites.cpp
    cff/cfg_origin.cpp
    cff/preparation.cpp
    cff/module_prepare.cpp
    cff/call_frame_sites.cpp
    cff/call_abi_retention.cpp
    cff/external_calls.cpp
    cff/call_frame_plan.cpp
    cff/call_frame_metadata.cpp
    cff/call_frame_rewrite.cpp
    cff/frame_eh.cpp
    cff/frame_eh_guard.cpp
    cff/frame_profile.cpp
    cff/frame_profile_guard.cpp
    cff/call_frame_verify.cpp
    cff/frame_address.cpp
    cff/call_preparation.cpp
    cff/call_steps.cpp
    cff/call_address_bind.cpp
    cff/call_address_emit.cpp
    cff/call_address_proof.cpp
    cff/call_step_proof.cpp
    cff/call_preparation_verify.cpp
    cff/ssa_origin.cpp
    cff/local_sites.cpp
    cff/local_metadata.cpp
    cff/local_table.cpp
    cff/local_bind.cpp
    cff/local_proof.cpp
    cff/local_table_proof.cpp
    cff/local_verify.cpp
    cff/scalar_proof.cpp
    cff/bogus_blocks.cpp
    cff/bogus_control_plan.cpp
    cff/bogus_control_descriptor.cpp
    cff/bogus_control_proof.cpp
    cff/bogus_clones.cpp
    cff/bogus_synthesis.cpp
    cff/transition_sites.cpp
    cff/opaque_expression.cpp
    cff/opaque_choices.cpp
    cff/junk_expression.cpp
    cff/reachable_junk.cpp
    cff/site_prepare.cpp
    cff/mutation_guard.cpp
    cff/dependency_contract.cpp
    cff/site_report.cpp
    cff/exceptional_origins.cpp
    cff/site_alias.cpp
    cff/site_alias_graph.cpp
    cff/site_provenance.cpp
    cff/site_origin.cpp
    cff/report_writer.cpp
    cff/registry.cpp
    cff/marker_selection.cpp
    cff/request_manifest.cpp
    cff/relative_tree.cpp
    cff/region_relative_tree.cpp
    cff/region_validation.cpp
    cff/region_rewrite.cpp
    cff/region_scope.cpp
    cff/region_boundary.cpp
    cff/region_pipeline.cpp
    cff/validation.cpp
    cff/control_validation.cpp
    cff/hybrid_eh_validation.cpp
    cff/hybrid_eh_registry.cpp
    cff/hybrid_eh_prepare.cpp
    cff/hybrid_eh_edges.cpp
    cff/hybrid_eh_bind.cpp
    cff/hybrid_eh_report.cpp
    cff/hybrid_flow_plan.cpp
    cff/hybrid_flow_verify.cpp
    cff/transition_proof.cpp
    cff/dispatch_proof.cpp
    cff/block_pad.cpp
    cff/block_split.cpp
    cff/block_deduplicate.cpp
    cff/common_exit.cpp
    cff/ssa_lower.cpp
    cff/switch_lower.cpp
    cff/switch_lower_edges.cpp
    cff/state_layout.cpp
    cff/block_layout.cpp
    cff/constant_hide.cpp
    cff/scalar_mask.cpp
    cff/compare_codec.cpp
    cff/compare_hide.cpp
    cff/archive_keys.cpp
    cff/call_indirect.cpp
    cff/reference_sites.cpp
    cff/reference_table.cpp
    cff/import_routes.cpp
    cff/import_table.cpp
    cff/import_proof.cpp
    cff/reference_bind.cpp
    cff/reference_proof.cpp
    cff/decoy_transition.cpp
    cff/transition_encode.cpp
    cff/transition_rewrite.cpp
    cff/transition_model.cpp
    cff/transition_predicate_model.cpp
    cff/transition_literal_model.cpp
    cff/hybrid_scalar_bindings.cpp
    cff/transition_registry.cpp
    cff/transition_layer_descriptor.cpp
    cff/transition_layer_selection.cpp
    cff/transition_layers.cpp
    cff/transition_model_identity.cpp
    cff/transition_model_match.cpp
    cff/state_binding_proof.cpp
    cff/opaque_transition.cpp
    cff/junk_transition.cpp
    cff/contribution_expression.cpp
    cff/contribution_validate.cpp
    cff/contribution_resolve.cpp
    cff/path_fold_emit.cpp
    cff/path_fold_sites.cpp
    cff/path_fold_retain.cpp
    cff/path_fold_bind.cpp
    cff/path_fold_proof.cpp
    cff/path_fold_seal.cpp
    cff/state_rewrite.cpp
    cff/dispatch_tree.cpp)
target_compile_features(pyobf_native_cff PRIVATE cxx_std_17)
target_include_directories(pyobf_native_cff PRIVATE ${LLVM_INCLUDE_DIRS}
    "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/demo")

if(PYOBF_NATIVE_BUILD_SMOKE)
    add_executable(pyobf_native_cff_path_fold_seal
        tests/path_fold_seal.cpp cff/path_fold_seal.cpp cff/path_fold_sites.cpp
        cff/path_fold_proof.cpp cff/path_fold_emit.cpp cff/site_origin.cpp)
    target_compile_features(pyobf_native_cff_path_fold_seal PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_path_fold_seal PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff" "${PROJECT_SOURCE_DIR}/src")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_path_fold_seal PRIVATE LLVM)
    else()
        llvm_map_components_to_libnames(path_fold_seal_libraries Core Support)
        target_link_libraries(pyobf_native_cff_path_fold_seal PRIVATE ${path_fold_seal_libraries})
    endif()
    add_test(NAME pyobf_native_cff_path_fold_seal COMMAND pyobf_native_cff_path_fold_seal)
    get_filename_component(path_fold_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set_tests_properties(pyobf_native_cff_path_fold_seal PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${path_fold_runtime_directory}")
    add_executable(pyobf_native_cff_path_fold_fixture
        tests/path_fold_fixture.cpp cff/path_fold_emit.cpp)
    include(cmake/ContributionFixture.cmake)
    include(cmake/TransitionModelFixture.cmake)
    target_compile_features(pyobf_native_cff_path_fold_fixture PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_path_fold_fixture PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff" "${PROJECT_SOURCE_DIR}/src")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_path_fold_fixture PRIVATE LLVM)
    else()
        llvm_map_components_to_libnames(path_fold_libraries Core Support)
        target_link_libraries(pyobf_native_cff_path_fold_fixture PRIVATE ${path_fold_libraries})
    endif()
    add_executable(pyobf_native_cff_contract_smoke
        tests/contract_smoke.cpp cff/mutation_guard.cpp cff/site_alias_graph.cpp cff/cfg_origin.cpp)
    target_compile_features(pyobf_native_cff_contract_smoke PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_contract_smoke PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_contract_smoke PRIVATE LLVM)
    else()
        llvm_map_components_to_libnames(contract_libraries Core Support)
        target_link_libraries(pyobf_native_cff_contract_smoke PRIVATE ${contract_libraries})
    endif()
    add_test(NAME pyobf_native_cff_mutation_contract COMMAND pyobf_native_cff_contract_smoke)
    get_filename_component(contract_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set_tests_properties(pyobf_native_cff_mutation_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contract_runtime_directory}")
    add_executable(pyobf_native_cff_expression_fixture
        tests/expression_fixture.cpp cff/opaque_expression.cpp cff/junk_expression.cpp)
    target_compile_features(pyobf_native_cff_expression_fixture PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_expression_fixture PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_expression_fixture PRIVATE LLVM)
    else()
        target_link_libraries(pyobf_native_cff_expression_fixture PRIVATE ${contract_libraries})
    endif()
    add_executable(pyobf_native_cff_scalar_fixture
        tests/scalar_fixture.cpp cff/scalar_mask.cpp cff/compare_codec.cpp)
    target_compile_features(pyobf_native_cff_scalar_fixture PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_scalar_fixture PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_scalar_fixture PRIVATE LLVM)
    else()
        target_link_libraries(pyobf_native_cff_scalar_fixture PRIVATE ${contract_libraries})
    endif()
    add_executable(pyobf_native_cff_reference_contract
        tests/reference_contract.cpp cff/reference_proof.cpp cff/scalar_mask.cpp
        cff/import_proof.cpp cff/scalar_proof.cpp cff/call_step_proof.cpp)
    target_compile_features(pyobf_native_cff_reference_contract PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_reference_contract PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_reference_contract PRIVATE LLVM)
    else()
        target_link_libraries(pyobf_native_cff_reference_contract PRIVATE ${contract_libraries})
    endif()
    add_test(NAME pyobf_native_cff_reference_contract COMMAND pyobf_native_cff_reference_contract)
    set_tests_properties(pyobf_native_cff_reference_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contract_runtime_directory}")
    add_executable(pyobf_native_cff_import_contract tests/import_contract.cpp cff/reference_proof.cpp
        cff/import_proof.cpp cff/scalar_mask.cpp cff/scalar_proof.cpp cff/call_step_proof.cpp)
    target_compile_features(pyobf_native_cff_import_contract PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_import_contract PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_import_contract PRIVATE LLVM)
    else()
        target_link_libraries(pyobf_native_cff_import_contract PRIVATE ${contract_libraries})
    endif()
    add_test(NAME pyobf_native_cff_import_contract COMMAND pyobf_native_cff_import_contract)
    set_tests_properties(pyobf_native_cff_import_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contract_runtime_directory}")
    add_executable(pyobf_native_cff_frame_eh_contract tests/frame_eh_contract.cpp
        cff/frame_eh_guard.cpp cff/exceptional_origins.cpp)
    target_compile_features(pyobf_native_cff_frame_eh_contract PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_frame_eh_contract PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_frame_eh_contract PRIVATE LLVM)
    else()
        llvm_map_components_to_libnames(frame_eh_libraries Core Support Analysis)
        target_link_libraries(pyobf_native_cff_frame_eh_contract PRIVATE ${frame_eh_libraries})
    endif()
    add_test(NAME pyobf_native_cff_frame_eh_contract COMMAND pyobf_native_cff_frame_eh_contract)
    set_tests_properties(pyobf_native_cff_frame_eh_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contract_runtime_directory}")
    add_executable(pyobf_native_cff_hybrid_flow_contract tests/hybrid_flow_contract.cpp
        cff/hybrid_flow_plan.cpp cff/hybrid_flow_verify.cpp cff/state_binding_proof.cpp cff/transition_proof.cpp
        cff/dispatch_proof.cpp cff/transition_encode.cpp cff/state_layout.cpp cff/dispatch_tree.cpp
        cff/hybrid_eh_bind.cpp cff/scalar_proof.cpp cff/scalar_mask.cpp cff/call_step_proof.cpp
        cff/path_fold_proof.cpp cff/path_fold_emit.cpp)
    target_compile_features(pyobf_native_cff_hybrid_flow_contract PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_hybrid_flow_contract PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff" "${PROJECT_SOURCE_DIR}/src")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_hybrid_flow_contract PRIVATE LLVM)
    else()
        target_link_libraries(pyobf_native_cff_hybrid_flow_contract PRIVATE ${contract_libraries})
    endif()
    add_test(NAME pyobf_native_cff_hybrid_flow_contract COMMAND pyobf_native_cff_hybrid_flow_contract)
    set_tests_properties(pyobf_native_cff_hybrid_flow_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contract_runtime_directory}")
    add_executable(pyobf_native_cff_frame_profile_contract tests/frame_profile_contract.cpp
        cff/frame_profile.cpp cff/frame_profile_guard.cpp cff/call_frame_metadata.cpp)
    target_compile_features(pyobf_native_cff_frame_profile_contract PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_frame_profile_contract PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_frame_profile_contract PRIVATE LLVM)
    else()
        target_link_libraries(pyobf_native_cff_frame_profile_contract PRIVATE ${contract_libraries})
    endif()
    add_test(NAME pyobf_native_cff_frame_profile_contract COMMAND pyobf_native_cff_frame_profile_contract)
    set_tests_properties(pyobf_native_cff_frame_profile_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contract_runtime_directory}")
    add_executable(pyobf_native_cff_frame_contract
        tests/frame_contract.cpp cff/call_frame_metadata.cpp cff/call_frame_verify.cpp
        cff/frame_address.cpp cff/reference_proof.cpp cff/ssa_origin.cpp cff/import_proof.cpp cff/scalar_proof.cpp
        cff/call_address_proof.cpp cff/call_step_proof.cpp cff/scalar_mask.cpp)
    target_compile_features(pyobf_native_cff_frame_contract PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_frame_contract PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_frame_contract PRIVATE LLVM)
    else()
        target_link_libraries(pyobf_native_cff_frame_contract PRIVATE ${contract_libraries})
    endif()
    add_test(NAME pyobf_native_cff_frame_contract COMMAND pyobf_native_cff_frame_contract)
    set_tests_properties(pyobf_native_cff_frame_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contract_runtime_directory}")
    add_executable(pyobf_native_cff_preparation_contract
        tests/preparation_contract.cpp cff/call_frame_metadata.cpp cff/call_frame_verify.cpp
        cff/frame_address.cpp cff/reference_proof.cpp cff/ssa_origin.cpp cff/scalar_mask.cpp cff/import_proof.cpp cff/scalar_proof.cpp
        cff/call_address_emit.cpp cff/call_address_proof.cpp cff/call_step_proof.cpp cff/call_preparation_verify.cpp)
    target_compile_features(pyobf_native_cff_preparation_contract PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_preparation_contract PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_preparation_contract PRIVATE LLVM)
    else()
        llvm_map_components_to_libnames(preparation_libraries Core Support TransformUtils)
        target_link_libraries(pyobf_native_cff_preparation_contract PRIVATE ${preparation_libraries})
    endif()
    add_test(NAME pyobf_native_cff_preparation_contract COMMAND pyobf_native_cff_preparation_contract)
    set_tests_properties(pyobf_native_cff_preparation_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contract_runtime_directory}")
    add_executable(pyobf_native_cff_local_contract
        tests/local_contract.cpp cff/local_metadata.cpp cff/local_sites.cpp cff/local_proof.cpp
        cff/local_table_proof.cpp cff/local_verify.cpp cff/scalar_mask.cpp cff/scalar_proof.cpp
        cff/site_origin.cpp cff/ssa_origin.cpp cff/call_frame_metadata.cpp cff/call_step_proof.cpp)
    target_compile_features(pyobf_native_cff_local_contract PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_cff_local_contract PRIVATE
        ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff")
    if(TARGET LLVM)
        target_link_libraries(pyobf_native_cff_local_contract PRIVATE LLVM)
    else()
        target_link_libraries(pyobf_native_cff_local_contract PRIVATE ${contract_libraries})
    endif()
    add_test(NAME pyobf_native_cff_local_contract COMMAND pyobf_native_cff_local_contract)
    set_tests_properties(pyobf_native_cff_local_contract PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contract_runtime_directory}")
endif()

message(STATUS "Native CFF pass supports selected branch/switch LLVM functions with ordinary SSA/PHI")
