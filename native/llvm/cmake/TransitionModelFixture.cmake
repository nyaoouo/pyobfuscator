add_executable(pyobf_native_cff_transition_model_contract tests/transition_model_contract.cpp
    cff/transition_model.cpp cff/transition_predicate_model.cpp cff/transition_literal_model.cpp cff/transition_model_identity.cpp cff/transition_model_match.cpp
    cff/transition_registry.cpp
    cff/opaque_transition.cpp cff/junk_transition.cpp cff/decoy_transition.cpp
    cff/opaque_expression.cpp cff/junk_expression.cpp cff/component_seed.cpp cff/site_origin.cpp cff/transition_encode.cpp cff/scalar_mask.cpp)
target_compile_features(pyobf_native_cff_transition_model_contract PRIVATE cxx_std_17)
target_include_directories(pyobf_native_cff_transition_model_contract PRIVATE
    ${LLVM_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/cff" "${PROJECT_SOURCE_DIR}/src")
if(TARGET LLVM)
    target_link_libraries(pyobf_native_cff_transition_model_contract PRIVATE LLVM)
else()
    llvm_map_components_to_libnames(transition_model_libraries Core Support)
    target_link_libraries(pyobf_native_cff_transition_model_contract PRIVATE ${transition_model_libraries})
endif()
add_test(NAME pyobf_native_cff_transition_model_contract COMMAND pyobf_native_cff_transition_model_contract)
get_filename_component(transition_model_runtime "${CMAKE_CXX_COMPILER}" DIRECTORY)
set_tests_properties(pyobf_native_cff_transition_model_contract PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${transition_model_runtime}")
