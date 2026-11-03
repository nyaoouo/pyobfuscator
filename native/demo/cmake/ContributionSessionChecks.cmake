include_guard(GLOBAL)
get_target_property(contribution_client_source pyobf_native_contribution_runtime PYOBF_NATIVE_CONTRIBUTION_CLIENT_SOURCE)
foreach(profile none O2)
    add_test(NAME pyobf_native_demo_contribution_session_${profile}
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_contribution_session.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/recipes/bootstrap.json" "${CMAKE_CURRENT_BINARY_DIR}"
            "${release_plan}" "${release_record_blob}" "${profile}" ${session_ipo}
            --sources ${session_authored_sources} "${contribution_client_source}")
    set_tests_properties(pyobf_native_demo_contribution_session_${profile} PROPERTIES TIMEOUT 180)
endforeach()
