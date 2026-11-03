include_guard(GLOBAL)
if(NOT TARGET pyobf_native_cff_contribution_fixture)
    return()
endif()
add_test(NAME pyobf_native_demo_cff_contribution
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_cff_contribution.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}"
        "$<TARGET_FILE:pyobf_native_cff_contribution_fixture>" "${CMAKE_CURRENT_BINARY_DIR}" ${path_fold_ipo})
set_tests_properties(pyobf_native_demo_cff_contribution PROPERTIES TIMEOUT 90)
