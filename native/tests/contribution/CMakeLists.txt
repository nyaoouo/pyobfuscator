find_package(Python3 COMPONENTS Interpreter REQUIRED)
find_package(Threads REQUIRED)
get_filename_component(contribution_test_runtime "${CMAKE_CXX_COMPILER}" DIRECTORY)
add_executable(pyobf_native_contribution_context context.cpp)
target_include_directories(pyobf_native_contribution_context PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(pyobf_native_contribution_context PRIVATE
    pyobf_native_contribution_runtime pyobf_native_contribution_provider Threads::Threads)
add_test(NAME pyobf_native_contribution_context
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_context.py"
        "$<TARGET_FILE:pyobf_native_contribution_context>" "${contribution_test_runtime}")
set_tests_properties(pyobf_native_contribution_context PROPERTIES TIMEOUT 90)

add_executable(pyobf_native_contribution_derive_failure derive_failure.cpp
    "${PROJECT_SOURCE_DIR}/src/contribution/context_derive.cpp")
target_compile_features(pyobf_native_contribution_derive_failure PRIVATE cxx_std_17)
target_include_directories(pyobf_native_contribution_derive_failure PRIVATE "${PROJECT_SOURCE_DIR}/include")
add_test(NAME pyobf_native_contribution_derive_failure COMMAND pyobf_native_contribution_derive_failure)
set_tests_properties(pyobf_native_contribution_derive_failure PROPERTIES TIMEOUT 30
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${contribution_test_runtime}")

add_executable(pyobf_native_contribution_gate_reference gate_fixture.cpp gate_host.cpp)
target_include_directories(pyobf_native_contribution_gate_reference PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(pyobf_native_contribution_gate_reference PRIVATE
    pyobf_native_contribution_gate pyobf_native_contribution_provider pyobf_native_contribution_reference)
add_test(NAME pyobf_native_contribution_gate_reference
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_gate_reference.py"
        "$<TARGET_FILE:pyobf_native_contribution_gate_reference>" "${contribution_test_runtime}")
set_tests_properties(pyobf_native_contribution_gate_reference PROPERTIES TIMEOUT 120)
