add_library(pyobf_native_context_provider SHARED provider.cpp)
target_include_directories(pyobf_native_context_provider PRIVATE "${PROJECT_SOURCE_DIR}/include")
target_compile_features(pyobf_native_context_provider PRIVATE cxx_std_17)
target_link_libraries(pyobf_native_context_provider PRIVATE pyobf_native_bootstrap_context)

find_package(Threads REQUIRED)
add_executable(pyobf_native_context_smoke lifecycle.cpp concurrency.cpp module.cpp)
target_link_libraries(pyobf_native_context_smoke PRIVATE pyobf_native_bootstrap_context Threads::Threads)
if(TARGET pyobf_native_archive_runtime)
    # The combined consumer must not get duplicate memory/atomic/backend definitions.
    target_link_libraries(pyobf_native_context_smoke PRIVATE pyobf_native_archive_runtime)
endif()
add_test(NAME pyobf_native_context_lifetime
    COMMAND pyobf_native_context_smoke "$<TARGET_FILE:pyobf_native_context_provider>")
get_filename_component(context_compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
set_tests_properties(pyobf_native_context_lifetime PROPERTIES TIMEOUT 30
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${context_compiler_directory}")

add_executable(pyobf_native_context_binding binding_smoke.cpp binding_reentrancy.cpp binding_concurrency.cpp)
target_link_libraries(pyobf_native_context_binding PRIVATE pyobf_native_bootstrap_context pyobf_native_sdk Threads::Threads)
add_test(NAME pyobf_native_context_binding
    COMMAND pyobf_native_context_binding "$<TARGET_FILE:pyobf_native_context_provider>")
set_tests_properties(pyobf_native_context_binding PROPERTIES TIMEOUT 30
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${context_compiler_directory}")

get_target_property(context_core pyobf_native_bootstrap_context PYOBF_NATIVE_CONTEXT_CORE_SOURCES)
add_executable(pyobf_native_context_failures failures.cpp ${context_core})
target_compile_features(pyobf_native_context_failures PRIVATE cxx_std_17)
target_include_directories(pyobf_native_context_failures PRIVATE
    "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src")
add_test(NAME pyobf_native_context_failures COMMAND pyobf_native_context_failures)
set_tests_properties(pyobf_native_context_failures PROPERTIES TIMEOUT 30
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${context_compiler_directory}")

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME pyobf_native_context_backend
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_backend.py"
        "${CMAKE_COMMAND}" "${CMAKE_CXX_COMPILER}" "${CMAKE_MAKE_PROGRAM}"
        "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_GENERATOR}")
set_tests_properties(pyobf_native_context_backend PROPERTIES TIMEOUT 120)
