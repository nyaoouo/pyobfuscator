add_executable(pyobf_native_sdk_smoke sdk_smoke.cpp)
target_link_libraries(pyobf_native_sdk_smoke PRIVATE pyobf_native_sdk)
add_test(NAME pyobf_native_sdk_smoke COMMAND pyobf_native_sdk_smoke)

get_filename_component(compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
if(PYOBF_NATIVE_BACKEND_ID STREQUAL "windows_user")
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    find_package(Threads REQUIRED)
    set(windows_hash_source "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/hash.cpp")
    add_executable(pyobf_native_sha256 hash_sha256.cpp "${windows_hash_source}"
        "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/memory.cpp")
    add_executable(pyobf_native_sha256_failure hash_sha256_failure.cpp "${windows_hash_source}")
    foreach(hash_target pyobf_native_sha256 pyobf_native_sha256_failure)
        target_compile_features(${hash_target} PRIVATE cxx_std_17)
        target_include_directories(${hash_target} PRIVATE "${PROJECT_SOURCE_DIR}/include")
        target_link_libraries(${hash_target} PRIVATE bcrypt)
    endforeach()
    target_link_libraries(pyobf_native_sha256 PRIVATE Threads::Threads)
    add_test(NAME pyobf_native_sha256
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_hash_sha256.py"
            "$<TARGET_FILE:pyobf_native_sha256>")
    add_test(NAME pyobf_native_sha256_failure COMMAND pyobf_native_sha256_failure)
    set_tests_properties(pyobf_native_sha256 pyobf_native_sha256_failure PROPERTIES TIMEOUT 30
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
endif()
set_tests_properties(pyobf_native_sdk_smoke PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")

add_executable(pyobf_native_sdk_snapshot sdk_snapshot.cpp)
find_package(Threads REQUIRED)
target_link_libraries(pyobf_native_sdk_snapshot PRIVATE pyobf_native_sdk Threads::Threads)
add_test(NAME pyobf_native_sdk_snapshot COMMAND pyobf_native_sdk_snapshot)
set_tests_properties(pyobf_native_sdk_snapshot PROPERTIES TIMEOUT 30
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")

if(WIN32)
    add_library(pyobf_native_sample_dll SHARED sample_dll.cpp)
    target_link_libraries(pyobf_native_sample_dll PRIVATE pyobf_native_sdk)

    add_executable(pyobf_native_load_smoke load_smoke.cpp)
    target_compile_features(pyobf_native_load_smoke PRIVATE cxx_std_17)
    add_test(NAME pyobf_native_load_smoke
        COMMAND pyobf_native_load_smoke "$<TARGET_FILE:pyobf_native_sample_dll>")
    set_tests_properties(pyobf_native_load_smoke PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
endif()

if(TARGET pyobf_native_archive_runtime)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    execute_process(COMMAND "${Python3_EXECUTABLE}" -c "import cryptography"
                    RESULT_VARIABLE archive_crypto_result)
    if(NOT archive_crypto_result EQUAL 0)
        message(FATAL_ERROR "Archive fixtures require cryptography in Python3_EXECUTABLE")
    endif()
    set(archive_header "${CMAKE_CURRENT_BINARY_DIR}/archive_fixture.hpp")
    set(archive_source "${CMAKE_CURRENT_BINARY_DIR}/archive_fixture.cpp")
    add_custom_command(OUTPUT "${archive_header}" "${archive_source}"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/archive_fixture.py"
                "${archive_header}" "${archive_source}"
        DEPENDS archive_fixture.py "${PROJECT_SOURCE_DIR}/tools/archive_format.py"
                "${PROJECT_SOURCE_DIR}/tools/pack_archive.py"
        VERBATIM)
    add_executable(pyobf_native_archive_smoke archive_smoke.cpp "${archive_source}" "${archive_header}")
    target_include_directories(pyobf_native_archive_smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(pyobf_native_archive_smoke PRIVATE pyobf_native_archive_runtime)
    add_test(NAME pyobf_native_archive_runtime COMMAND pyobf_native_archive_smoke)
    add_test(NAME pyobf_native_archive_require_failure
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_archive_failure.py"
                "$<TARGET_FILE:pyobf_native_archive_smoke>")
    add_test(NAME pyobf_native_archive_tool
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_archive_tool.py"
                "${CMAKE_CURRENT_BINARY_DIR}")
    add_test(NAME pyobf_native_archive_build_tools
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_archive_build_tools.py"
                "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(pyobf_native_archive_runtime pyobf_native_archive_require_failure PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${compiler_directory}")
endif()
