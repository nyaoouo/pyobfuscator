find_package(Python3 COMPONENTS Interpreter REQUIRED)
find_package(Threads REQUIRED)
get_filename_component(capture_runtime_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)

add_executable(pyobf_native_capture_probe probe.cpp descriptor.cpp)
target_link_libraries(pyobf_native_capture_probe PRIVATE pyobf_native_code_capture Threads::Threads)
foreach(variant IN ITEMS 1 2)
    add_library(pyobf_native_capture_sample${variant} SHARED sample.cpp)
    target_compile_definitions(pyobf_native_capture_sample${variant} PRIVATE OFFSET=${variant})
    if(MSVC)
        # Test-only initialized pointer joins executable code; RX admission is checked live.
        # LINK may report LNK4254 for the differing code/initialized-data content flags.
        target_link_options(pyobf_native_capture_sample${variant} PRIVATE "/MERGE:.capture=.text")
    endif()
endforeach()
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
    target_link_options(pyobf_native_capture_sample2 PRIVATE "-Wl,--image-base,0x0")
endif()

if(TARGET pyobf_native_code_observer)
    add_executable(pyobf_native_observer_probe observer_probe.cpp)
    target_link_libraries(pyobf_native_observer_probe PRIVATE pyobf_native_code_observer Threads::Threads)
    add_executable(pyobf_native_observer_time observer_time_probe.cpp
        "${PROJECT_SOURCE_DIR}/src/measurement/observer_time.cpp")
    target_compile_features(pyobf_native_observer_time PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_observer_time PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/include")
    add_test(NAME pyobf_native_observer_time
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_observer_time.py"
            "$<TARGET_FILE:pyobf_native_observer_time>" "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(pyobf_native_observer_time PROPERTIES TIMEOUT 45)
    add_executable(pyobf_native_observer_faults observer_faults.cpp observer_fixture.cpp observer_policy.cpp
        observer_races.cpp observer_failures.cpp failure_backend.cpp ${observer_core_sources}
        ${reference_core_sources} ${reference_archive_sources} ${capture_core_sources} ${observer_context_sources}
        "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/atomic.cpp")
    target_compile_features(pyobf_native_observer_faults PRIVATE cxx_std_17)
    target_link_libraries(pyobf_native_observer_faults PRIVATE Threads::Threads)
    target_include_directories(pyobf_native_observer_faults PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/include")
    add_test(NAME pyobf_native_observer_faults
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_observer_faults.py"
            "$<TARGET_FILE:pyobf_native_observer_faults>" "${CMAKE_CURRENT_BINARY_DIR}"
            --runtime-directory "${capture_runtime_directory}")
    set_tests_properties(pyobf_native_observer_faults PROPERTIES TIMEOUT 90)
    add_executable(pyobf_native_snapshot_report_faults snapshot_report_probe.cpp observer_fixture.cpp
        failure_backend.cpp ${observer_core_sources} ${reference_core_sources} ${reference_archive_sources}
        ${capture_core_sources} ${observer_context_sources}
        "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/atomic.cpp")
    target_compile_features(pyobf_native_snapshot_report_faults PRIVATE cxx_std_17)
    target_link_libraries(pyobf_native_snapshot_report_faults PRIVATE Threads::Threads)
    target_include_directories(pyobf_native_snapshot_report_faults PRIVATE
        "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/include")
    add_test(NAME pyobf_native_snapshot_report_faults
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_snapshot_report.py"
            "$<TARGET_FILE:pyobf_native_snapshot_report_faults>" "${CMAKE_CURRENT_BINARY_DIR}"
            --runtime-directory "${capture_runtime_directory}")
    set_tests_properties(pyobf_native_snapshot_report_faults PROPERTIES TIMEOUT 90)
    add_executable(pyobf_native_owner_reader_faults owner_reader_faults.cpp observer_fixture.cpp failure_backend.cpp
        ${observer_core_sources} ${reference_core_sources} ${reference_archive_sources} ${capture_core_sources}
        ${observer_context_sources} "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/atomic.cpp")
    target_compile_features(pyobf_native_owner_reader_faults PRIVATE cxx_std_17)
    target_link_libraries(pyobf_native_owner_reader_faults PRIVATE Threads::Threads)
    target_include_directories(pyobf_native_owner_reader_faults PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/include")
    add_test(NAME pyobf_native_owner_reader_faults
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_observer_faults.py"
            "$<TARGET_FILE:pyobf_native_owner_reader_faults>" "${CMAKE_CURRENT_BINARY_DIR}"
            --runtime-directory "${capture_runtime_directory}" --reader-cases)
    set_tests_properties(pyobf_native_owner_reader_faults PROPERTIES TIMEOUT 90)
    add_executable(pyobf_native_measured_key_probe measured_key_probe.cpp)
    target_link_libraries(pyobf_native_measured_key_probe PRIVATE pyobf_native_measured_release)
    add_executable(pyobf_native_measured_key_faults measured_key_faults.cpp observer_fixture.cpp failure_backend.cpp
        ${measured_release_sources} ${observer_core_sources} ${reference_core_sources} ${reference_archive_sources}
        ${capture_core_sources} ${observer_context_sources}
        "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/atomic.cpp")
    target_compile_features(pyobf_native_measured_key_faults PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_measured_key_faults PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/include")
    add_test(NAME pyobf_native_measured_key_faults
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_observer_faults.py"
            "$<TARGET_FILE:pyobf_native_measured_key_faults>" "${CMAKE_CURRENT_BINARY_DIR}"
            --runtime-directory "${capture_runtime_directory}")
    set_tests_properties(pyobf_native_measured_key_faults PROPERTIES TIMEOUT 90)
    add_executable(pyobf_native_measured_contribution_probe measured_key_probe.cpp measured_contribution_cases.cpp)
    target_compile_definitions(pyobf_native_measured_contribution_probe PRIVATE PYOBF_TEST_MEASURED_CONTRIBUTION=1)
    target_link_libraries(pyobf_native_measured_contribution_probe PRIVATE pyobf_native_measured_contribution)
    add_executable(pyobf_native_measured_contribution_faults measured_key_faults.cpp measured_contribution_faults.cpp
        observer_fixture.cpp failure_backend.cpp ${measured_contribution_sources} ${measured_release_sources}
        ${observer_core_sources} ${reference_core_sources} ${reference_archive_sources} ${capture_core_sources}
        ${observer_context_sources} "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/atomic.cpp")
    target_compile_definitions(pyobf_native_measured_contribution_faults PRIVATE PYOBF_TEST_MEASURED_CONTRIBUTION=1)
    target_compile_features(pyobf_native_measured_contribution_faults PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_measured_contribution_faults PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/include")
    add_test(NAME pyobf_native_measured_contribution_faults
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_observer_faults.py"
            "$<TARGET_FILE:pyobf_native_measured_contribution_faults>" "${CMAKE_CURRENT_BINARY_DIR}"
            --runtime-directory "${capture_runtime_directory}")
    set_tests_properties(pyobf_native_measured_contribution_faults PROPERTIES TIMEOUT 90)
    add_executable(pyobf_native_measured_scope_probe measured_key_probe.cpp measured_contribution_cases.cpp scope_cases.cpp scope_body.cpp)
    target_compile_definitions(pyobf_native_measured_scope_probe PRIVATE PYOBF_TEST_MEASURED_CONTRIBUTION=1 PYOBF_TEST_MEASURED_SCOPE=1)
    target_link_libraries(pyobf_native_measured_scope_probe PRIVATE pyobf_native_measured_scope_reference Threads::Threads)
    get_target_property(scope_fault_sources pyobf_native_measured_contribution_faults SOURCES)
    add_executable(pyobf_native_measured_scope_faults ${scope_fault_sources} scope_faults.cpp ${measured_scope_sources})
    target_compile_definitions(pyobf_native_measured_scope_faults PRIVATE PYOBF_TEST_MEASURED_CONTRIBUTION=1 PYOBF_TEST_MEASURED_SCOPE=1)
    target_compile_features(pyobf_native_measured_scope_faults PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_measured_scope_faults PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/include")
    add_test(NAME pyobf_native_measured_scope_faults
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_observer_faults.py"
            "$<TARGET_FILE:pyobf_native_measured_scope_faults>" "${CMAKE_CURRENT_BINARY_DIR}"
            --runtime-directory "${capture_runtime_directory}")
    set_tests_properties(pyobf_native_measured_scope_faults PROPERTIES TIMEOUT 90)
endif()

add_test(NAME pyobf_native_code_capture
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_capture.py"
        "$<TARGET_FILE:pyobf_native_capture_probe>" "${capture_runtime_directory}" "${CMAKE_CURRENT_BINARY_DIR}"
        --sample "$<TARGET_FILE:pyobf_native_capture_sample1>" --sample "$<TARGET_FILE:pyobf_native_capture_sample2>")
set_tests_properties(pyobf_native_code_capture PROPERTIES TIMEOUT 90)

add_executable(pyobf_native_capture_failures failures.cpp failure_backend.cpp ${capture_core_sources})
target_compile_features(pyobf_native_capture_failures PRIVATE cxx_std_17)
target_include_directories(pyobf_native_capture_failures PRIVATE "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src")
add_test(NAME pyobf_native_code_capture_failures
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_failures.py"
        "$<TARGET_FILE:pyobf_native_capture_failures>" "${capture_runtime_directory}")
set_tests_properties(pyobf_native_code_capture_failures PROPERTIES TIMEOUT 30)

if(TARGET pyobf_native_code_reference)
    add_executable(pyobf_native_reference_probe reference_probe.cpp)
    target_link_libraries(pyobf_native_reference_probe PRIVATE pyobf_native_code_reference Threads::Threads)
    add_executable(pyobf_native_reference_faults reference_faults.cpp failure_backend.cpp
        ${reference_core_sources} ${reference_archive_sources} ${capture_core_sources}
        "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/atomic.cpp")
    target_compile_features(pyobf_native_reference_faults PRIVATE cxx_std_17)
    target_include_directories(pyobf_native_reference_faults PRIVATE "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src")
endif()
