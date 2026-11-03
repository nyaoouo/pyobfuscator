cmake_minimum_required(VERSION 3.21)
project(pyobf_snapshot_report_fixture LANGUAGES CXX)

set(PYOBF_NATIVE_BUILD_SMOKE OFF CACHE BOOL "" FORCE)
set(PYOBF_NATIVE_BUILD_CONTEXT_RUNTIME ON CACHE BOOL "" FORCE)
set(PYOBF_NATIVE_BUILD_LLVM_PASS OFF CACHE BOOL "" FORCE)
set(PYOBF_NATIVE_BUILD_DEMO OFF CACHE BOOL "" FORCE)
get_filename_component(native_root "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
add_subdirectory("${native_root}" native_runtime)

if(NOT TARGET pyobf_native_code_observer)
    message(FATAL_ERROR "The selected backend has no observer")
endif()
get_target_property(observer_sources pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_CORE_SOURCES)
add_executable(snapshot_report_probe
    "${CMAKE_CURRENT_LIST_DIR}/../snapshot_report_probe.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/../observer_fixture.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/../failure_backend.cpp"
    ${observer_sources}
    "${native_root}/backends/windows_user/operations/atomic.cpp")
target_compile_features(snapshot_report_probe PRIVATE cxx_std_17)
target_include_directories(snapshot_report_probe PRIVATE "${native_root}/src" "${native_root}/include")
find_package(Threads REQUIRED)
target_link_libraries(snapshot_report_probe PRIVATE Threads::Threads)
