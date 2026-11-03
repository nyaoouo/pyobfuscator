cmake_minimum_required(VERSION 3.21)
project(pyobfuscator_native LANGUAGES CXX)

include(cmake/Options.cmake)
include(cmake/Backends.cmake)

if(PYOBF_NATIVE_BUILD_SMOKE OR PYOBF_NATIVE_BUILD_DEMO)
    enable_testing()
endif()

# Interface sources compile inside each consumer, so distributing this SDK does not require
# shipping a prebuilt library and a later LLVM pipeline can see its implementation.
add_library(pyobf_native_sdk INTERFACE)
set_target_properties(pyobf_native_sdk PROPERTIES
    PYOBF_NATIVE_CAN_ARCHIVE "${PYOBF_NATIVE_BACKEND_CAN_ARCHIVE}"
    PYOBF_NATIVE_ARCHIVE_SOURCES "${PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES}")
target_compile_features(pyobf_native_sdk INTERFACE cxx_std_17)
target_include_directories(pyobf_native_sdk INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_sources(pyobf_native_sdk INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sdk.cpp"
    ${PYOBF_NATIVE_BACKEND_SDK_SOURCES})

if(PYOBF_NATIVE_BUILD_ARCHIVE_RUNTIME)
    add_subdirectory(archive)
endif()

if(PYOBF_NATIVE_BUILD_CONTEXT_RUNTIME OR PYOBF_NATIVE_BUILD_DEMO)
    add_subdirectory(context)
    add_subdirectory(contribution)
    if(PYOBF_NATIVE_BACKEND_CAN_CODE_CAPTURE)
        add_subdirectory(measurement)
    endif()
endif()

if(PYOBF_NATIVE_BUILD_SMOKE)
    add_subdirectory(tests)
endif()

if(PYOBF_NATIVE_BUILD_LLVM_PASS)
    add_subdirectory(llvm)
endif()

include(context/Checks.cmake)
include(contribution/Checks.cmake)
include(measurement/Checks.cmake)

if(PYOBF_NATIVE_BUILD_SMOKE AND TARGET pyobf_native_archive_runtime AND TARGET pyobf_native_cff
        AND PYOBF_NATIVE_BACKEND_ID STREQUAL "windows_user"
        AND CMAKE_CXX_COMPILER_ID MATCHES "Clang"
        AND CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
    find_program(PYOBF_ARCHIVE_OPT NAMES opt HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
    find_program(PYOBF_ARCHIVE_LLVM_LINK NAMES llvm-link HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
    find_program(PYOBF_ARCHIVE_OBJDUMP NAMES llvm-objdump HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
    add_test(NAME pyobf_native_archive_cff
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/check_archive_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_ARCHIVE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_ARCHIVE_LLVM_LINK}" "${PYOBF_ARCHIVE_OBJDUMP}"
                "${PROJECT_SOURCE_DIR}/demo/check_linked_cff.py"
                "${PROJECT_BINARY_DIR}/tests/archive_fixture.hpp"
                "${PROJECT_BINARY_DIR}/tests/archive_fixture.cpp"
                "${PROJECT_SOURCE_DIR}/tests/archive_smoke.cpp" "${PROJECT_BINARY_DIR}/tests"
                "${PROJECT_SOURCE_DIR}/src/archive/format.cpp"
                "${PROJECT_SOURCE_DIR}/src/archive/acquire.cpp"
                "${PROJECT_SOURCE_DIR}/src/archive/require.cpp"
                ${PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES})
    add_test(NAME pyobf_native_archive_plan
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/check_archive_plan.py"
                "${PYOBF_ARCHIVE_OPT}" "$<TARGET_FILE:pyobf_native_cff>" "${PROJECT_BINARY_DIR}/tests")
    add_test(NAME pyobf_native_archive_protected
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/check_archive_protected.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_ARCHIVE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_ARCHIVE_LLVM_LINK}" "${PYOBF_ARCHIVE_OBJDUMP}"
                "${PROJECT_SOURCE_DIR}/demo/check_linked_cff.py" "${PROJECT_BINARY_DIR}/tests")
    get_filename_component(archive_compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    find_program(PYOBF_ARCHIVE_NINJA NAMES ninja HINTS "${archive_compiler_directory}" REQUIRED)
    add_test(NAME pyobf_native_archive_pipeline
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/check_archive_pipeline.py"
                "${CMAKE_COMMAND}" "${PYOBF_ARCHIVE_NINJA}" "${CMAKE_CXX_COMPILER}"
                "${PYOBF_ARCHIVE_OPT}" "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_ARCHIVE_LLVM_LINK}"
                "${PYOBF_ARCHIVE_OBJDUMP}" "${PROJECT_BINARY_DIR}/tests")
    add_test(NAME pyobf_native_archive_empty
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/check_archive_empty.py"
                "${CMAKE_COMMAND}" "${PYOBF_ARCHIVE_NINJA}" "${CMAKE_CXX_COMPILER}"
                "${PYOBF_ARCHIVE_OPT}" "$<TARGET_FILE:pyobf_native_cff>" "${PYOBF_ARCHIVE_LLVM_LINK}"
                "${PYOBF_ARCHIVE_OBJDUMP}" "${PROJECT_BINARY_DIR}/tests")
endif()

if(PYOBF_NATIVE_BUILD_DEMO)
    if(NOT PYOBF_NATIVE_BUILD_LLVM_PASS)
        message(FATAL_ERROR "PYOBF_NATIVE_BUILD_DEMO requires PYOBF_NATIVE_BUILD_LLVM_PASS=ON")
    endif()
    add_subdirectory(demo)
endif()
