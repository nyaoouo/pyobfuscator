cmake_minimum_required(VERSION 3.21)
project(archive_pipeline_fixture LANGUAGES CXX)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
include("${NATIVE_ROOT}/backends/windows_user/Backend.cmake")
include("${NATIVE_ROOT}/cmake/LLVMCompile.cmake")
include("${NATIVE_ROOT}/cmake/ArchivePipeline.cmake")
include("${NATIVE_ROOT}/cmake/Assets.cmake")
add_library(pyobf_native_cff MODULE IMPORTED)
set_target_properties(pyobf_native_cff PROPERTIES IMPORTED_LOCATION "${PLUGIN}")
add_library(pyobf_native_sdk INTERFACE)
set_target_properties(pyobf_native_sdk PROPERTIES
    PYOBF_NATIVE_CAN_ARCHIVE "${PYOBF_NATIVE_BACKEND_CAN_ARCHIVE}"
    PYOBF_NATIVE_ARCHIVE_SOURCES "${PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES}")

set(extra_runtime_sources "")
if(SOURCE_IR)
    set(combined "${SOURCE_IR}")
else()
    pyobf_native_embed_asset(asset_source asset_header ID sample FILE "${ASSET_FILE}"
        DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/assets")
    pyobf_native_compile_ir(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/asset.ll" SOURCE "${asset_source}"
        INCLUDES "${NATIVE_ROOT}/include" "${CMAKE_CURRENT_BINARY_DIR}/assets" DEPENDS "${asset_header}")
    pyobf_native_compile_ir(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/reader.ll"
        SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/reader.cpp"
        INCLUDES "${NATIVE_ROOT}/include" "${CMAKE_CURRENT_BINARY_DIR}/assets" DEPENDS "${asset_header}")
    set(combined "${CMAKE_CURRENT_BINARY_DIR}/combined.ll")
    add_custom_command(OUTPUT "${combined}"
        COMMAND "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" -S "${CMAKE_CURRENT_BINARY_DIR}/asset.ll"
                "${CMAKE_CURRENT_BINARY_DIR}/reader.ll" -o "${combined}"
        DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/asset.ll" "${CMAKE_CURRENT_BINARY_DIR}/reader.ll" VERBATIM)
    list(APPEND extra_runtime_sources "${NATIVE_ROOT}/src/archive/asset_identity.cpp")
endif()
set(requested "${CMAKE_CURRENT_BINARY_DIR}/requested.ll")
set(requests "${CMAKE_CURRENT_BINARY_DIR}/requests.json")
if(NOT RECIPE)
    set(RECIPE "${NATIVE_ROOT}/demo/recipes/archive.json")
endif()
set(selection "-pyobf-cff-config=${RECIPE}")
add_custom_command(OUTPUT "${requested}" "${requests}"
    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "${PLUGIN}"
            -passes=pyobf-native-cff-requests ${selection} "-pyobf-cff-requests-output=${requests}"
            -verify-each -S "${combined}" -o "${requested}"
    DEPENDS "${combined}" "${RECIPE}" VERBATIM)
set(optimized "${CMAKE_CURRENT_BINARY_DIR}/optimized.ll")
add_custom_command(OUTPUT "${optimized}"
    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" "-passes=default<O2>" -verify-each
            -S "${requested}" -o "${optimized}"
    DEPENDS "${requested}" VERBATIM)
pyobf_native_archive_pipeline(prepared merged_requests INPUT "${optimized}"
    PREFIX "${CMAKE_CURRENT_BINARY_DIR}/archive" REQUESTS "${requests}" CFF_ARGS ${selection}
    DEPENDS "${RECIPE}"
    EXTRA_RUNTIME_SOURCES ${extra_runtime_sources})
set(protected "${CMAKE_CURRENT_BINARY_DIR}/protected.ll")
set(report "${CMAKE_CURRENT_BINARY_DIR}/coverage.json")
add_custom_command(OUTPUT "${protected}" "${report}"
    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "${PLUGIN}"
            -passes=pyobf-native-cff ${selection} "-pyobf-cff-requests-input=${merged_requests}"
            "-pyobf-cff-report=${report}" -verify-each -S "${prepared}" -o "${protected}"
    DEPENDS "${prepared}" "${merged_requests}" "${RECIPE}" VERBATIM)
pyobf_native_emit_object("${CMAKE_CURRENT_BINARY_DIR}/protected.obj" "${protected}")
add_library(asset_fixture SHARED "${CMAKE_CURRENT_BINARY_DIR}/protected.obj")
set_target_properties(asset_fixture PROPERTIES LINKER_LANGUAGE CXX PREFIX "")
target_link_libraries(asset_fixture PRIVATE ${PYOBF_NATIVE_BACKEND_LINK_LIBRARIES})
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/final.json"
    COMMAND "${Python3_EXECUTABLE}" "${NATIVE_ROOT}/demo/check_linked_cff.py"
            "${OBJDUMP}" "$<TARGET_FILE:asset_fixture>" "${report}"
            --output "${CMAKE_CURRENT_BINARY_DIR}/final.json"
    DEPENDS asset_fixture "${report}" "${NATIVE_ROOT}/demo/check_linked_cff.py"
        "${NATIVE_ROOT}/demo/cff_contribution_evidence.py" "${NATIVE_ROOT}/demo/cff_contribution_groups.py" VERBATIM)
add_custom_target(verify_asset ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/final.json")
