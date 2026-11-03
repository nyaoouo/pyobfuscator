cmake_minimum_required(VERSION 3.21)
project(hybrid_project_fixture LANGUAGES CXX)

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

pyobf_native_embed_asset(asset_source asset_header ID sample FILE "${ASSET_FILE}"
    DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/assets")
set(units "")
set(index 0)
foreach(source IN ITEMS "${CMAKE_CURRENT_SOURCE_DIR}/owner.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/whole.cpp"
        "${NATIVE_ROOT}/src/sdk.cpp" ${PYOBF_NATIVE_BACKEND_SDK_SOURCES} "${asset_source}")
    set(unit "${CMAKE_CURRENT_BINARY_DIR}/unit-${index}.ll")
    pyobf_native_compile_ir(OUTPUT "${unit}" SOURCE "${source}"
        INCLUDES "${NATIVE_ROOT}/include" "${CMAKE_CURRENT_BINARY_DIR}/assets"
        DEFINITIONS HYBRID_SUBJECT_BUILD=1 DEPENDS "${asset_header}" "${CMAKE_CURRENT_SOURCE_DIR}/api.hpp")
    list(APPEND units "${unit}")
    math(EXPR index "${index} + 1")
endforeach()
set(combined "${CMAKE_CURRENT_BINARY_DIR}/combined.ll")
add_custom_command(OUTPUT "${combined}"
    COMMAND "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" -S ${units} -o "${combined}"
    DEPENDS ${units} VERBATIM)
set(selection "-pyobf-cff-config=${RECIPE}" "-pyobf-cff-seed=${SEED}")
set(requested "${CMAKE_CURRENT_BINARY_DIR}/requested.ll")
set(requests "${CMAKE_CURRENT_BINARY_DIR}/requests.json")
add_custom_command(OUTPUT "${requested}" "${requests}"
    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "${PLUGIN}"
            -passes=pyobf-native-cff-requests ${selection} "-pyobf-cff-requests-output=${requests}"
            -verify-each -S "${combined}" -o "${requested}"
    DEPENDS "${combined}" "${RECIPE}" "${PLUGIN}" VERBATIM)
set(optimized "${CMAKE_CURRENT_BINARY_DIR}/optimized.ll")
add_custom_command(OUTPUT "${optimized}"
    COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" "-passes=${SOURCE_OPT}" -verify-each -S "${requested}" -o "${optimized}"
    DEPENDS "${requested}" VERBATIM)
if(ARCHIVE_ENABLED)
    pyobf_native_archive_pipeline(prepared merged INPUT "${optimized}"
        PREFIX "${CMAKE_CURRENT_BINARY_DIR}/archive" REQUESTS "${requests}" CFF_ARGS ${selection}
        DEPENDS "${RECIPE}" EXTRA_RUNTIME_SOURCES "${NATIVE_ROOT}/src/archive/asset_identity.cpp"
        INPUT_BACKEND_SOURCES ${PYOBF_NATIVE_BACKEND_SDK_SOURCES})
else()
    set(identity "${CMAKE_CURRENT_BINARY_DIR}/identity.ll")
    pyobf_native_compile_ir(OUTPUT "${identity}" SOURCE "${NATIVE_ROOT}/src/archive/asset_identity.cpp"
        INCLUDES "${NATIVE_ROOT}/include")
    set(identity_requested "${CMAKE_CURRENT_BINARY_DIR}/identity.requested.ll")
    set(identity_requests "${CMAKE_CURRENT_BINARY_DIR}/identity.requests.json")
    add_custom_command(OUTPUT "${identity_requested}" "${identity_requests}"
        COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "${PLUGIN}"
                -passes=pyobf-native-cff-requests "-pyobf-cff-requests-output=${identity_requests}"
                -verify-each -S "${identity}" -o "${identity_requested}"
        DEPENDS "${identity}" "${PLUGIN}" VERBATIM)
    set(prepared "${CMAKE_CURRENT_BINARY_DIR}/prepared.ll")
    set(merged "${CMAKE_CURRENT_BINARY_DIR}/merged.requests.json")
    add_custom_command(OUTPUT "${prepared}"
        COMMAND "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" -S "${optimized}" "${identity_requested}" -o "${prepared}"
        DEPENDS "${optimized}" "${identity_requested}" VERBATIM)
    add_custom_command(OUTPUT "${merged}"
        COMMAND "${Python3_EXECUTABLE}" "${NATIVE_ROOT}/tools/merge_requests.py" "${merged}" "${requests}" "${identity_requests}"
        DEPENDS "${requests}" "${identity_requests}" "${NATIVE_ROOT}/tools/merge_requests.py" VERBATIM)
endif()
set(final_ir "${prepared}")
if(PROTECT)
    set(final_ir "${CMAKE_CURRENT_BINARY_DIR}/protected.ll")
    set(report "${CMAKE_CURRENT_BINARY_DIR}/coverage.json")
    add_custom_command(OUTPUT "${final_ir}" "${report}"
        COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "${PLUGIN}"
                -passes=pyobf-native-cff ${selection} "-pyobf-cff-requests-input=${merged}"
                "-pyobf-cff-report=${report}" -verify-each -S "${prepared}" -o "${final_ir}"
        DEPENDS "${prepared}" "${merged}" "${RECIPE}" "${PLUGIN}" VERBATIM)
endif()
pyobf_native_emit_object("${CMAKE_CURRENT_BINARY_DIR}/subject.obj" "${final_ir}")
add_library(callback_provider SHARED provider.cpp)
target_compile_features(callback_provider PRIVATE cxx_std_17)
target_compile_definitions(callback_provider PRIVATE HYBRID_PROVIDER_BUILD=1)
set_target_properties(callback_provider PROPERTIES PREFIX "")
add_library(hybrid_subject SHARED "${CMAKE_CURRENT_BINARY_DIR}/subject.obj")
set_target_properties(hybrid_subject PROPERTIES PREFIX "" LINKER_LANGUAGE CXX)
target_link_libraries(hybrid_subject PRIVATE callback_provider ${PYOBF_NATIVE_BACKEND_LINK_LIBRARIES})
add_executable(hybrid_probe harness.cpp)
target_compile_features(hybrid_probe PRIVATE cxx_std_17)
target_link_libraries(hybrid_probe PRIVATE hybrid_subject callback_provider)
if(PROTECT)
    set(final_report "${CMAKE_CURRENT_BINARY_DIR}/final.json")
    add_custom_command(OUTPUT "${final_report}"
        COMMAND "${Python3_EXECUTABLE}" "${NATIVE_ROOT}/demo/check_linked_cff.py"
                "${OBJDUMP}" "$<TARGET_FILE:hybrid_subject>" "${report}" --output "${final_report}"
        DEPENDS hybrid_subject "${report}" "${NATIVE_ROOT}/demo/check_linked_cff.py"
            "${NATIVE_ROOT}/demo/cff_contribution_evidence.py" "${NATIVE_ROOT}/demo/cff_contribution_groups.py" VERBATIM)
    add_custom_target(verify_hybrid ALL DEPENDS "${final_report}")
endif()
