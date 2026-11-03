add_library(pyobf_native_contribution_runtime INTERFACE)
target_link_libraries(pyobf_native_contribution_runtime INTERFACE pyobf_native_bootstrap_context)
target_sources(pyobf_native_contribution_runtime INTERFACE "${PROJECT_SOURCE_DIR}/src/contribution/client.cpp")
set_target_properties(pyobf_native_contribution_runtime PROPERTIES
    PYOBF_NATIVE_CONTRIBUTION_CLIENT_SOURCE "${PROJECT_SOURCE_DIR}/src/contribution/client.cpp")

add_library(pyobf_native_contribution_gate INTERFACE)
target_link_libraries(pyobf_native_contribution_gate INTERFACE pyobf_native_contribution_runtime)
target_sources(pyobf_native_contribution_gate INTERFACE "${PROJECT_SOURCE_DIR}/src/contribution/gate.cpp")
add_library(pyobf_native_contribution_reference INTERFACE)
target_link_libraries(pyobf_native_contribution_reference INTERFACE pyobf_native_bootstrap_context)
target_sources(pyobf_native_contribution_reference INTERFACE "${PROJECT_SOURCE_DIR}/src/contribution/marker.cpp")

if(PYOBF_NATIVE_BACKEND_CAN_SHA256)
    if(NOT PYOBF_NATIVE_BACKEND_SHA256_SOURCES)
        message(FATAL_ERROR "Contribution provider needs backend SHA-256 sources")
    endif()
    add_library(pyobf_native_contribution_provider INTERFACE)
    target_link_libraries(pyobf_native_contribution_provider INTERFACE
        pyobf_native_bootstrap_context ${PYOBF_NATIVE_BACKEND_LINK_LIBRARIES})
    target_sources(pyobf_native_contribution_provider INTERFACE
        "${PROJECT_SOURCE_DIR}/src/contribution/context_derive.cpp" ${PYOBF_NATIVE_BACKEND_SHA256_SOURCES})
    set_target_properties(pyobf_native_contribution_provider PROPERTIES
        PYOBF_NATIVE_CONTRIBUTION_PROVIDER_SOURCE "${PROJECT_SOURCE_DIR}/src/contribution/context_derive.cpp")
endif()

if(PYOBF_NATIVE_BUILD_SMOKE AND TARGET pyobf_native_contribution_provider)
    add_subdirectory("${PROJECT_SOURCE_DIR}/tests/contribution" "${PROJECT_BINARY_DIR}/tests/contribution")
endif()
