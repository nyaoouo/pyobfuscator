if(NOT PYOBF_NATIVE_BACKEND_CAN_SHA256 OR NOT PYOBF_NATIVE_BACKEND_CAPTURE_SOURCES)
    message(FATAL_ERROR "Native code capture needs backend SHA-256/module/clock operations")
endif()

set(capture_core_sources
    "${PROJECT_SOURCE_DIR}/src/measurement/ownership.cpp"
    "${PROJECT_SOURCE_DIR}/src/measurement/validation.cpp"
    "${PROJECT_SOURCE_DIR}/src/measurement/material.cpp"
    "${PROJECT_SOURCE_DIR}/src/measurement/capture.cpp")
set(capture_backend_sources ${PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES}
    ${PYOBF_NATIVE_BACKEND_SHA256_SOURCES} ${PYOBF_NATIVE_BACKEND_CAPTURE_SOURCES})
list(REMOVE_DUPLICATES capture_backend_sources)

# Private source runtime; no installed/public observation SDK or exported object ABI.
add_library(pyobf_native_code_capture INTERFACE)
target_compile_features(pyobf_native_code_capture INTERFACE cxx_std_17)
target_include_directories(pyobf_native_code_capture INTERFACE
    "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src")
target_sources(pyobf_native_code_capture INTERFACE ${capture_core_sources} ${capture_backend_sources})
target_link_libraries(pyobf_native_code_capture INTERFACE ${PYOBF_NATIVE_BACKEND_LINK_LIBRARIES})
set_target_properties(pyobf_native_code_capture PROPERTIES
    PYOBF_NATIVE_CAPTURE_CORE_SOURCES "${capture_core_sources}"
    PYOBF_NATIVE_CAPTURE_BACKEND_SOURCES "${capture_backend_sources}")

if(PYOBF_NATIVE_BACKEND_CAN_ARCHIVE)
    set(reference_core_sources
        "${PROJECT_SOURCE_DIR}/src/measurement/reference_owner.cpp"
        "${PROJECT_SOURCE_DIR}/src/measurement/reference_key.cpp"
        "${PROJECT_SOURCE_DIR}/src/measurement/reference_payload.cpp"
        "${PROJECT_SOURCE_DIR}/src/measurement/reference_decode.cpp")
    set(reference_archive_sources "${PROJECT_SOURCE_DIR}/src/archive/format.cpp"
        "${PROJECT_SOURCE_DIR}/src/archive/acquire.cpp")
    set(reference_backend_sources ${capture_backend_sources} ${PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES})
    list(REMOVE_DUPLICATES reference_backend_sources)
    add_library(pyobf_native_code_reference INTERFACE)
    target_link_libraries(pyobf_native_code_reference INTERFACE pyobf_native_code_capture)
    target_sources(pyobf_native_code_reference INTERFACE ${reference_core_sources}
        ${reference_archive_sources} ${PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES})
    set_target_properties(pyobf_native_code_reference PROPERTIES
        PYOBF_NATIVE_REFERENCE_CORE_SOURCES "${reference_core_sources};${reference_archive_sources};${capture_core_sources}"
        PYOBF_NATIVE_REFERENCE_BACKEND_SOURCES "${reference_backend_sources}")
    if(TARGET pyobf_native_bootstrap_context)
        set(observer_core_sources
            "${PROJECT_SOURCE_DIR}/src/measurement/observer_time.cpp"
            "${PROJECT_SOURCE_DIR}/src/measurement/observer_state.cpp"
            "${PROJECT_SOURCE_DIR}/src/measurement/observer_factory.cpp"
            "${PROJECT_SOURCE_DIR}/src/measurement/observer_sampling.cpp"
            "${PROJECT_SOURCE_DIR}/src/measurement/observer_dispatch.cpp"
            "${PROJECT_SOURCE_DIR}/src/measurement/observer_client.cpp"
            "${PROJECT_SOURCE_DIR}/src/measurement/snapshot_report.cpp")
        add_library(pyobf_native_code_observer INTERFACE)
        target_link_libraries(pyobf_native_code_observer INTERFACE
            pyobf_native_code_reference pyobf_native_bootstrap_context)
        target_sources(pyobf_native_code_observer INTERFACE ${observer_core_sources})
        get_target_property(observer_context_sources pyobf_native_bootstrap_context PYOBF_NATIVE_CONTEXT_CORE_SOURCES)
        set_target_properties(pyobf_native_code_observer PROPERTIES
            PYOBF_NATIVE_OBSERVER_CORE_SOURCES "${observer_core_sources};${reference_core_sources};${reference_archive_sources};${capture_core_sources};${observer_context_sources}"
            PYOBF_NATIVE_OBSERVER_BACKEND_SOURCES "${reference_backend_sources}")
        set(measured_release_sources "${PROJECT_SOURCE_DIR}/src/release/measured_expansion.cpp"
            "${PROJECT_SOURCE_DIR}/src/release/measured_key.cpp")
        add_library(pyobf_native_measured_release INTERFACE)
        target_link_libraries(pyobf_native_measured_release INTERFACE pyobf_native_code_observer)
        target_sources(pyobf_native_measured_release INTERFACE ${measured_release_sources})
        set_target_properties(pyobf_native_measured_release PROPERTIES
            PYOBF_NATIVE_MEASURED_RELEASE_CORE_SOURCES "${measured_release_sources}")
        set(measured_contribution_sources "${PROJECT_SOURCE_DIR}/src/contribution/measured.cpp"
            "${PROJECT_SOURCE_DIR}/src/contribution/context_derive.cpp")
        add_library(pyobf_native_measured_contribution INTERFACE)
        target_link_libraries(pyobf_native_measured_contribution INTERFACE pyobf_native_measured_release)
        target_sources(pyobf_native_measured_contribution INTERFACE ${measured_contribution_sources})
        set_target_properties(pyobf_native_measured_contribution PROPERTIES
            PYOBF_NATIVE_MEASURED_CONTRIBUTION_CORE_SOURCES "${measured_contribution_sources}")
        set(measured_scope_sources "${PROJECT_SOURCE_DIR}/src/contribution/scope.cpp"
            "${PROJECT_SOURCE_DIR}/src/contribution/scope_query.cpp"
            "${PROJECT_SOURCE_DIR}/src/contribution/scope_material.cpp")
        add_library(pyobf_native_measured_scope INTERFACE)
        target_link_libraries(pyobf_native_measured_scope INTERFACE pyobf_native_measured_contribution)
        target_sources(pyobf_native_measured_scope INTERFACE ${measured_scope_sources})
        set_target_properties(pyobf_native_measured_scope PROPERTIES
            PYOBF_NATIVE_MEASURED_SCOPE_CORE_SOURCES "${measured_scope_sources}")
        if(TARGET pyobf_native_contribution_gate)
            add_library(pyobf_native_mixed_contribution INTERFACE)
            target_link_libraries(pyobf_native_mixed_contribution INTERFACE
                pyobf_native_measured_scope pyobf_native_contribution_gate)
            target_sources(pyobf_native_mixed_contribution INTERFACE
                "${PROJECT_SOURCE_DIR}/src/contribution/mixed_gate.cpp")
        endif()
        add_library(pyobf_native_measured_scope_reference INTERFACE)
        target_link_libraries(pyobf_native_measured_scope_reference INTERFACE pyobf_native_measured_scope)
        target_sources(pyobf_native_measured_scope_reference INTERFACE
            "${PROJECT_SOURCE_DIR}/src/contribution/scope_marker.cpp"
            "${PROJECT_SOURCE_DIR}/src/contribution/mixed_marker.cpp")
    endif()
endif()

if(PYOBF_NATIVE_BUILD_SMOKE)
    add_subdirectory("${PROJECT_SOURCE_DIR}/tests/measurement" "${PROJECT_BINARY_DIR}/tests/measurement")
endif()
