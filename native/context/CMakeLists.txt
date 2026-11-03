if(NOT PYOBF_NATIVE_BACKEND_CAN_CONTEXT OR NOT PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES)
    message(FATAL_ERROR "The selected backend does not provide owned bootstrap context operations")
endif()

set(PYOBF_NATIVE_CONTEXT_CORE_SOURCES
    "${PROJECT_SOURCE_DIR}/src/context/synchronization.cpp"
    "${PROJECT_SOURCE_DIR}/src/context/lifetime.cpp"
    "${PROJECT_SOURCE_DIR}/src/context/factory.cpp"
    "${PROJECT_SOURCE_DIR}/src/context/owner.cpp"
    "${PROJECT_SOURCE_DIR}/src/context/lease.cpp"
    "${PROJECT_SOURCE_DIR}/src/context/call.cpp"
    "${PROJECT_SOURCE_DIR}/src/context/publication.cpp"
    "${PROJECT_SOURCE_DIR}/src/context/binding.cpp"
    "${PROJECT_SOURCE_DIR}/src/context/bound_call.cpp")
add_library(pyobf_native_bootstrap_context INTERFACE)
set_target_properties(pyobf_native_bootstrap_context PROPERTIES
    PYOBF_NATIVE_CONTEXT_CORE_SOURCES "${PYOBF_NATIVE_CONTEXT_CORE_SOURCES}"
    PYOBF_NATIVE_CONTEXT_BACKEND_SOURCES "${PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES}")
target_compile_features(pyobf_native_bootstrap_context INTERFACE cxx_std_17)
target_include_directories(pyobf_native_bootstrap_context INTERFACE
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
target_sources(pyobf_native_bootstrap_context INTERFACE
    ${PYOBF_NATIVE_CONTEXT_CORE_SOURCES} ${PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES})

if(PYOBF_NATIVE_BUILD_SMOKE)
    enable_testing()
    add_subdirectory("${PROJECT_SOURCE_DIR}/tests/context" "${PROJECT_BINARY_DIR}/tests/context")
endif()
