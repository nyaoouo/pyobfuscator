if(NOT PYOBF_NATIVE_BACKEND_CAN_ARCHIVE OR NOT PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES)
    message(FATAL_ERROR "The selected backend does not provide the typed archive operations")
endif()

# Runtime sources compile in the consumer, alongside generated per-record cache wrappers.
add_library(pyobf_native_archive_runtime INTERFACE)
target_compile_features(pyobf_native_archive_runtime INTERFACE cxx_std_17)
target_include_directories(pyobf_native_archive_runtime INTERFACE
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
target_sources(pyobf_native_archive_runtime INTERFACE
    "${PROJECT_SOURCE_DIR}/src/archive/format.cpp"
    "${PROJECT_SOURCE_DIR}/src/archive/acquire.cpp"
    "${PROJECT_SOURCE_DIR}/src/archive/require.cpp"
    ${PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES})
target_link_libraries(pyobf_native_archive_runtime INTERFACE ${PYOBF_NATIVE_BACKEND_LINK_LIBRARIES})
