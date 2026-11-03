if(WIN32)
    set(default_native_backend windows_user)
else()
    set(default_native_backend portable_stub)
endif()
set(PYOBF_NATIVE_BACKEND "${default_native_backend}" CACHE STRING
    "Named native target backend")

set(backend_manifest "${PROJECT_SOURCE_DIR}/backends/${PYOBF_NATIVE_BACKEND}/Backend.cmake")
if(NOT EXISTS "${backend_manifest}")
    message(FATAL_ERROR "Unknown native backend: ${PYOBF_NATIVE_BACKEND}")
endif()
include("${backend_manifest}")
if(NOT PYOBF_NATIVE_BACKEND_ID STREQUAL PYOBF_NATIVE_BACKEND)
    message(FATAL_ERROR "Native backend manifest ID does not match its directory")
endif()
if(NOT PYOBF_NATIVE_BACKEND_SDK_SOURCES)
    message(FATAL_ERROR "Native backend must provide SDK sources")
endif()
foreach(source IN LISTS PYOBF_NATIVE_BACKEND_SDK_SOURCES
        PYOBF_NATIVE_BACKEND_SYSTEM_SOURCES PYOBF_NATIVE_BACKEND_ENVIRONMENT_SOURCES
        PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES
        PYOBF_NATIVE_BACKEND_SHA256_SOURCES PYOBF_NATIVE_BACKEND_CAPTURE_SOURCES)
    if(NOT EXISTS "${source}")
        message(FATAL_ERROR "Native backend source does not exist: ${source}")
    endif()
endforeach()
