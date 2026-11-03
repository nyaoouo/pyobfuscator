if(NOT WIN32)
    message(FATAL_ERROR "windows_user backend requires Windows")
endif()
set(PYOBF_NATIVE_BACKEND_ID windows_user)
set(PYOBF_NATIVE_BACKEND_CAN_ENCRYPTED_DEMO TRUE)
set(PYOBF_NATIVE_BACKEND_CAN_ARCHIVE TRUE)
set(PYOBF_NATIVE_BACKEND_CAN_CONTEXT TRUE)
set(PYOBF_NATIVE_BACKEND_CAN_SHA256 TRUE)
set(PYOBF_NATIVE_BACKEND_CAN_CODE_CAPTURE FALSE)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PYOBF_NATIVE_BACKEND_CAN_CODE_CAPTURE TRUE)
endif()
set(PYOBF_NATIVE_BACKEND_CAPTURE_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/measurement/module_view.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/measurement/clock.cpp")
set(PYOBF_NATIVE_BACKEND_SHA256_SOURCES "${CMAKE_CURRENT_LIST_DIR}/operations/hash.cpp")
set(PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/operations/memory.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/atomic.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/archive_support.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/code_lifetime.cpp")
set(PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/operations/memory.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/crypto.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/atomic.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/archive_support.cpp")
set(PYOBF_NATIVE_BACKEND_SDK_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/sdk_environment.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/atomic.cpp")
set(PYOBF_NATIVE_BACKEND_SYSTEM_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/operations/memory.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/hash.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/crypto.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/operations/loader.cpp")
set(PYOBF_NATIVE_BACKEND_ENVIRONMENT_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/environment/registry.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/environment/placeholder.cpp")
set(PYOBF_NATIVE_BACKEND_TEST_ENVIRONMENT_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/environment/clear.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/environment/triggered.cpp")
set(PYOBF_NATIVE_BACKEND_DETECTORS placeholder)
set(PYOBF_NATIVE_BACKEND_LINK_LIBRARIES bcrypt)
