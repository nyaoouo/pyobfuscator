get_target_property(session_core pyobf_native_bootstrap_context PYOBF_NATIVE_CONTEXT_CORE_SOURCES)
set(session_authored_sources "")
foreach(source IN LISTS bootstrap_sources)
    get_filename_component(source "${source}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    list(APPEND session_authored_sources "${source}")
endforeach()
list(APPEND session_authored_sources "${CMAKE_CURRENT_SOURCE_DIR}/payload.cpp"
    "${PROJECT_SOURCE_DIR}/src/sdk.cpp" ${session_core})
# The fixture supplies semantic operations. Keep the actual SDK detector, omit its shared ops.
foreach(source IN LISTS PYOBF_NATIVE_BACKEND_SDK_SOURCES)
    if(NOT source IN_LIST PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES)
        list(APPEND session_authored_sources "${source}")
    endif()
endforeach()
add_library(pyobf_native_session_hash OBJECT "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/hash.cpp")
target_compile_definitions(pyobf_native_session_hash PRIVATE hash_sha256=hash_sha256_actual)
add_library(pyobf_native_session_crypto OBJECT "${PROJECT_SOURCE_DIR}/backends/windows_user/operations/crypto.cpp")
target_compile_definitions(pyobf_native_session_crypto PRIVATE decrypt_payload=decrypt_payload_actual)
foreach(crypto_target pyobf_native_session_hash pyobf_native_session_crypto)
    target_compile_features(${crypto_target} PRIVATE cxx_std_17)
    target_include_directories(${crypto_target} PRIVATE "${PROJECT_SOURCE_DIR}/include")
endforeach()
set(session_fixture_sources session_smoke.cpp session_protocol.cpp session_backend.cpp session_fold.cpp
    session_common.cpp session_crypto.cpp)
add_executable(pyobf_native_demo_session ${session_authored_sources} ${session_fixture_sources} "${payload_blob}"
    "${path_events_header}" "${PROJECT_SOURCE_DIR}/src/path_fold/marker.cpp"
    "$<TARGET_OBJECTS:pyobf_native_demo_record>" "$<TARGET_OBJECTS:pyobf_native_session_hash>"
    "$<TARGET_OBJECTS:pyobf_native_session_crypto>")
set_target_properties(pyobf_native_demo_session PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/unfinalized")
target_compile_features(pyobf_native_demo_session PRIVATE cxx_std_17)
target_include_directories(pyobf_native_demo_session PRIVATE "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")
find_package(Threads REQUIRED)
target_link_libraries(pyobf_native_demo_session PRIVATE Threads::Threads bcrypt)
add_dependencies(pyobf_native_demo_session pyobf_native_demo_inner)
add_test(NAME pyobf_native_demo_session
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/session_fold_reference.py"
        "$<TARGET_FILE:pyobf_native_demo_session>" "${release_plan}" "${release_record_blob}")
get_filename_component(session_compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
set_tests_properties(pyobf_native_demo_session PROPERTIES TIMEOUT 30
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${session_compiler_directory}")

set(session_ipo "")
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    list(APPEND session_ipo --ipo)
endif()
foreach(profile none O2)
    add_test(NAME pyobf_native_demo_session_cff_${profile}
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_session_cff.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/recipes/bootstrap.json" "${CMAKE_CURRENT_BINARY_DIR}"
            "${release_plan}" "${release_record_blob}" "${profile}" ${session_ipo}
            --sources ${session_authored_sources})
    set_tests_properties(pyobf_native_demo_session_cff_${profile} PROPERTIES TIMEOUT 180)
endforeach()

if(PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE)
    add_executable(pyobf_native_demo_lifetime lifetime_smoke.cpp)
    target_compile_features(pyobf_native_demo_lifetime PRIVATE cxx_std_17)
    if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        target_compile_definitions(pyobf_native_demo_lifetime PRIVATE PYOBF_DEMO_POST_CODE_HASH=1)
    endif()
    target_link_libraries(pyobf_native_demo_lifetime PRIVATE Threads::Threads)
    add_test(NAME pyobf_native_demo_lifetime
        COMMAND pyobf_native_demo_lifetime "${demo_outer_image}")
    set_tests_properties(pyobf_native_demo_lifetime PROPERTIES TIMEOUT 60
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${session_compiler_directory}")
endif()
