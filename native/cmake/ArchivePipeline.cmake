include_guard(GLOBAL)
include("${CMAKE_CURRENT_LIST_DIR}/LLVMCompile.cmake")

function(pyobf_native_archive_pipeline output_ir output_requests)
    cmake_parse_arguments(ARCHIVE "" "INPUT;PREFIX;REQUESTS" "CFF_ARGS;DEPENDS;EXTRA_RUNTIME_SOURCES;INPUT_BACKEND_SOURCES;INPUT_RUNTIME_SOURCES" ${ARGN})
    if(ARCHIVE_UNPARSED_ARGUMENTS OR NOT ARCHIVE_INPUT OR NOT ARCHIVE_PREFIX OR NOT ARCHIVE_REQUESTS)
        message(FATAL_ERROR "Native archive pipeline needs INPUT, PREFIX and REQUESTS")
    endif()
    get_target_property(capability pyobf_native_sdk PYOBF_NATIVE_CAN_ARCHIVE)
    get_target_property(backend_sources pyobf_native_sdk PYOBF_NATIVE_ARCHIVE_SOURCES)
    if(NOT capability OR NOT backend_sources)
        message(FATAL_ERROR "The selected backend cannot provide the native archive runtime")
    endif()
    get_filename_component(native_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    set(plan "${ARCHIVE_PREFIX}.plan.json")
    set(pending "${ARCHIVE_PREFIX}.pending.ll")
    set(pool "${ARCHIVE_PREFIX}.bin")
    set(source "${ARCHIVE_PREFIX}.cpp")
    set(bindings "${ARCHIVE_PREFIX}.bindings.json")
    add_custom_command(OUTPUT "${plan}" "${pending}"
        COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
                -passes=pyobf-native-archive-plan ${ARCHIVE_CFF_ARGS}
                "-pyobf-archive-plan-output=${plan}" -verify-each -S "${ARCHIVE_INPUT}" -o "${pending}"
        DEPENDS "${ARCHIVE_INPUT}" ${ARCHIVE_DEPENDS} pyobf_native_cff
        VERBATIM)
    add_custom_command(OUTPUT "${pool}" "${source}" "${bindings}"
        COMMAND "${Python3_EXECUTABLE}" "${native_root}/tools/pack_archive.py"
                "${plan}" "${pool}" "${source}" "${bindings}" --allow-empty-plan
        DEPENDS "${plan}" "${native_root}/tools/pack_archive.py" "${native_root}/tools/archive_format.py"
        VERBATIM)
    set(runtime_sources "${native_root}/src/archive/format.cpp"
        "${native_root}/src/archive/acquire.cpp" "${native_root}/src/archive/require.cpp"
        ${backend_sources} ${ARCHIVE_EXTRA_RUNTIME_SOURCES} "${source}")
    set(input_backend_sources "")
    foreach(input_source IN LISTS ARCHIVE_INPUT_BACKEND_SOURCES)
        if(NOT EXISTS "${input_source}")
            message(FATAL_ERROR "An input backend source does not exist: ${input_source}")
        endif()
        get_filename_component(canonical "${input_source}" REALPATH)
        list(APPEND input_backend_sources "${canonical}")
    endforeach()
    set(shared_backend_sources "")
    set(input_runtime_sources "")
    foreach(input_source IN LISTS ARCHIVE_INPUT_RUNTIME_SOURCES)
        if(NOT EXISTS "${input_source}")
            message(FATAL_ERROR "An input runtime source does not exist: ${input_source}")
        endif()
        get_filename_component(canonical "${input_source}" REALPATH)
        list(APPEND input_runtime_sources "${canonical}")
    endforeach()
    foreach(backend_source IN LISTS backend_sources)
        get_filename_component(canonical "${backend_source}" REALPATH)
        list(APPEND shared_backend_sources "${canonical}")
    endforeach()
    set(units "")
    set(index 0)
    foreach(runtime_source IN LISTS runtime_sources)
        get_filename_component(canonical "${runtime_source}" REALPATH)
        # INPUT already defines these exact backend operations; wrappers/core stay in this phase.
        if(canonical IN_LIST input_runtime_sources OR
           (canonical IN_LIST shared_backend_sources AND canonical IN_LIST input_backend_sources))
            continue()
        endif()
        set(unit "${ARCHIVE_PREFIX}.runtime.${index}.ll")
        pyobf_native_compile_ir(OUTPUT "${unit}" SOURCE "${runtime_source}"
            INCLUDES "${native_root}/include" "${native_root}/src")
        list(APPEND units "${unit}")
        math(EXPR index "${index} + 1")
    endforeach()
    set(runtime "${ARCHIVE_PREFIX}.runtime.ll")
    add_custom_command(OUTPUT "${runtime}"
        COMMAND "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" -S ${units} -o "${runtime}"
        DEPENDS ${units}
        VERBATIM)
    set(runtime_requested "${ARCHIVE_PREFIX}.runtime.requested.ll")
    set(runtime_requests "${ARCHIVE_PREFIX}.runtime.requests.json")
    add_custom_command(OUTPUT "${runtime_requested}" "${runtime_requests}"
        COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
                -passes=pyobf-native-cff-requests "-pyobf-cff-requests-output=${runtime_requests}"
                -verify-each -S "${runtime}" -o "${runtime_requested}"
        DEPENDS "${runtime}" pyobf_native_cff
        VERBATIM)
    set(merged_requests "${ARCHIVE_PREFIX}.requests.json")
    add_custom_command(OUTPUT "${merged_requests}"
        COMMAND "${Python3_EXECUTABLE}" "${native_root}/tools/merge_requests.py"
                "${merged_requests}" "${ARCHIVE_REQUESTS}" "${runtime_requests}"
        DEPENDS "${ARCHIVE_REQUESTS}" "${runtime_requests}" "${native_root}/tools/merge_requests.py"
        VERBATIM)
    set(linked "${ARCHIVE_PREFIX}.linked.ll")
    add_custom_command(OUTPUT "${linked}"
        COMMAND "${PYOBF_NATIVE_LLVM_LINK_EXECUTABLE}" -S "${pending}" "${runtime_requested}" -o "${linked}"
        DEPENDS "${pending}" "${runtime_requested}"
        VERBATIM)
    set(prepared "${ARCHIVE_PREFIX}.prepared.ll")
    add_custom_command(OUTPUT "${prepared}"
        COMMAND "${PYOBF_NATIVE_OPT_EXECUTABLE}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
                -passes=pyobf-native-archive-materialize "-pyobf-archive-bindings=${bindings}"
                -verify-each -S "${linked}" -o "${prepared}"
        DEPENDS "${linked}" "${bindings}" pyobf_native_cff
        VERBATIM)
    set(${output_ir} "${prepared}" PARENT_SCOPE)
    set(${output_requests} "${merged_requests}" PARENT_SCOPE)
endfunction()
