include_guard(GLOBAL)

function(pyobf_native_embed_asset output_source output_header)
    cmake_parse_arguments(ASSET "" "ID;FILE;DIRECTORY" "" ${ARGN})
    if(ASSET_UNPARSED_ARGUMENTS OR NOT ASSET_ID MATCHES "^[a-z][a-z0-9_]*$" OR
            NOT ASSET_FILE OR NOT ASSET_DIRECTORY)
        message(FATAL_ERROR "Native asset needs ID, FILE and DIRECTORY")
    endif()
    string(LENGTH "${ASSET_ID}" identity_length)
    if(identity_length GREATER 64)
        message(FATAL_ERROR "Native asset ID exceeds 64 characters")
    endif()
    get_filename_component(input "${ASSET_FILE}" ABSOLUTE)
    if(NOT EXISTS "${input}" OR IS_DIRECTORY "${input}")
        message(FATAL_ERROR "Native asset input is not a file: ${input}")
    endif()
    get_filename_component(directory "${ASSET_DIRECTORY}" ABSOLUTE)
    file(MAKE_DIRECTORY "${directory}")
    get_filename_component(native_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
    set(header "${directory}/asset_${ASSET_ID}.hpp")
    set(source "${directory}/asset_${ASSET_ID}.cpp")
    add_custom_command(OUTPUT "${header}" "${source}"
        COMMAND "${Python3_EXECUTABLE}" "${native_root}/tools/embed_asset.py"
                "${ASSET_ID}" "${input}" "${header}" "${source}"
        DEPENDS "${input}" "${native_root}/tools/embed_asset.py"
        VERBATIM)
    set(${output_source} "${source}" PARENT_SCOPE)
    set(${output_header} "${header}" PARENT_SCOPE)
endfunction()
