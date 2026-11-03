include_guard(GLOBAL)

# Source-only private reader family. Its inputs precede codegen and reference completion.
function(pyobf_native_owner_readers plan directory source_out)
    set(header "${directory}/owner_readers.hpp")
    set(source "${directory}/owner_readers.cpp")
    set(tools "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tools")
    add_custom_command(OUTPUT "${header}" "${source}"
        COMMAND "${Python3_EXECUTABLE}" "${tools}/prepare_owner_readers.py" "${plan}" "${header}" "${source}"
        DEPENDS "${plan}" "${tools}/prepare_owner_readers.py" "${tools}/owner_reader_plan.py"
            "${tools}/prepare_references.py" "${tools}/reference_plan.py" "${tools}/reference_identity.py"
            "${tools}/atomic_artifact.py" VERBATIM)
    set(${source_out} "${source}" PARENT_SCOPE)
endfunction()
