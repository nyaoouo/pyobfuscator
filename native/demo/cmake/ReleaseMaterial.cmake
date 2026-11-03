include_guard(GLOBAL)

function(pyobf_native_demo_prepare_material material_out header_out namespace prefix)
    get_filename_component(material_native_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../.." ABSOLUTE)
    set(material "${prefix}-material.private.json")
    set(header "${CMAKE_CURRENT_BINARY_DIR}/${namespace}_generated.hpp")
    add_custom_command(OUTPUT "${material}" "${header}"
        COMMAND "${Python3_EXECUTABLE}" "${material_native_root}/tools/prepare_release_material.py"
            "${material}" "${header}" --event-namespace "${namespace}"
        DEPENDS "${material_native_root}/tools/prepare_release_material.py"
            "${material_native_root}/tools/release_material.py"
            "${material_native_root}/tools/path_fold_reference.py" "${material_native_root}/tools/atomic_artifact.py"
        VERBATIM)
    set(${material_out} "${material}" PARENT_SCOPE)
    set(${header_out} "${header}" PARENT_SCOPE)
endfunction()
