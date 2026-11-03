include_guard(GLOBAL)
set(PYOBF_REFERENCE_TOOLS "${CMAKE_CURRENT_LIST_DIR}/../tools")

# Private build seam. Runtime readiness/provider integration remains a separate consumer.
function(pyobf_native_reference_storage target plan)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    get_filename_component(plan "${plan}" ABSOLUTE)
    set(directory "${CMAKE_CURRENT_BINARY_DIR}/${target}.references")
    file(MAKE_DIRECTORY "${directory}")
    set(header "${directory}/reference_slots.hpp")
    set(source "${directory}/reference_slots.cpp")
    add_custom_command(OUTPUT "${header}" "${source}"
        COMMAND "${Python3_EXECUTABLE}" "${PYOBF_REFERENCE_TOOLS}/prepare_references.py" "${plan}" "${header}" "${source}"
        DEPENDS "${plan}" "${PYOBF_REFERENCE_TOOLS}/prepare_references.py" "${PYOBF_REFERENCE_TOOLS}/reference_plan.py"
            "${PYOBF_REFERENCE_TOOLS}/reference_identity.py" "${PYOBF_REFERENCE_TOOLS}/reference_slots.py"
            "${PYOBF_REFERENCE_TOOLS}/pe_layout.py" "${PYOBF_REFERENCE_TOOLS}/pe_relocations.py"
            "${PYOBF_REFERENCE_TOOLS}/atomic_artifact.py"
        VERBATIM)
    add_library(${target}_reference_store OBJECT "${source}")
    target_compile_features(${target}_reference_store PRIVATE cxx_std_17)
    target_include_directories(${target}_reference_store PRIVATE "${directory}" "${PYOBF_REFERENCE_TOOLS}/../src"
        "${PYOBF_REFERENCE_TOOLS}/../include")
    set_target_properties(${target}_reference_store PROPERTIES INTERPROCEDURAL_OPTIMIZATION FALSE)
    if(NOT MSVC)
        target_compile_options(${target}_reference_store PRIVATE -fno-lto)
    endif()
    target_sources(${target} PRIVATE "$<TARGET_OBJECTS:${target}_reference_store>")
    target_include_directories(${target} PRIVATE "${directory}")
    add_dependencies(${target} ${target}_reference_store)
    set_target_properties(${target} PROPERTIES PYOBF_NATIVE_REFERENCE_PLAN "${plan}")
endfunction()

function(pyobf_native_finalize_references target raw_target material output report)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    cmake_parse_arguments(PARSE_ARGV 5 REF "" "" "TARGETS;OBJECTS;SCOPE_MATERIALS;OWNERSHIP;OWNERSHIP_REPORTS;DEPENDS")
    if(REF_UNPARSED_ARGUMENTS OR REF_KEYWORDS_MISSING_VALUES)
        message(FATAL_ERROR "Unexpected reference finalization arguments")
    endif()
    get_target_property(plan ${raw_target} PYOBF_NATIVE_REFERENCE_PLAN)
    if(NOT plan)
        message(FATAL_ERROR "Reference finalization requires pre-codegen storage on its raw target")
    endif()
    set(options "")
    set(inputs "")
    foreach(kind TARGETS OBJECTS SCOPE_MATERIALS OWNERSHIP OWNERSHIP_REPORTS)
        if(kind STREQUAL "TARGETS")
            set(option --target)
        elseif(kind STREQUAL "OBJECTS")
            set(option --object)
        elseif(kind STREQUAL "SCOPE_MATERIALS")
            set(option --scope-material)
        elseif(kind STREQUAL "OWNERSHIP")
            set(option --ownership)
        else()
            set(option --ownership-report)
        endif()
        foreach(binding IN LISTS REF_${kind})
            if(NOT binding MATCHES "^[^=]+=.+$")
                message(FATAL_ERROR "Reference artifact binding needs identity=path")
            endif()
            list(APPEND options "${option}" "${binding}")
            string(REGEX REPLACE "^[^=]+=" "" input "${binding}")
            list(APPEND inputs "${input}")
        endforeach()
    endforeach()
    set(tools finalize_references atomic_artifact reference_plan reference_identity reference_slots
        code_reference code_subject code_observation coff_symbols coff_layout coff_relocations
        function_subject function_inventory generated_function_subject generated_ownership pe_layout pe_relocations pe_data_patch release_material path_fold_reference
        archive_format pack_archive measured_scope measured_release release_format)
    set(dependencies "")
    foreach(tool IN LISTS tools)
        list(APPEND dependencies "${PYOBF_REFERENCE_TOOLS}/${tool}.py")
    endforeach()
    add_custom_command(OUTPUT "${output}" "${report}"
        COMMAND "${Python3_EXECUTABLE}" "${PYOBF_REFERENCE_TOOLS}/finalize_references.py"
            "$<TARGET_FILE:${raw_target}>" "${plan}" "${material}" "${output}" --report "${report}" ${options}
        DEPENDS ${raw_target} "${plan}" "${material}" ${inputs} ${dependencies} ${REF_DEPENDS}
        VERBATIM)
    add_custom_target(${target} DEPENDS "${output}" "${report}")
endfunction()
