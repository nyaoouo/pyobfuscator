include_guard(GLOBAL)

function(pyobf_native_compiler_arguments output)
    separate_arguments(arguments NATIVE_COMMAND "${CMAKE_CXX_FLAGS}")
    if(CMAKE_CXX_COMPILER_TARGET)
        list(APPEND arguments "--target=${CMAKE_CXX_COMPILER_TARGET}")
    endif()
    if(CMAKE_SYSROOT)
        list(APPEND arguments "--sysroot=${CMAKE_SYSROOT}")
    endif()
    if(CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN)
        list(APPEND arguments "--gcc-toolchain=${CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN}")
    endif()
    set(${output} ${arguments} PARENT_SCOPE)
endfunction()

function(pyobf_native_compile_ir)
    cmake_parse_arguments(IR "" "OUTPUT;SOURCE" "INCLUDES;DEFINITIONS;DEPENDS" ${ARGN})
    if(IR_UNPARSED_ARGUMENTS OR NOT IR_OUTPUT OR NOT IR_SOURCE)
        message(FATAL_ERROR "pyobf_native_compile_ir needs OUTPUT and SOURCE")
    endif()
    pyobf_native_compiler_arguments(arguments)
    foreach(directory IN LISTS IR_INCLUDES)
        list(APPEND arguments -I "${directory}")
    endforeach()
    foreach(definition IN LISTS IR_DEFINITIONS)
        list(APPEND arguments "-D${definition}")
    endforeach()
    add_custom_command(OUTPUT "${IR_OUTPUT}"
        COMMAND "${CMAKE_CXX_COMPILER}" ${arguments} -std=c++17 -O0 -S -emit-llvm
                -Xclang -disable-O0-optnone
                -MMD -MF "${IR_OUTPUT}.d" -MT "${IR_OUTPUT}"
                "${IR_SOURCE}" -o "${IR_OUTPUT}"
        DEPENDS "${IR_SOURCE}" ${IR_DEPENDS}
        DEPFILE "${IR_OUTPUT}.d"
        VERBATIM)
endfunction()

function(pyobf_native_untransformed_ownership output input)
    find_program(PYOBF_INVENTORY_OPT NAMES opt HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
    add_custom_command(OUTPUT "${output}"
        COMMAND "${PYOBF_INVENTORY_OPT}" -load-pass-plugin "$<TARGET_FILE:pyobf_native_cff>"
            -passes=pyobf-native-untransformed-ownership "-pyobf-cff-report=${output}" -disable-output "${input}"
        DEPENDS "${input}" pyobf_native_cff VERBATIM)
endfunction()

function(pyobf_native_emit_object output input)
    cmake_parse_arguments(PARSE_ARGV 2 EMIT "FUNCTION_SECTIONS" "OWNERSHIP_REPORT" "")
    if(EMIT_UNPARSED_ARGUMENTS OR EMIT_KEYWORDS_MISSING_VALUES)
        message(FATAL_ERROR "pyobf_native_emit_object received unknown emission arguments")
    endif()
    pyobf_native_compiler_arguments(arguments)
    if(EMIT_FUNCTION_SECTIONS)
        list(APPEND arguments -ffunction-sections)
    endif()
    set(ownership_outputs "")
    set(ownership_command "")
    set(ownership_inputs "")
    if(EMIT_OWNERSHIP_REPORT)
        if(NOT EMIT_FUNCTION_SECTIONS)
            message(FATAL_ERROR "Generated ownership requires explicit function-section emission")
        endif()
        find_package(Python3 COMPONENTS Interpreter REQUIRED)
        set(ownership_outputs "${output}.ownership.json")
        set(ownership_command COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tools/function_inventory.py"
            "${output}" "${input}" "${EMIT_OWNERSHIP_REPORT}" "${ownership_outputs}")
        list(APPEND ownership_inputs "${EMIT_OWNERSHIP_REPORT}")
        foreach(tool function_inventory generated_ownership reference_plan reference_identity coff_layout coff_symbols pe_layout atomic_artifact)
            list(APPEND ownership_inputs "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tools/${tool}.py")
        endforeach()
    endif()
    # CFF is the last IR transformation. Parent IPO may link this native object, not
    # rerun optimization over the sealed CFF module.
    add_custom_command(OUTPUT "${output}" ${ownership_outputs}
        COMMAND "${CMAKE_CXX_COMPILER}" ${arguments} -O0 -fno-lto -c "${input}" -o "${output}"
        ${ownership_command}
        DEPENDS "${input}" ${ownership_inputs}
        VERBATIM)
    set_source_files_properties("${output}" PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)
endfunction()
