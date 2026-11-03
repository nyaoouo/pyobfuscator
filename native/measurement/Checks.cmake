if(NOT PYOBF_NATIVE_BUILD_SMOKE OR NOT TARGET pyobf_native_code_capture OR NOT TARGET pyobf_native_cff
        OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang"
        OR NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
    return()
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
find_program(PYOBF_CAPTURE_OPT NAMES opt HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(PYOBF_CAPTURE_LINK NAMES llvm-link HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(PYOBF_CAPTURE_OBJDUMP NAMES llvm-objdump HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
get_target_property(capture_core pyobf_native_code_capture PYOBF_NATIVE_CAPTURE_CORE_SOURCES)
get_target_property(capture_backend pyobf_native_code_capture PYOBF_NATIVE_CAPTURE_BACKEND_SOURCES)
get_filename_component(capture_runtime "${CMAKE_CXX_COMPILER}" DIRECTORY)
set(capture_ipo "")
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    list(APPEND capture_ipo --ipo)
endif()
if(TARGET pyobf_native_code_observer)
    get_target_property(owner_reader_core pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_CORE_SOURCES)
    get_target_property(owner_reader_backend pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_BACKEND_SOURCES)
    add_test(NAME pyobf_native_code_owner_readers
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_owner_readers.py"
            "${CMAKE_CXX_COMPILER}" "${capture_runtime}" "${PROJECT_BINARY_DIR}/tests/measurement"
            --core ${owner_reader_core} --backend ${owner_reader_backend})
    set_tests_properties(pyobf_native_code_owner_readers PROPERTIES TIMEOUT 180)
    foreach(profile none O2)
        add_test(NAME pyobf_native_code_owner_readers_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_owner_readers.py"
                "${CMAKE_CXX_COMPILER}" "${capture_runtime}" "${PROJECT_BINARY_DIR}/tests/measurement"
                --core ${owner_reader_core} --backend ${owner_reader_backend} --profile ${profile} ${capture_ipo}
                --opt "${PYOBF_CAPTURE_OPT}" --plugin "$<TARGET_FILE:pyobf_native_cff>"
                --llvm-link "${PYOBF_CAPTURE_LINK}" --objdump "${PYOBF_CAPTURE_OBJDUMP}")
        set_tests_properties(pyobf_native_code_owner_readers_cff_${profile} PROPERTIES TIMEOUT 180)
    endforeach()
    add_test(NAME pyobf_native_code_observer
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_observer.py"
            "${CMAKE_CXX_COMPILER}" "$<TARGET_FILE:pyobf_native_observer_probe>" "${capture_runtime}"
            "${PROJECT_BINARY_DIR}/tests/measurement")
    set_tests_properties(pyobf_native_code_observer PROPERTIES TIMEOUT 90)
    add_test(NAME pyobf_native_measured_key
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_measured_key.py"
            "${CMAKE_CXX_COMPILER}" "$<TARGET_FILE:pyobf_native_measured_key_probe>" "${capture_runtime}"
            "${PROJECT_BINARY_DIR}/tests/measurement")
    set_tests_properties(pyobf_native_measured_key PROPERTIES TIMEOUT 90)
    add_test(NAME pyobf_native_measured_contribution
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_measured_key.py"
            "${CMAKE_CXX_COMPILER}" "$<TARGET_FILE:pyobf_native_measured_contribution_probe>" "${capture_runtime}"
            "${PROJECT_BINARY_DIR}/tests/measurement" --contribution)
    set_tests_properties(pyobf_native_measured_contribution PROPERTIES TIMEOUT 90)
    add_test(NAME pyobf_native_measured_scope
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_measured_key.py"
            "${CMAKE_CXX_COMPILER}" "$<TARGET_FILE:pyobf_native_measured_scope_probe>" "${capture_runtime}"
            "${PROJECT_BINARY_DIR}/tests/measurement" --contribution --scope)
    set_tests_properties(pyobf_native_measured_scope PROPERTIES TIMEOUT 90)
endif()
if(TARGET pyobf_native_code_observer)
    get_target_property(observer_core pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_CORE_SOURCES)
    get_target_property(observer_backend pyobf_native_code_observer PYOBF_NATIVE_OBSERVER_BACKEND_SOURCES)
    get_target_property(measured_release_core pyobf_native_measured_release PYOBF_NATIVE_MEASURED_RELEASE_CORE_SOURCES)
    get_target_property(measured_contribution_core pyobf_native_measured_contribution PYOBF_NATIVE_MEASURED_CONTRIBUTION_CORE_SOURCES)
    get_target_property(measured_scope_core pyobf_native_measured_scope PYOBF_NATIVE_MEASURED_SCOPE_CORE_SOURCES)
    add_test(NAME pyobf_native_code_material_slots
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_scope_slots.py"
            "${CMAKE_CXX_COMPILER}" "${capture_runtime}" "${PROJECT_BINARY_DIR}/tests/measurement" ${capture_ipo}
            --cmake "${CMAKE_COMMAND}" --ninja "${CMAKE_MAKE_PROGRAM}"
            --native ${measured_scope_core} ${measured_contribution_core} ${measured_release_core} ${observer_core}
            --backend ${observer_backend})
    set_tests_properties(pyobf_native_code_material_slots PROPERTIES TIMEOUT 180)
    foreach(profile none O2)
        add_test(NAME pyobf_native_code_observer_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_observer_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CAPTURE_LINK}" "${PYOBF_CAPTURE_OBJDUMP}" "${capture_runtime}"
                "${PROJECT_BINARY_DIR}/tests/measurement" ${profile} ${capture_ipo}
                --core ${observer_core} --backend ${observer_backend})
        set_tests_properties(pyobf_native_code_observer_cff_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_measured_key_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_observer_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CAPTURE_LINK}" "${PYOBF_CAPTURE_OBJDUMP}" "${capture_runtime}"
                "${PROJECT_BINARY_DIR}/tests/measurement" ${profile} ${capture_ipo} --measured-key
                --core ${measured_release_core} ${observer_core} --backend ${observer_backend})
        set_tests_properties(pyobf_native_measured_key_cff_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_measured_contribution_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_observer_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CAPTURE_LINK}" "${PYOBF_CAPTURE_OBJDUMP}" "${capture_runtime}"
                "${PROJECT_BINARY_DIR}/tests/measurement" ${profile} ${capture_ipo} --measured-contribution
                --core ${measured_contribution_core} ${measured_release_core} ${observer_core} --backend ${observer_backend})
        set_tests_properties(pyobf_native_measured_contribution_cff_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_measured_scope_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_observer_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CAPTURE_LINK}" "${PYOBF_CAPTURE_OBJDUMP}" "${capture_runtime}"
                "${PROJECT_BINARY_DIR}/tests/measurement" ${profile} ${capture_ipo} --measured-scope
                --core ${measured_scope_core} ${measured_contribution_core} ${measured_release_core} ${observer_core}
                --backend ${observer_backend})
        set_tests_properties(pyobf_native_measured_scope_cff_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_grouped_scope_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/grouped_scope_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CAPTURE_LINK}" "${PYOBF_CAPTURE_OBJDUMP}" "${capture_runtime}"
                "${PROJECT_BINARY_DIR}/tests/measurement" ${profile} ${capture_ipo} --measured-scope
                --core ${measured_scope_core} ${measured_contribution_core} ${measured_release_core} ${observer_core}
                --backend ${observer_backend})
        set_tests_properties(pyobf_native_grouped_scope_cff_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_grouped_scope_composed_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/grouped_scope_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CAPTURE_LINK}" "${PYOBF_CAPTURE_OBJDUMP}" "${capture_runtime}"
                "${PROJECT_BINARY_DIR}/tests/measurement" ${profile} ${capture_ipo} --measured-scope --composed
                --core ${measured_scope_core} ${measured_contribution_core} ${measured_release_core} ${observer_core}
                --backend ${observer_backend})
        set_tests_properties(pyobf_native_grouped_scope_composed_${profile} PROPERTIES TIMEOUT 300)
        add_test(NAME pyobf_native_unit6_detached_scope_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/contribution/unit6_scope.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CAPTURE_LINK}" "${PYOBF_CAPTURE_OBJDUMP}" "${capture_runtime}"
                "${PROJECT_BINARY_DIR}/tests/measurement" ${profile} ${capture_ipo} --measured-scope
                --measure-output "${PROJECT_BINARY_DIR}/tests/measurement/unit6-detached-scope-${profile}.json"
                --core ${measured_scope_core} ${measured_contribution_core} ${measured_release_core} ${observer_core}
                --backend ${observer_backend})
        set_tests_properties(pyobf_native_unit6_detached_scope_${profile} PROPERTIES TIMEOUT 480)
    endforeach()
endif()
add_test(NAME pyobf_native_code_function_subjects
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_functions.py"
        "${CMAKE_CXX_COMPILER}" "$<TARGET_FILE:pyobf_native_capture_probe>"
        "${capture_runtime}" "${PROJECT_BINARY_DIR}/tests/measurement")
set_tests_properties(pyobf_native_code_function_subjects PROPERTIES TIMEOUT 90)
add_test(NAME pyobf_native_code_generated_subjects
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_generated.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
        "${PYOBF_CAPTURE_OBJDUMP}" "$<TARGET_FILE:pyobf_native_capture_probe>"
        "${capture_runtime}" "${PROJECT_BINARY_DIR}/tests/measurement"
        --cmake "${CMAKE_COMMAND}" --ninja "${CMAKE_MAKE_PROGRAM}" --llvm-link "${PYOBF_CAPTURE_LINK}")
set_tests_properties(pyobf_native_code_generated_subjects PROPERTIES TIMEOUT 180)
foreach(profile none O2)
    add_test(NAME pyobf_native_code_capture_cff_${profile}
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_cff.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
            "${PYOBF_CAPTURE_LINK}" "${PYOBF_CAPTURE_OBJDUMP}" "${capture_runtime}"
            "${PROJECT_BINARY_DIR}/tests/measurement" ${profile} ${capture_ipo}
            --cmake "${CMAKE_COMMAND}" --ninja "${CMAKE_MAKE_PROGRAM}"
            --core ${capture_core} --backend ${capture_backend}
            --sample "$<TARGET_FILE:pyobf_native_capture_sample1>" --sample "$<TARGET_FILE:pyobf_native_capture_sample2>")
    set_tests_properties(pyobf_native_code_capture_cff_${profile} PROPERTIES TIMEOUT 180)
endforeach()

if(TARGET pyobf_native_code_reference)
    get_target_property(reference_core pyobf_native_code_reference PYOBF_NATIVE_REFERENCE_CORE_SOURCES)
    get_target_property(reference_backend pyobf_native_code_reference PYOBF_NATIVE_REFERENCE_BACKEND_SOURCES)
    add_test(NAME pyobf_native_code_reference
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_reference.py"
            "${CMAKE_CXX_COMPILER}" "$<TARGET_FILE:pyobf_native_reference_probe>" "${capture_runtime}"
            "${PROJECT_BINARY_DIR}/tests/measurement" --faults "$<TARGET_FILE:pyobf_native_reference_faults>")
    set_tests_properties(pyobf_native_code_reference PROPERTIES TIMEOUT 90)
    add_test(NAME pyobf_native_code_reference_slots
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_slots.py"
            "${CMAKE_CXX_COMPILER}" "${capture_runtime}" "${PROJECT_BINARY_DIR}/tests/measurement" ${capture_ipo}
            --cmake "${CMAKE_COMMAND}" --ninja "${CMAKE_MAKE_PROGRAM}"
            --native ${reference_core} --backend ${reference_backend})
    set_tests_properties(pyobf_native_code_reference_slots PROPERTIES TIMEOUT 120)
    foreach(profile none O2)
        add_test(NAME pyobf_native_code_reference_cff_${profile}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/measurement/check_reference_cff.py"
                "${CMAKE_CXX_COMPILER}" "${PYOBF_CAPTURE_OPT}" "$<TARGET_FILE:pyobf_native_cff>"
                "${PYOBF_CAPTURE_LINK}" "${PYOBF_CAPTURE_OBJDUMP}" "${capture_runtime}"
                "${PROJECT_BINARY_DIR}/tests/measurement" ${profile} ${capture_ipo}
                --core ${reference_core} --backend ${reference_backend})
        set_tests_properties(pyobf_native_code_reference_cff_${profile} PROPERTIES TIMEOUT 240)
    endforeach()
endif()
