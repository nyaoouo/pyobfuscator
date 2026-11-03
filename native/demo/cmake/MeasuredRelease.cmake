include_guard(GLOBAL)
include("${PROJECT_SOURCE_DIR}/cmake/ReferenceSlots.cmake")

if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH)
add_library(pyobf_native_demo_measured_record OBJECT "${PROJECT_SOURCE_DIR}/backends/windows_user/measured_release_record.cpp")
target_compile_features(pyobf_native_demo_measured_record PRIVATE cxx_std_17)
target_include_directories(pyobf_native_demo_measured_record PRIVATE "${PROJECT_SOURCE_DIR}/src")
set_target_properties(pyobf_native_demo_measured_record PROPERTIES INTERPROCEDURAL_OPTIMIZATION FALSE)
target_compile_options(pyobf_native_demo_measured_record PRIVATE -O0 -fno-lto)
endif()

function(pyobf_native_demo_prepare_code_reference raw_target plan_out directory_out)
    set(plan "${CMAKE_CURRENT_BINARY_DIR}/${raw_target}.reference-plan.private.json")
    add_custom_command(OUTPUT "${plan}"
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/bootstrap_reference_plan.py"
            "${release_material}" "${raw_target}" "${plan}"
        DEPENDS "${release_material}" "${PROJECT_SOURCE_DIR}/tools/bootstrap_reference_plan.py"
            "${PROJECT_SOURCE_DIR}/tools/release_material.py" "${PROJECT_SOURCE_DIR}/tools/path_fold_reference.py"
            "${PROJECT_SOURCE_DIR}/tools/reference_plan.py" "${PROJECT_SOURCE_DIR}/tools/reference_identity.py"
            "${PROJECT_SOURCE_DIR}/tools/atomic_artifact.py" VERBATIM)
    set(${plan_out} "${plan}" PARENT_SCOPE)
    set(${directory_out} "${CMAKE_CURRENT_BINARY_DIR}/${raw_target}.references" PARENT_SCOPE)
endfunction()

function(pyobf_native_demo_add_measured_release_checks)
    get_target_property(raw pyobf_native_demo_outer PYOBF_NATIVE_UNFINALIZED_TARGET)
    get_target_property(image pyobf_native_demo_outer PYOBF_NATIVE_FINAL_IMAGE)
    get_target_property(plan ${raw} PYOBF_NATIVE_MEASURED_REFERENCE_PLAN)
    get_target_property(backend ${raw} PYOBF_NATIVE_MEASURED_BACKEND_SOURCES)
    set(options "")
    if(PYOBF_NATIVE_DEMO_OUTER_CFF)
        get_target_property(object ${raw} PYOBF_NATIVE_MEASURED_CFF_OBJECT)
        get_target_property(coverage ${raw} PYOBF_NATIVE_MEASURED_CFF_REPORT)
        list(APPEND options --object "${object}" --coverage "${coverage}")
    else()
        if(PYOBF_DEMO_POST_PARENT_KIND EQUAL 3)
            get_target_property(object ${raw} PYOBF_NATIVE_MEASURED_OBJECT)
            list(APPEND options --object "${object}")
        else()
            get_target_property(sources ${raw} PYOBF_NATIVE_MEASURED_AUTHORED_SOURCES)
            list(APPEND options --sources ${sources})
        endif()
    endif()
    if(NOT PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE)
        list(APPEND options --blocked)
    endif()
    if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        pyobf_native_demo_post_arguments(function_options ${raw})
        list(APPEND options ${function_options})
        list(APPEND options --post-input "${payload_binding_reference}" "${payload_scope_material}"
            "$<TARGET_FILE:pyobf_native_demo_inner>" "${linked_cff_report}" "${release_plan}")
    endif()
    add_test(NAME pyobf_native_demo_measured_release
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_measured_release.py"
            "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${image}" "$<TARGET_FILE:${raw}>"
            "${plan}" "${release_material}" "${release_record_blob}" "${CMAKE_CURRENT_BINARY_DIR}/pyobf_native_demo_outer.release.json"
            "$<TARGET_OBJECTS:${raw}_reference_store>" "$<TARGET_OBJECTS:pyobf_native_demo_measured_record>"
            "${CMAKE_CURRENT_BINARY_DIR}/${raw}.references" "${CMAKE_CURRENT_BINARY_DIR}"
            --cmake "${CMAKE_COMMAND}" --dependency-target pyobf_native_demo_outer --backend ${backend} ${options})
    set_tests_properties(pyobf_native_demo_measured_release PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE)
endfunction()

function(pyobf_native_demo_measured_arguments output)
    set(options "")
    if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH OR PYOBF_NATIVE_DEMO_POST_CODE_HASH)
        list(APPEND options --measured-material "${release_material}")
        if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
            if(PYOBF_NATIVE_DEMO_POST_SUBJECTS)
                list(APPEND options --post-subjects "${PYOBF_NATIVE_DEMO_POST_SUBJECTS}")
            endif()
            list(APPEND options --post-material "${payload_scope_material}" --post-private "${payload_binding_reference}"
                --post-child "$<TARGET_FILE:pyobf_native_demo_inner>" --post-child-report "${linked_cff_report}"
                --post-release-plan "${release_plan}")
            if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH)
                list(APPEND options --post-pre-release)
            endif()
        endif()
        foreach(target IN LISTS ARGN)
            get_target_property(raw ${target} PYOBF_NATIVE_UNFINALIZED_TARGET)
            get_target_property(plan ${raw} PYOBF_NATIVE_MEASURED_REFERENCE_PLAN)
            list(APPEND options --measured-reference "${target}" "${plan}" "$<TARGET_OBJECTS:${raw}_reference_store>")
            get_target_property(reader_object ${raw} PYOBF_NATIVE_MEASURED_CFF_OBJECT)
            if(reader_object)
                list(APPEND options --measured-reader "${target}" "${reader_object}" "${reader_object}.ownership.json")
            endif()
            if(PYOBF_NATIVE_DEMO_POST_CODE_HASH)
                pyobf_native_demo_post_objects(bindings ${raw})
                foreach(binding IN LISTS bindings)
                    list(APPEND options --post-object "${target}" "${binding}")
                endforeach()
                pyobf_native_demo_post_ownership(manifests reports ${raw})
                foreach(binding IN LISTS manifests)
                    list(APPEND options --post-ownership "${target}" "${binding}")
                endforeach()
                foreach(binding IN LISTS reports)
                    list(APPEND options --post-ownership-report "${target}" "${binding}")
                endforeach()
            endif()
        endforeach()
    endif()
    set(${output} ${options} PARENT_SCOPE)
endfunction()

function(pyobf_native_demo_finalize_measured target raw_target plan final_image_out report_out)
    set(image "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${target}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set(report "${CMAKE_CURRENT_BINARY_DIR}/${target}.release.json")
    set(dependencies "")
    foreach(tool finalize_measured_release finalize_references pe_release_record release_format measured_release measured_scope
            release_material path_fold_reference reference_plan reference_identity reference_slots code_reference
            code_subject code_observation coff_symbols coff_layout coff_relocations function_subject function_inventory
            generated_function_subject generated_ownership pe_layout
            pe_relocations pe_data_patch archive_format pack_archive atomic_artifact)
        list(APPEND dependencies "${PROJECT_SOURCE_DIR}/tools/${tool}.py")
    endforeach()
    add_custom_command(OUTPUT "${image}" "${report}"
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/finalize_measured_release.py"
            "$<TARGET_FILE:${raw_target}>" "${plan}" "${release_material}" "${release_record_blob}"
            "${image}" --report "${report}"
        DEPENDS ${raw_target} "${plan}" "${release_material}" "${release_record_blob}" ${dependencies} VERBATIM)
    set(${final_image_out} "${image}" PARENT_SCOPE)
    set(${report_out} "${report}" PARENT_SCOPE)
endfunction()
