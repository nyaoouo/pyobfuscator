include_guard(GLOBAL)
if(NOT PYOBF_NATIVE_DEMO_OUTER_CFF OR NOT PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE)
    return()
endif()
set(bootstrap_measure_args "")
set(bootstrap_measure_dependencies pyobf_native_demo_outer)
set(bootstrap_measured_targets pyobf_native_demo_outer)
foreach(source IN LISTS outer_failure_sources)
    list(APPEND bootstrap_measure_args "--backend-source=${source}")
endforeach()
foreach(library IN LISTS PYOBF_NATIVE_BACKEND_LINK_LIBRARIES)
    list(APPEND bootstrap_measure_args "--library=${library}")
endforeach()
if(PYOBF_NATIVE_DEMO_DECOY AND decoy_sources STREQUAL decoy_sample_sources)
    list(APPEND bootstrap_measure_args "--decoy-configuration=${PYOBF_NATIVE_OUTER_DECOY_CFF_CONFIG}")
    list(APPEND bootstrap_measure_dependencies pyobf_native_demo_outer_decoy pyobf_native_demo_outer_decoy_triggered)
    list(APPEND bootstrap_measured_targets pyobf_native_demo_outer_decoy pyobf_native_demo_outer_decoy_triggered)
endif()
if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH OR PYOBF_NATIVE_DEMO_POST_CODE_HASH)
    pyobf_native_demo_measured_arguments(bootstrap_measured_options ${bootstrap_measured_targets})
    list(APPEND bootstrap_measure_args ${bootstrap_measured_options})
endif()
add_custom_target(pyobf_native_demo_measure_bootstrap
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/measure_bootstrap.py"
        "${CMAKE_CXX_COMPILER}" "${PYOBF_NATIVE_OPT_EXECUTABLE}" "$<TARGET_FILE:pyobf_native_cff>"
        "${PYOBF_NATIVE_OBJDUMP_EXECUTABLE}" "${PYOBF_NATIVE_OUTER_CFF_CONFIG}"
        "${CMAKE_CURRENT_BINARY_DIR}" "${release_record_blob}"
        "${CMAKE_CURRENT_BINARY_DIR}/bootstrap.measurements.json" "--seed=${PYOBF_NATIVE_CFF_SEED}" ${bootstrap_measure_args}
    DEPENDS ${bootstrap_measure_dependencies}
    VERBATIM)
