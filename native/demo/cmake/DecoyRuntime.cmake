include_guard(GLOBAL)
if(NOT PYOBF_NATIVE_DEMO_DECOY)
    return()
endif()

set(PYOBF_NATIVE_OUTER_DECOY_CFF_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/recipes/bootstrap-decoy.json"
    CACHE FILEPATH "Outer-decoy recipe with independently required runtime fold sites")
get_filename_component(PYOBF_NATIVE_OUTER_DECOY_CFF_CONFIG "${PYOBF_NATIVE_OUTER_DECOY_CFF_CONFIG}" ABSOLUTE)
if(NOT EXISTS "${PYOBF_NATIVE_OUTER_DECOY_CFF_CONFIG}")
    message(FATAL_ERROR "Outer-decoy recipe is absent")
endif()
set(decoy_runtime_sources bootstrap/decoy_session.cpp bootstrap/decoy_preparation.cpp
    bootstrap/decoy_key.cpp bootstrap/decoy_release.cpp)
pyobf_native_demo_add_outer(pyobf_native_demo_outer_decoy DECOY)
pyobf_native_demo_add_outer(pyobf_native_demo_outer_decoy_triggered DECOY
    DEFINITIONS PYOBF_DEMO_FORCE_TRIGGERED=1 PYOBF_NATIVE_TEST_DETECTORS=1
    ENVIRONMENT_SOURCES ${PYOBF_NATIVE_BACKEND_TEST_ENVIRONMENT_SOURCES})
