if(NOT PYOBF_NATIVE_BACKEND_CAN_ENCRYPTED_DEMO)
    message(FATAL_ERROR "The selected native backend cannot build the encrypted demo")
endif()
if(NOT PYOBF_NATIVE_BACKEND_SYSTEM_SOURCES OR
   NOT PYOBF_NATIVE_BACKEND_ENVIRONMENT_SOURCES OR
   NOT PYOBF_NATIVE_BACKEND_DETECTORS)
    message(FATAL_ERROR "The encrypted-demo backend has an incomplete operations/detector manifest")
endif()
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "The first native CFF demo requires Clang and a matching opt tool")
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
execute_process(
    COMMAND "${Python3_EXECUTABLE}" -c "import cryptography"
    RESULT_VARIABLE python_crypto_result)
if(NOT python_crypto_result EQUAL 0)
    message(FATAL_ERROR "The native demo packer requires cryptography in Python3_EXECUTABLE")
endif()
find_program(PYOBF_NATIVE_OPT_EXECUTABLE NAMES opt HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(PYOBF_NATIVE_LLVM_LINK_EXECUTABLE NAMES llvm-link
    HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(PYOBF_NATIVE_OBJDUMP_EXECUTABLE NAMES llvm-objdump
    HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)

set(PYOBF_NATIVE_DEMO_ENV_DETECTORS "placeholder" CACHE STRING
    "Semicolon-separated pre-release detectors registered by the selected backend")
list(LENGTH PYOBF_NATIVE_DEMO_ENV_DETECTORS detector_count)
if(detector_count EQUAL 0 OR detector_count GREATER 8)
    message(FATAL_ERROR "Select between one and eight native environment detectors")
endif()
foreach(detector IN LISTS PYOBF_NATIVE_DEMO_ENV_DETECTORS)
    if(NOT detector IN_LIST PYOBF_NATIVE_BACKEND_DETECTORS)
        message(FATAL_ERROR "Detector '${detector}' is not registered by ${PYOBF_NATIVE_BACKEND}")
    endif()
endforeach()
set(unique_detectors ${PYOBF_NATIVE_DEMO_ENV_DETECTORS})
list(REMOVE_DUPLICATES unique_detectors)
list(LENGTH unique_detectors unique_detector_count)
if(NOT unique_detector_count EQUAL detector_count)
    message(FATAL_ERROR "Native environment detector names must be unique")
endif()
string(JOIN "," PYOBF_DEMO_ENV_DETECTORS ${PYOBF_NATIVE_DEMO_ENV_DETECTORS})

set(PYOBF_NATIVE_CFF_FUNCTIONS
    "" CACHE STRING "Additional exact IR function names to transform")
set(PYOBF_NATIVE_CFF_CONFIG "" CACHE FILEPATH "Versioned CFF recipe configuration JSON")
option(PYOBF_NATIVE_DEMO_ARCHIVE "Build verified typed archives into the inner demo DLL" OFF)
option(PYOBF_NATIVE_DEMO_OUTER_CFF "Protect marked outer bootstrap glue in its own CFF domain" ON)
option(PYOBF_NATIVE_DEMO_PRE_CODE_HASH "Bind child release to an independent actual outer-text observation" OFF)
option(PYOBF_NATIVE_DEMO_POST_CODE_HASH "Bind later parent/inner operations to invocation-owned code observations" OFF)
option(PYOBF_NATIVE_DEMO_POST_MIXED "Bind two POST owners to both owned and measured original-edge sources" OFF)
set(PYOBF_NATIVE_DEMO_BUILDER_RECEIPT "" CACHE FILEPATH
    "Externally frozen builder receipt for the mixed POST final child image")
option(PYOBF_NATIVE_DEMO_G3_SUBJECTS
    "Require exact COFF-to-PE mixed owner and helper function subjects" OFF)
option(PYOBF_NATIVE_DEMO_G3_ENTRY_STATES
    "Require exact mixed owner entry states from the frozen CFF recipes" OFF)
option(PYOBF_NATIVE_DEMO_G3_REPLAY
    "Replay mixed CFF opt/Clang outputs before freezing the builder receipt" OFF)
option(PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN
    "Require a separately frozen O2 archive-origin producer record" OFF)
option(PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR
    "Replay the fixed requested-to-optimized O2 IR predecessor" OFF)
set(PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR_RECORD "" CACHE FILEPATH
    "External fixed record for the selected O2 IR predecessor")
option(PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION
    "Bind selected O2 archive predicate publication and read routes in the child PE" OFF)
option(PYOBF_NATIVE_DEMO_G3_ARCHIVE_DECODER_LINKAGE
    "Bind the selected archive decoder call and argument chain in the child PE" OFF)
option(PYOBF_NATIVE_DEMO_G3_ARCHIVE_FIRST_USE_ARM
    "Bind the selected conditional archive cache first-use arm in the child PE" OFF)
option(PYOBF_NATIVE_DEMO_G3_ARCHIVE_ENTRY_ROUTE
    "Bind the selected archive entry success path to the first-use arm" OFF)
option(PYOBF_NATIVE_DEMO_G3_O2_ORIGINAL_PREDICATES
    "Bind the selected O2 wrapper original predicate to its linked PE route" OFF)
set(PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN_RECORD "" CACHE FILEPATH
    "External fixed record for the selected O2 archive-origin producer chain")
option(PYOBF_NATIVE_DEMO_G3_LOCAL_CALLEES
    "Require exact mixed binding callees and their bounded local status route" OFF)
option(PYOBF_NATIVE_DEMO_G3_HELPER_ARGUMENTS
    "Bind both mixed helper entry arguments to the local binding call" OFF)
option(PYOBF_NATIVE_DEMO_G3_BINDING_STATUS_EFFECTS
    "Bind the local Scope binding-status pointer, generation and availability routes" OFF)
option(PYOBF_NATIVE_DEMO_G3_CONTEXT_AVAILABILITY_EFFECT
    "Bind the called context-availability closing decision and local lock route" OFF)
option(PYOBF_NATIVE_DEMO_G3_BOUND_CALL
    "Bind the local publication comparison, retained lease and invoke argument route" OFF)
option(PYOBF_NATIVE_DEMO_G3_RETAIN_LOCAL
    "Bind the selected retain-context guards and local increment route" OFF)
option(PYOBF_NATIVE_DEMO_G3_INVOKE_LOCAL
    "Bind the selected invoke request, callback and completion route" OFF)
option(PYOBF_NATIVE_DEMO_G3_ORIGINAL_PREDICATES
    "Bind mixed POST original predicates to their linked machine-code condition" OFF)
option(PYOBF_NATIVE_DEMO_G3_PARENT_CALLBACK
    "Bind the real outer creator callback target to its linked PE" OFF)
set(PYOBF_NATIVE_DEMO_OUTER_BUILDER_DIR "" CACHE PATH
    "External directory for independently frozen real and triggered outer builder receipts")
option(PYOBF_NATIVE_DEMO_G3_OUTER_REPLAY
    "Require fixed outer compiler replay and final PE build consistency" OFF)
if(PYOBF_NATIVE_DEMO_G3_SUBJECTS AND (NOT PYOBF_NATIVE_DEMO_POST_MIXED OR
        NOT PYOBF_NATIVE_DEMO_BUILDER_RECEIPT))
    message(FATAL_ERROR "G3 function subjects require mixed POST and a fixed builder receipt")
endif()
if(PYOBF_NATIVE_DEMO_G3_ENTRY_STATES AND NOT PYOBF_NATIVE_DEMO_G3_SUBJECTS)
    message(FATAL_ERROR "G3 entry states require exact G3 function subjects")
endif()
if(PYOBF_NATIVE_DEMO_G3_REPLAY AND NOT PYOBF_NATIVE_DEMO_G3_ENTRY_STATES)
    message(FATAL_ERROR "G3 builder replay requires exact mixed entry states")
endif()
if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN AND
        (NOT PYOBF_NATIVE_DEMO_G3_REPLAY OR NOT PYOBF_NATIVE_DEMO_ARCHIVE OR
         NOT PYOBF_NATIVE_CFF_SOURCE_OPT STREQUAL "O2" OR
         NOT PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN_RECORD))
    message(FATAL_ERROR "G3 archive origin requires builder replay, archive, source O2 and an external fixed record")
endif()
if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN_RECORD)
    get_filename_component(PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN_RECORD
        "${PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN_RECORD}" ABSOLUTE)
endif()
if(PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR AND
        (NOT PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN OR
         NOT PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR_RECORD))
    message(FATAL_ERROR "G3 O2 predecessor needs archive origin and an external fixed record")
endif()
if(PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR_RECORD)
    get_filename_component(PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR_RECORD
        "${PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR_RECORD}" ABSOLUTE)
endif()
if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION AND
        (NOT PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN OR
         NOT PYOBF_NATIVE_DEMO_G3_ENTRY_STATES OR
         NOT PYOBF_NATIVE_DEMO_G3_SUBJECTS OR
         NOT PYOBF_NATIVE_DEMO_POST_MIXED))
    message(FATAL_ERROR "G3 archive publication needs archive origin, exact subjects, entry states and mixed POST")
endif()
if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION AND PYOBF_NATIVE_DEMO_G3_ORIGINAL_PREDICATES)
    message(FATAL_ERROR "G3 archive publication and source-none original predicates are distinct profiles")
endif()
if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_DECODER_LINKAGE AND NOT PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION)
    message(FATAL_ERROR "G3 archive decoder linkage requires archive publication")
endif()
if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_FIRST_USE_ARM AND NOT PYOBF_NATIVE_DEMO_G3_ARCHIVE_DECODER_LINKAGE)
    message(FATAL_ERROR "G3 archive first-use arm requires decoder linkage")
endif()
if(PYOBF_NATIVE_DEMO_G3_ARCHIVE_ENTRY_ROUTE AND NOT PYOBF_NATIVE_DEMO_G3_ARCHIVE_FIRST_USE_ARM)
    message(FATAL_ERROR "G3 archive entry route requires the first-use arm")
endif()
if(PYOBF_NATIVE_DEMO_G3_O2_ORIGINAL_PREDICATES AND
        (NOT PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR OR
         NOT PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION))
    message(FATAL_ERROR "G3 O2 original predicates require O2 predecessor and archive publication")
endif()
if(PYOBF_NATIVE_DEMO_G3_LOCAL_CALLEES AND NOT PYOBF_NATIVE_DEMO_G3_ENTRY_STATES)
    message(FATAL_ERROR "G3 local callees require exact mixed entry states")
endif()
if(PYOBF_NATIVE_DEMO_G3_HELPER_ARGUMENTS AND NOT PYOBF_NATIVE_DEMO_G3_LOCAL_CALLEES)
    message(FATAL_ERROR "G3 helper arguments require the local callee proof")
endif()
if(PYOBF_NATIVE_DEMO_G3_BINDING_STATUS_EFFECTS AND NOT PYOBF_NATIVE_DEMO_G3_HELPER_ARGUMENTS)
    message(FATAL_ERROR "G3 binding-status effects require exact mixed helper arguments")
endif()
if(PYOBF_NATIVE_DEMO_G3_CONTEXT_AVAILABILITY_EFFECT AND
        NOT PYOBF_NATIVE_DEMO_G3_BINDING_STATUS_EFFECTS)
    message(FATAL_ERROR "G3 context-availability effect requires binding-status effects")
endif()
if(PYOBF_NATIVE_DEMO_G3_BOUND_CALL AND NOT PYOBF_NATIVE_DEMO_G3_CONTEXT_AVAILABILITY_EFFECT)
    message(FATAL_ERROR "G3 bound-call route requires context-availability effects")
endif()
if(PYOBF_NATIVE_DEMO_G3_RETAIN_LOCAL AND NOT PYOBF_NATIVE_DEMO_G3_BOUND_CALL)
    message(FATAL_ERROR "G3 retain local route requires bound-call route")
endif()
if(PYOBF_NATIVE_DEMO_G3_INVOKE_LOCAL AND
        (NOT PYOBF_NATIVE_DEMO_G3_BOUND_CALL OR NOT PYOBF_NATIVE_DEMO_G3_RETAIN_LOCAL))
    message(FATAL_ERROR "G3 invoke local route requires bound-call and retain local routes")
endif()
if(PYOBF_NATIVE_DEMO_G3_ORIGINAL_PREDICATES AND NOT PYOBF_NATIVE_DEMO_G3_ENTRY_STATES)
    message(FATAL_ERROR "G3 original predicates require exact mixed entry states")
endif()
if(PYOBF_NATIVE_DEMO_G3_PARENT_CALLBACK AND (NOT PYOBF_NATIVE_DEMO_POST_MIXED OR
        NOT PYOBF_NATIVE_DEMO_OUTER_CFF))
    message(FATAL_ERROR "G3 parent callback requires mixed POST and outer CFF")
endif()
if(PYOBF_NATIVE_DEMO_G3_OUTER_REPLAY AND (NOT PYOBF_NATIVE_DEMO_G3_PARENT_CALLBACK OR
        NOT PYOBF_NATIVE_DEMO_OUTER_BUILDER_DIR))
    message(FATAL_ERROR "G3 outer replay requires the parent callback gate and an external receipt directory")
endif()
if(PYOBF_NATIVE_DEMO_OUTER_BUILDER_DIR)
    if(NOT PYOBF_NATIVE_DEMO_POST_MIXED OR NOT PYOBF_NATIVE_DEMO_OUTER_CFF)
        message(FATAL_ERROR "Outer builder receipts currently require mixed POST and outer CFF")
    endif()
    get_filename_component(PYOBF_NATIVE_DEMO_OUTER_BUILDER_DIR
        "${PYOBF_NATIVE_DEMO_OUTER_BUILDER_DIR}" ABSOLUTE)
endif()
if(PYOBF_NATIVE_DEMO_BUILDER_RECEIPT)
    if(NOT PYOBF_NATIVE_DEMO_POST_MIXED)
        message(FATAL_ERROR "The builder receipt currently requires mixed POST")
    endif()
    get_filename_component(PYOBF_NATIVE_DEMO_BUILDER_RECEIPT
        "${PYOBF_NATIVE_DEMO_BUILDER_RECEIPT}" ABSOLUTE)
endif()
if(PYOBF_NATIVE_DEMO_POST_MIXED AND (NOT PYOBF_NATIVE_DEMO_POST_CODE_HASH OR
        NOT PYOBF_NATIVE_DEMO_OUTER_CFF OR NOT PYOBF_NATIVE_BACKEND_ID STREQUAL "windows_user"))
    message(FATAL_ERROR "Mixed POST requires outer CFF and the Windows post-release observation backend")
endif()
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH AND (NOT TARGET pyobf_native_measured_scope OR NOT PYOBF_NATIVE_BACKEND_ID STREQUAL "windows_user"))
    message(FATAL_ERROR "Post-release measurement requires the implemented Windows scoped observation backend")
endif()
if(PYOBF_NATIVE_DEMO_PRE_CODE_HASH AND (NOT TARGET pyobf_native_measured_release OR NOT PYOBF_NATIVE_BACKEND_ID STREQUAL "windows_user"))
    message(FATAL_ERROR "Measured bootstrap release requires the implemented Windows code-observation backend")
endif()
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/PostSubjects.cmake")
set(PYOBF_NATIVE_OUTER_CFF_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/recipes/bootstrap.json" CACHE FILEPATH
    "Separate outer-bootstrap CFF recipe")
set(PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT "none" CACHE STRING "Ordinary outer source optimization before CFF: none or O2")
set_property(CACHE PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT PROPERTY STRINGS none O2)
if(PYOBF_NATIVE_DEMO_OUTER_CFF)
    get_filename_component(PYOBF_NATIVE_OUTER_CFF_CONFIG "${PYOBF_NATIVE_OUTER_CFF_CONFIG}" ABSOLUTE)
    if(NOT EXISTS "${PYOBF_NATIVE_OUTER_CFF_CONFIG}")
        message(FATAL_ERROR "Outer-bootstrap CFF configuration file is absent")
    endif()
    if(NOT PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT STREQUAL "none" AND NOT PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT STREQUAL "O2")
        message(FATAL_ERROR "Native outer source optimization must be none or O2")
    endif()
endif()
set(PYOBF_NATIVE_CFF_SOURCE_OPT "none" CACHE STRING "Ordinary source IR optimization before CFF: none or O2")
set_property(CACHE PYOBF_NATIVE_CFF_SOURCE_OPT PROPERTY STRINGS none O2)
set(PYOBF_NATIVE_DEMO_ASSET "" CACHE FILEPATH "Optional binary asset embedded through the archive pipeline")
if(PYOBF_NATIVE_DEMO_ASSET AND NOT PYOBF_NATIVE_DEMO_ARCHIVE)
    message(FATAL_ERROR "The demo asset requires PYOBF_NATIVE_DEMO_ARCHIVE=ON")
endif()
if(NOT PYOBF_NATIVE_CFF_SOURCE_OPT STREQUAL "none" AND NOT PYOBF_NATIVE_CFF_SOURCE_OPT STREQUAL "O2")
    message(FATAL_ERROR "Native source optimization must be none or O2")
endif()
if(PYOBF_NATIVE_DEMO_ARCHIVE)
    if(NOT PYOBF_NATIVE_BACKEND_CAN_ARCHIVE OR NOT PYOBF_NATIVE_BACKEND_ARCHIVE_SOURCES)
        message(FATAL_ERROR "The selected backend does not provide archive operations")
    endif()
    if(NOT PYOBF_NATIVE_CFF_CONFIG)
        set(PYOBF_NATIVE_CFF_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/recipes/archive.json")
    endif()
endif()
set(PYOBF_NATIVE_CFF_PRIVATE_MAP "" CACHE FILEPATH "Opt-in private CFF site/source map")
set(PYOBF_DEMO_CFF_CONFIG_ARGS "")
set(PYOBF_DEMO_CFF_MAP_ARGS "")
if(PYOBF_NATIVE_CFF_CONFIG)
    get_filename_component(PYOBF_NATIVE_CFF_CONFIG "${PYOBF_NATIVE_CFF_CONFIG}" ABSOLUTE)
    if(NOT EXISTS "${PYOBF_NATIVE_CFF_CONFIG}")
        message(FATAL_ERROR "Native CFF configuration file is absent")
    endif()
    list(APPEND PYOBF_DEMO_CFF_CONFIG_ARGS "-pyobf-cff-config=${PYOBF_NATIVE_CFF_CONFIG}")
endif()
if(PYOBF_NATIVE_CFF_PRIVATE_MAP)
    if(PYOBF_NATIVE_DEMO_G3_REPLAY)
        message(FATAL_ERROR "G3 builder replay does not admit a private-map output")
    endif()
    get_filename_component(PYOBF_NATIVE_CFF_PRIVATE_MAP "${PYOBF_NATIVE_CFF_PRIVATE_MAP}" ABSOLUTE)
    list(APPEND PYOBF_DEMO_CFF_MAP_ARGS "-pyobf-cff-private-map=${PYOBF_NATIVE_CFF_PRIVATE_MAP}")
endif()
set(PYOBF_NATIVE_CFF_REGIONS
    "" CACHE STRING "Semicolon-separated function:entry:exit CFF regions")
set(PYOBF_DEMO_CFF_REGION_ARGS "")
foreach(cff_region IN LISTS PYOBF_NATIVE_CFF_REGIONS)
    list(APPEND PYOBF_DEMO_CFF_REGION_ARGS "-pyobf-cff-region=${cff_region}")
endforeach()
option(PYOBF_NATIVE_CFF_MARKERS "Select source-marked payload and SDK functions" ON)
set(PYOBF_NATIVE_DEMO_PAYLOAD_BINDING "strict" CACHE STRING "Payload source binding: strict or decoupled")
set_property(CACHE PYOBF_NATIVE_DEMO_PAYLOAD_BINDING PROPERTY STRINGS strict decoupled)
if(NOT PYOBF_NATIVE_DEMO_PAYLOAD_BINDING STREQUAL "strict" AND
        NOT PYOBF_NATIVE_DEMO_PAYLOAD_BINDING STREQUAL "decoupled")
    message(FATAL_ERROR "Native payload binding must be strict or decoupled")
endif()
if(PYOBF_NATIVE_DEMO_PAYLOAD_BINDING STREQUAL "strict" AND
        (NOT PYOBF_NATIVE_CFF_MARKERS OR NOT TARGET pyobf_native_contribution_provider))
    message(FATAL_ERROR "Strict payload binding requires marked SDK support and an available contribution provider")
endif()
if(PYOBF_NATIVE_DEMO_POST_CODE_HASH AND NOT PYOBF_NATIVE_DEMO_PAYLOAD_BINDING STREQUAL "strict")
    message(FATAL_ERROR "Post-release measurement requires strict measured payload binding")
endif()
if(PYOBF_NATIVE_DEMO_POST_MIXED AND NOT PYOBF_NATIVE_DEMO_PAYLOAD_BINDING STREQUAL "strict")
    message(FATAL_ERROR "Mixed POST requires strict payload binding")
endif()
if(PYOBF_NATIVE_DEMO_ARCHIVE AND NOT PYOBF_NATIVE_CFF_MARKERS)
    message(FATAL_ERROR "The archive demo requires marked SDK support selection")
endif()
option(PYOBF_NATIVE_CFF_REQUIRE_DECISION_FLOW
    "Reject source-marked functions that only receive padded CFF shape" OFF)
if(PYOBF_NATIVE_CFF_REQUIRE_DECISION_FLOW)
    set(PYOBF_DEMO_CFF_REQUIRE_DECISION_FLOW true)
else()
    set(PYOBF_DEMO_CFF_REQUIRE_DECISION_FLOW false)
endif()
if(NOT PYOBF_NATIVE_CFF_FUNCTIONS AND NOT PYOBF_NATIVE_CFF_MARKERS AND
   NOT PYOBF_NATIVE_CFF_REGIONS AND NOT PYOBF_NATIVE_CFF_CONFIG)
    message(FATAL_ERROR "The native demo requires CFF functions or source markers")
endif()
string(JOIN "," PYOBF_DEMO_CFF_FUNCTIONS ${PYOBF_NATIVE_CFF_FUNCTIONS})
if(PYOBF_NATIVE_CFF_MARKERS)
    set(default_deep_functions "pyobf_demo_compute")
else()
    set(default_deep_functions "")
endif()
set(PYOBF_NATIVE_CFF_DEEP_FUNCTIONS "${default_deep_functions}" CACHE STRING
    "Selected native functions that use the deeper CFF strategy")
set(payload_deep_functions ${PYOBF_NATIVE_CFF_DEEP_FUNCTIONS})
if(PYOBF_NATIVE_DEMO_PAYLOAD_BINDING STREQUAL "strict" AND NOT PYOBF_NATIVE_DEMO_POST_MIXED AND
        "pyobf_demo_compute" IN_LIST payload_deep_functions)
    list(APPEND payload_deep_functions pyobf_demo_bound_compute)
endif()
string(JOIN "," PYOBF_DEMO_CFF_DEEP_FUNCTIONS ${payload_deep_functions})
if(PYOBF_NATIVE_CFF_MARKERS)
    set(PYOBF_DEMO_CFF_MARKERS true)
else()
    set(PYOBF_DEMO_CFF_MARKERS false)
endif()
set(PYOBF_NATIVE_CFF_STRATEGY "relative-tree" CACHE STRING
    "Registered CFF strategy for the native demo")
if(NOT DEFINED PYOBF_NATIVE_CFF_SEED)
    string(RANDOM LENGTH 8 ALPHABET 123456789 generated_cff_seed)
    set(PYOBF_NATIVE_CFF_SEED "${generated_cff_seed}" CACHE STRING
        "Build-specific native CFF state-layout seed")
endif()
option(PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE
    "Let an unavailable environment detector proceed in the demo" ON)

if(PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE)
    set(PYOBF_DEMO_ALLOW_UNAVAILABLE 1)
else()
    set(PYOBF_DEMO_ALLOW_UNAVAILABLE 0)
endif()
string(RANDOM LENGTH 8 ALPHABET 123456789 PYOBF_DEMO_ENV_OPERATION_ID)
include(cmake/DecoyConfigure.cmake)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/demo_config.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/demo_config.hpp" @ONLY)
