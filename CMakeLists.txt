cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


project(seos_nw_lib C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        seos_nw_core/src/SeosNwStack.c
        seos_nw_common/src/SeosNwCommon.c
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        seos_nw_common/src
        seos_nw_core/src/include
)


if (NETWORK_CONFIG_H_FILE)
    target_compile_definitions(${PROJECT_NAME}
        INTERFACE
            NETWORK_CONFIG_H_FILE="${NETWORK_CONFIG_H_FILE}"
    )
endif()


add_subdirectory(3rdParty/picotcp)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        picotcp
        seos_libs
        seos_core_api
)

# if invoked from the SEOS sandbox, provide a documentation build target
if (COMMAND seos_create_doxygen_target)

    # there are no pre or post steps
    seos_create_doxygen_target(seos_nw_lib_doc ":" ":")

endif()
