cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)

#-------------------------------------------------------------------------------
project(os_network_lib C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        network_core/src/network_stack_core.c
        network_core/src/network_config.c
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        include
)


add_subdirectory(3rdParty/picotcp)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        picotcp
        seos_core_api
        seos_libs
)

#-------------------------------------------------------------------------------
project(os_network_api C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        network_client_api_interface.c
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        seos_core_api
)


#-------------------------------------------------------------------------------
# if invoked from the OS sandbox, provide a documentation build target
if (COMMAND os_create_doxygen_target)

    # there are no pre or post steps
    os_create_doxygen_target(os_network_stack_doc ":" ":")

endif()
