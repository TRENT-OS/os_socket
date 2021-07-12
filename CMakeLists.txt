#
# OS Network
#
# Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


# include the PicoTCP project, but do not build any targets from it unless they
# are explicitly included, e.g via os_network_lib below.
add_subdirectory(3rdParty/picotcp EXCLUDE_FROM_ALL)


#-------------------------------------------------------------------------------
project(os_network_lib C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        network_core/src/network_stack_core.c
        network_core/src/network_config.c
        network_core/src/network_stack_pico.c
        network_core/src/network_stack_pico_nic.c
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        include
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        picotcp
        os_core_api
        lib_debug
        lib_macros
)


#-------------------------------------------------------------------------------
project(os_network_api C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        network_client.c
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        include
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        os_core_api
        lib_debug
        lib_macros
)
