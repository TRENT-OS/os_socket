#
# OS Socket Client API Implementation
#
# Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


#-------------------------------------------------------------------------------
project(os_socket_client C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        OS_Socket_client.c
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        os_core_api
        lib_debug
        lib_macros
)
