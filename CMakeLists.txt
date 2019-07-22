# SEOS NW Library

project(seos_nwcore C)

add_library(
    ${PROJECT_NAME} STATIC

    "seos_nwcore/src/SeosNwStack.c"
    "seos_nwcore/src/SeosNwChanmuxIf.c"
    "seos_nwcommon/src/SeosNwCommon.c"
)
if (ENABLE_LINT)
        set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
        set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

target_compile_options(${PROJECT_NAME}
    PUBLIC
        -Wall
        -Werror
)

if (DEBUG_CONFIG_H_FILE)
    list(APPEND PUBLIC_TARGET_COMPILE_DEFINITIONS
        "DEBUG_CONFIG_H_FILE=${DEBUG_CONFIG_H_FILE}"
    )
endif()

if (MEMORY_CONFIG_H_FILE)
    list(APPEND PUBLIC_TARGET_COMPILE_DEFINITIONS
        "MEMORY_CONFIG_H_FILE=${MEMORY_CONFIG_H_FILE}"
    )
endif()


target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "seos_nwcommon/src"
        "seos_nwcore/src/include"
)

target_link_libraries(${PROJECT_NAME}
    picotcp
    seos_libs
)
