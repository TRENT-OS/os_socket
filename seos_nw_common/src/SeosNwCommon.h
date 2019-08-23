/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosNwCommon.h
 *
 * @brief Common utility functions for Network stack
 *
 */

#pragma once


#include "ChanMux_config.h"
#include "seos_err.h"
#include "seos_socket.h"

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

/* Map cmds with uart as this is used by proxy */

typedef enum
{
    NW_CTRL_CMD_OPEN       =  0,   //UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_OPEN,
    NW_CTRL_CMD_OPEN_CNF   =  1,   // UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_OPEN_CNF,
    NW_CTRL_CMD_CLOSE      =  2,   //UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_CLOSE,
    NW_CTRL_CMD_CLOSE_CNF  =  3,   // UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_CLOSE_CNF,
    NW_CTRL_CMD_GETMAC     =  4,  //UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_GETMAC,
    NW_CTRL_CMD_GETMAC_CNF =  5  //UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_GETMAC_CNF
} NwCtrlCommand;


/* MACRO's */
#define VALIDATE_NULL(param) \
    if(!param) \
    { \
        return -1; \
    }

#define VALIDATE_ONE(param,value) \
    if(param != value) { \
        pico_err = PICO_ERR_EINVAL; \
        return -1; \
    }

#define VALIDATE_TWO(param,value1,value2) \
    if(param != value1 && param != value2) { \
        pico_err = PICO_ERR_EINVAL; \
        return -1; \
    }

/**
 * @brief converts pico error to string
 *
 * @param e (required) Error number which needs to be converted to string.

 * @return Corresponding string for the error value requested.

 * @retval Human readable String
 *
 */

extern const char* nw_strerror(int e);
