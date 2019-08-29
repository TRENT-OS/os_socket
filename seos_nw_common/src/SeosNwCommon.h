/*
 *  SeosNwCommon.h
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
*/


/**
 * @defgroup SeosNwCommon SEOS Nwstack Common utility

 * @file SeosNwCommon.h

 * @brief Common utility functions for Network stack
 *
 */

#pragma once


#include "ChanMux_config.h"
#include "seos_err.h"

#include <stdint.h>
#include <stddef.h>
#include <limits.h>



/*********************************/
/*! Enum NW Stack Proxy Commands */
/*********************************/


typedef enum
{
    NW_CTRL_CMD_OPEN       =  0,   /*!< Open Channel */
    NW_CTRL_CMD_OPEN_CNF   =  1,   /*!< Open Confirmation */
    NW_CTRL_CMD_CLOSE      =  2,   /*!< Close Channel */
    NW_CTRL_CMD_CLOSE_CNF  =  3,   /*!< Close Confirmation */
    NW_CTRL_CMD_GETMAC     =  4,   /*!< GetMac for TAP */
    NW_CTRL_CMD_GETMAC_CNF =  5    /*!< GetMac Confirmation */
} Seos_NwCtrlCommand;


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
 * @details %seos_nw_strerror, convert pico error code to string

 * @ingroup SeosNwCommon
 *
 * @param e: Error Code which needs to be converted to string.

 * @return String corresponding to error code

 * @retval String of the error code
 *
 */

const char* seos_nw_strerror(int e);
