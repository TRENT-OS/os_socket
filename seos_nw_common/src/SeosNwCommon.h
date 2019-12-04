/*
 *  Common utility functions for Network stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosError.h"
#include <stdint.h>
#include <stddef.h>


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


const char* seos_nw_strerror(int e);
