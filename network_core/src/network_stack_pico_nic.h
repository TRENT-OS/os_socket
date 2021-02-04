/*
 * OS Network Stack
 *
 * NIC level functions for the PicoTCP implementation of the network stack.
 *
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Types.h"
#include "OS_Error.h"

OS_Error_t
pico_nic_initialize(
    const OS_NetworkStack_AddressConfig_t* config);
