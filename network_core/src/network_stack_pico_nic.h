/*
 *  OS Network Stack
 *
 *  Copyright (C) 2020, Hensoldt Cyber GmbH
 */
#pragma once

#include "OS_Types.h"
#include "OS_Error.h"

OS_Error_t
pico_nic_initialize(const os_network_stack_config_t* config);
