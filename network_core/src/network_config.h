/*
 * OS Network Stack Config Wrapper
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Types.h"
#include "OS_Dataport.h"
#include "OS_NetworkStack.h"
#include <stddef.h>

typedef OS_Error_t (*nic_initialize_func_t)(
    const OS_NetworkStack_AddressConfig_t* config);
typedef OS_Error_t (*stack_initialize_func_t)(void);
typedef void (*stack_tick_func_t)(void);

typedef struct
{
    nic_initialize_func_t nic_init;
    stack_initialize_func_t stack_init;
    stack_tick_func_t stack_tick;
} network_stack_interface_t;

const OS_NetworkStack_CamkesConfig_t* config_get_handlers(void);

//------------------------------------------------------------------------------
// System interface
//------------------------------------------------------------------------------

void wait_network_event(void);

void internal_notify_main_loop(void);

const OS_Dataport_t* get_nic_port_from(void);
const OS_Dataport_t* get_nic_port_to(void);

OS_Error_t
nic_dev_read(
    size_t* pLen,
    size_t* frameRemaining);

OS_Error_t
nic_dev_write(
    size_t* pLen);

OS_Error_t
nic_dev_get_mac_address(void);

void internal_socket_control_block_mutex_lock(void);
void internal_socket_control_block_mutex_unlock(void);

void internal_network_stack_thread_safety_mutex_lock(void);
void internal_network_stack_thread_safety_mutex_unlock(void);
