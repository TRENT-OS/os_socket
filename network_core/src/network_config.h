/*
 *  OS Network Stack Config Wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Types.h"
#include "OS_Dataport.h"
#include "OS_NetworkStackConf.h"
#include <stddef.h>

typedef OS_Error_t (*nic_initialize_func_t)(
    const os_network_stack_config_t* config);
typedef OS_Error_t (*stack_initialize_func_t)(void);
typedef void (*stack_tick_func_t)(void);

typedef struct
{
    nic_initialize_func_t nic_init;
    stack_initialize_func_t stack_init;
    stack_tick_func_t stack_tick;
} network_stack_interface_t;

const os_camkes_network_stack_config_t* config_get_handlers(void);

//------------------------------------------------------------------------------
// System interface
//------------------------------------------------------------------------------

void wait_network_event(void);

void internal_notify_main_loop(void);

void internal_notify_read(
    int handle);

void internal_wait_read(
    int handle);

void internal_notify_write(
    int handle);

void internal_wait_write(
    int handle);

void internal_notify_connection(
    int handle);

void internal_wait_connection(
    int handle);

void wait_nic_init_done(void);
const OS_Dataport_t* get_nic_port_from(void);
const OS_Dataport_t* get_nic_port_to(void);

OS_Error_t
nic_rpc_dev_write(
    size_t* pLen);

OS_Error_t
nic_rpc_get_mac(void);

void notify_app_init_done(void);

const OS_Dataport_t*
get_app_port(
    int handle);

void internal_socket_control_block_mutex_lock(void);
void internal_socket_control_block_mutex_unlock(void);

void internal_network_stack_thread_safety_mutex_lock(void);
void internal_network_stack_thread_safety_mutex_unlock(void);
