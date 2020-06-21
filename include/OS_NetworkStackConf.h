/*
 *  OS network stack configuration
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Error.h"
#include "OS_Types.h"
#include <stdlib.h>
#include <stdint.h>
#include "OS_Dataport.h"

typedef struct
{
    event_notify_func_t  notify_init_done;
    event_wait_func_t    wait_loop_event;

    struct
    {
        event_notify_func_t  notify_loop; // -> wait_event

        event_notify_func_t  notify_connection;
        event_wait_func_t    wait_connection;

        event_notify_func_t  notify_write;  // e_write_emit
        event_wait_func_t    wait_write;    // c_write_wait

        event_notify_func_t  notify_read;   // e_read_emit
        event_wait_func_t    wait_read;     // c_read_wait

        mutex_lock_func_t    allocator_lock;
        mutex_unlock_func_t  allocator_unlock;

        mutex_lock_func_t    nwStack_lock;
        mutex_unlock_func_t  nwStack_unlock;

        mutex_lock_func_t    socketCB_lock;
        mutex_unlock_func_t  socketCB_unlock;

        mutex_lock_func_t    stackTS_lock;
        mutex_unlock_func_t  stackTS_unlock;
    } internal;

    struct
    {
        OS_Dataport_t from; // NIC -> stack
        OS_Dataport_t to;   // stack -> NIC
        struct
        {
            OS_Error_t (*dev_write)(size_t* len);
            OS_Error_t (*get_mac)(void);
            // API extension: OS_Error_t (*get_link_state)(void);
        } rpc;
    } drv_nic;

    struct
    {
        event_notify_func_t   notify_init_done;
        OS_Dataport_t port;
    } app;

} os_camkes_network_stack_config_t;

typedef struct
{
    char*  dev_addr; /**< pointer to device address e.g. tap0, tap1 */
    char*  gateway_addr; /**< pointer to gateway addr */
    char*  subnet_mask; /**< pointer to subnet mask */
} os_network_stack_config_t;

OS_Error_t
OS_NetworkStack_run(
    const os_camkes_network_stack_config_t*  camkes_config,
    const os_network_stack_config_t*         config);

