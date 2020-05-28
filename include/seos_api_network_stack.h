/*
 *  SEOS network stack configuration
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Error.h"
#include "OS_Types.h"
#include <stdlib.h>
#include <stdint.h>

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
    } internal;

    struct
    {
        OS_shared_buffer_t  from;      // NIC -> stack
        OS_shared_buffer_t  to;        // stack -> NIC
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
        OS_shared_buffer_t  port;
    } app;

} seos_camkes_network_stack_config_t;


typedef struct
{
    char*  dev_addr; /**< pointer to device address e.g. tap0, tap1 */
    char*  gateway_addr; /**< pointer to gateway addr */
    char*  subnet_mask; /**< pointer to subnet mask */
} seos_network_stack_config_t;


OS_Error_t
seos_network_stack_run(
    const seos_camkes_network_stack_config_t*  camkes_config,
    const seos_network_stack_config_t*         config);

