/*
 * OS network stack configuration
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Error.h"
#include "OS_Network.h"
#include "OS_Types.h"
#include <stdlib.h>
#include <stdint.h>
#include "OS_Dataport.h"

typedef struct
{
    // The following variables are written from one thread (control thread) and
    // read from another (RPC thread) therefore volatile is needed to tell the
    // compiler that variable content can change outside of its control.
    volatile int status;
    volatile bool listening;
    volatile int accepted_handle;
    volatile int event;

    event_notify_func_t notify_connection;
    event_wait_func_t wait_connection;

    event_notify_func_t notify_write; // e_write_emit
    event_wait_func_t wait_write;     // c_write_wait

    event_notify_func_t notify_read; // e_read_emit
    event_wait_func_t wait_read;     // c_read_wait

    const OS_Dataport_t buf;

    void* implementation_socket;
} OS_NetworkStack_SocketResources_t;

typedef struct
{
    event_wait_func_t wait_loop_event;

    struct
    {
        event_notify_func_t notify_loop; // -> wait_event

        OS_NetworkStack_SocketResources_t* sockets;
        int number_of_sockets;

        mutex_lock_func_t allocator_lock;
        mutex_unlock_func_t allocator_unlock;

        mutex_lock_func_t nwStack_lock;
        mutex_unlock_func_t nwStack_unlock;

        mutex_lock_func_t socketCB_lock;
        mutex_unlock_func_t socketCB_unlock;

        mutex_lock_func_t stackTS_lock;
        mutex_unlock_func_t stackTS_unlock;
    } internal;

    struct
    {
        OS_Dataport_t from; // NIC -> stack
        OS_Dataport_t to;   // stack -> NIC
        struct
        {
            OS_Error_t (*dev_read)(size_t* len, size_t* frames_available);
            OS_Error_t (*dev_write)(size_t* len);
            OS_Error_t (*get_mac)(void);
            // API extension: OS_Error_t (*get_link_state)(void);
        } rpc;
    } drv_nic;

    struct
    {
        OS_Dataport_t port;
    } app;

} OS_NetworkStack_CamkesConfig_t;

typedef struct
{
    char* dev_addr;     /**< pointer to device address e.g. tap0, tap1 */
    char* gateway_addr; /**< pointer to gateway addr */
    char* subnet_mask;  /**< pointer to subnet mask */
} OS_NetworkStack_AddressConfig_t;

/**
 * @brief Initialize network stack
 *
 * Initialize the network stack
 *
 * @param camkes_config (required) camkes configuration
 * @param config (required) network configuration
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 */
OS_Error_t
OS_NetworkStack_init(
    const OS_NetworkStack_CamkesConfig_t* camkes_config,
    const OS_NetworkStack_AddressConfig_t* config);

/**
 * @brief Run network stack
 *
 *
 * @return an error code
 * @retval OS_SUCCESS if gracefully stopped
 * @retval OS_ERROR_INVALID_STATE if not initialized (see OS_NetworkStack_init())
 */
OS_Error_t
OS_NetworkStack_run(void);
