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
#include <arpa/inet.h>

#include "OS_Dataport.h"

typedef struct
{
    // The following variables are written from one thread (control thread) and
    // read from another (RPC thread) therefore volatile is needed to tell the
    // compiler that variable content can change outside of its control.
    volatile bool needsToBeNotified;
    volatile int currentSocketsInUse;

    int clientId;
    bool inUse;
    int socketQuota;

    // Use head and tail per client to circulate through the pending events
    // whenever _getPendingEvents() is called.
    int head;
    int tail;

    event_notify_func_t eventNotify;
} OS_NetworkStack_Client_t;

typedef struct
{
    // The following variables are written from one thread (control thread) and
    // read from another (RPC thread) therefore volatile is needed to tell the
    // compiler that variable content can change outside of its control.
    volatile int status;
    volatile int parentHandle;
    volatile uint16_t eventMask;
    volatile OS_Error_t current_error;
    volatile int pendingConnections;

    int clientId;

    void* buf_io;
    OS_Dataport_t buf;

    void* implementation_socket;
} OS_NetworkStack_SocketResources_t;

typedef struct
{
    event_wait_func_t wait_loop_event;

    struct
    {
        event_notify_func_t notify_loop; // -> wait_event

        OS_NetworkStack_SocketResources_t* sockets;

        OS_NetworkStack_Client_t* clients;

        int number_of_sockets;
        int number_of_clients;
        int* client_sockets_quota;

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

} OS_NetworkStack_CamkesConfig_t;

typedef struct
{
    char dev_addr[INET_ADDRSTRLEN];     /**< device address, e.g. tap0, tap1 */
    char gateway_addr[INET_ADDRSTRLEN]; /**< gateway addr */
    char subnet_mask[INET_ADDRSTRLEN];  /**< subnet mask */
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
