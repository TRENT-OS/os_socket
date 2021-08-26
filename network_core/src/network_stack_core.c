/*
 * OS Network Stack
 *
 * Core functions of the TRENTOS-M Network stack, independent of any
 * actual implementation
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "lib_debug/Debug.h"
#include "OS_Network.h"
#include "OS_NetworkStack.h"
#include "network/OS_NetworkStack.h"
#include "network/OS_Network_types.h"
#include "OS_NetworkStack.h"
#include "network_config.h"
#include "network_stack_core.h"
#include "network_stack_pico.h"
#include <stdlib.h>
#include <stdint.h>
#include "lib_macros/Check.h"

#define SOCKET_FREE   0
#define SOCKET_IN_USE 1
#define CONNECTED 1

typedef struct
{
    const OS_NetworkStack_CamkesConfig_t* camkes_cfg;
    const OS_NetworkStack_AddressConfig_t* cfg;
    OS_NetworkStack_SocketResources_t* sockets;
    OS_NetworkStack_Client_t* clients;

    int number_of_sockets;
} network_stack_t;

// network stack state
static network_stack_t instance = {0};


//------------------------------------------------------------------------------
const OS_NetworkStack_CamkesConfig_t*
config_get_handlers(void)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = instance.camkes_cfg;

    Debug_ASSERT( NULL != handlers );

    return handlers;
}


//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_create(
    const int  domain,
    const int  socket_type,
    int* const pHandle)
{
    CHECK_PTR_NOT_NULL(pHandle);

    return network_stack_pico_socket_create(
               domain,
               socket_type,
               pHandle,
               get_client_id(),
               get_client_id_buf(),
               get_client_id_buf_size());
}


//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_close(
    const int handle)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    CHECK_SOCKET(socket, handle);

    CHECK_CLIENT_ID(socket);

    return network_stack_pico_socket_close(handle, get_client_id());
}


//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_connect(
    const int                            handle,
    const OS_NetworkSocket_Addr_t* const dstAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    CHECK_SOCKET(socket, handle);

    CHECK_CLIENT_ID(socket);

    CHECK_PTR_NOT_NULL(dstAddr);

    CHECK_STR_IS_NUL_TERMINATED(dstAddr->addr, 16);

    return network_stack_pico_socket_connect(handle, dstAddr);
}


//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_bind(
    const int                            handle,
    const OS_NetworkSocket_Addr_t* const localAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    CHECK_SOCKET(socket, handle);

    CHECK_CLIENT_ID(socket);

    CHECK_PTR_NOT_NULL(localAddr);

    CHECK_STR_IS_NUL_TERMINATED(localAddr->addr, 16);

    return network_stack_pico_socket_bind(handle, localAddr);
}


//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_listen(
    const int handle,
    const int backlog)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    CHECK_SOCKET(socket, handle);

    CHECK_CLIENT_ID(socket);

    return network_stack_pico_socket_listen(handle, backlog);
}


//------------------------------------------------------------------------------
// For server wait on accept until client connects. Not much useful for client
// as we cannot accept incoming connections
OS_Error_t
networkStack_rpc_socket_accept(
    const int                      handle,
    int* const                     pClient_handle,
    OS_NetworkSocket_Addr_t* const srcAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    CHECK_SOCKET(socket, handle);

    CHECK_CLIENT_ID(socket);

    CHECK_PTR_NOT_NULL(pClient_handle);

    CHECK_PTR_NOT_NULL(srcAddr);

    return network_stack_pico_socket_accept(handle, pClient_handle, srcAddr);
}


//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_write(
    const int     handle,
    size_t* const pLen)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    CHECK_SOCKET(socket, handle);

    CHECK_CLIENT_ID(socket);

    CHECK_PTR_NOT_NULL(pLen);

    return network_stack_pico_socket_write(handle, pLen);
}

//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_read(
    const int     handle,
    size_t* const pLen)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    CHECK_SOCKET(socket, handle);

    CHECK_CLIENT_ID(socket);

    CHECK_PTR_NOT_NULL(pLen);

    return network_stack_pico_socket_read(handle, pLen);
}

//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_sendto(
    const int                            handle,
    size_t* const                        pLen,
    const OS_NetworkSocket_Addr_t* const dstAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    CHECK_SOCKET(socket, handle);

    CHECK_CLIENT_ID(socket);

    CHECK_PTR_NOT_NULL(pLen);

    CHECK_PTR_NOT_NULL(dstAddr);

    return network_stack_pico_socket_sendto(handle, pLen, dstAddr);
}

//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_recvfrom(
    const int                      handle,
    size_t* const                  pLen,
    OS_NetworkSocket_Addr_t* const srcAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    CHECK_SOCKET(socket, handle);

    CHECK_CLIENT_ID(socket);

    CHECK_PTR_NOT_NULL(pLen);

    return network_stack_pico_socket_recvfrom(handle, pLen, srcAddr);
}

//------------------------------------------------------------------------------
OS_Error_t
networkStack_rpc_socket_getPendingEvents(
    const size_t  maxRequestedSize,
    size_t* const pNumberOfEvents)
{
    CHECK_PTR_NOT_NULL(pNumberOfEvents);

    const int clientId = get_client_id();

    uint8_t* const clientDataport = get_client_id_buf();
    const size_t clientDataportSize = get_client_id_buf_size();

    int socketsWithEvents = 0;
    int offset = 0;
    int upperLimit = 0;

    if (maxRequestedSize <= clientDataportSize)
    {
        upperLimit = (maxRequestedSize - sizeof(OS_NetworkSocket_Evt_t));
    }
    else
    {
        upperLimit = (clientDataportSize - sizeof(OS_NetworkSocket_Evt_t));
    }

    do
    {
        int i = instance.clients[clientId].head;

        if (instance.sockets[i].client != NULL)
        {
            if (instance.sockets[i].client->clientId == clientId)
            {
                if (instance.sockets[i].eventMask)
                {
                    socketsWithEvents++;
                    OS_NetworkSocket_Evt_t event;

                    internal_network_stack_thread_safety_mutex_lock();
                    event.eventMask = instance.sockets[i].eventMask;
                    event.socketHandle = i;
                    event.currentError = instance.sockets[i].current_error;
                    instance.sockets[i].eventMask = 0;
                    internal_network_stack_thread_safety_mutex_unlock();

                memcpy(&clientDataport[offset], &event, sizeof(event));
                offset += sizeof(event);
            }
        }

        instance.clients[clientId].head++;

        if (instance.clients[clientId].head == instance.number_of_sockets)
        {
            instance.clients[clientId].head = 0;
        }
    }
    while ((instance.clients[clientId].head != instance.clients[clientId].tail)
           && (offset < upperLimit));

    // The loop was exited due to the fact that it reached the upperLimit of the
    // buffer to place the events in. Signal the client with the next tick, that
    // there are still events left.
    if (offset >= upperLimit
        && (instance.clients[clientId].head != instance.clients[clientId].tail))
    {
        instance.clients[clientId].needsToBeNotified = true;
    }

    instance.clients[clientId].tail = instance.clients[clientId].head;

    *pNumberOfEvents = socketsWithEvents;

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
// get implementation socket from a given handle
void*
get_implementation_socket_from_handle(
    const int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("Trying to use invalid handle");
        return NULL;
    }
    return instance.sockets[handle].implementation_socket;
}

//------------------------------------------------------------------------------
// get socket from a given handle
void*
get_socket_from_handle(
    const int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("Trying to use invalid handle");
        return NULL;
    }
    return &instance.sockets[handle];
}

//------------------------------------------------------------------------------
// get handle from a given socket
int
get_handle_from_implementation_socket(
    void* impl_sock)
{
    int handle = -1;
    for (int i = 0; i < instance.number_of_sockets; i++)
        if (instance.sockets[i].implementation_socket == impl_sock)
        {
            handle = i;
            break;
        }
    return handle;
}

//------------------------------------------------------------------------------
// Reserve a free handle
int
reserve_handle(
    void* impl_sock,
    int clientId)
{
    int handle = -1;

    if ((clientId < 0)
        || (instance.camkes_cfg->internal.number_of_clients <= clientId))
    {
        Debug_LOG_ERROR("Invalid client %d", clientId);
        return -1;
    }

    internal_socket_control_block_mutex_lock();

    if (!instance.clients[clientId].socketQuota)
    {
        Debug_LOG_ERROR("No free sockets available for client %d", clientId);
        internal_socket_control_block_mutex_unlock();
        return -1;
    }

    instance.clients[clientId].socketQuota--;

    for (int i = 0; i < instance.number_of_sockets; i++)
        if (instance.sockets[i].status == SOCKET_FREE)
        {
            instance.sockets[i].status = SOCKET_IN_USE;
            instance.sockets[i].implementation_socket = impl_sock;
            instance.sockets[i].accepted_handle = -1;
            instance.sockets[i].current_error = OS_SUCCESS;
            instance.sockets[i].client = &instance.clients[clientId];
            handle = i;
            break;
        }
    internal_socket_control_block_mutex_unlock();

    if ( handle == -1)
    {
        Debug_LOG_ERROR("No free sockets available %d", instance.number_of_sockets);
    }

    return handle;
}

//------------------------------------------------------------------------------
// free a handle
void
free_handle(
    const int handle,
    const int clientId)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("Trying to free invalid handle");
        return;
    }
    internal_socket_control_block_mutex_lock();

    instance.clients[clientId].socketQuota++;

    instance.sockets[handle].status = SOCKET_FREE;
    instance.sockets[handle].implementation_socket = NULL;
    instance.sockets[handle].accepted_handle = -1;
    instance.sockets[handle].client = NULL;
    internal_socket_control_block_mutex_unlock();
}

//------------------------------------------------------------------------------
// assign an accepted handle to its listening socket
void
set_accepted_handle(
    const int handle,
    const int accept_handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("set_accepted_handle: Invalid handle");
        return;
    }
    if (accept_handle < 0 || accept_handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("set_accepted_handle: Invalid accepted_handle");
        return;
    }
    internal_socket_control_block_mutex_lock();
    instance.sockets[handle].accepted_handle = accept_handle;
    instance.sockets[accept_handle].client = instance.sockets[handle].client;
    internal_socket_control_block_mutex_unlock();
}

//------------------------------------------------------------------------------
// get handle of the accepted connection
int
get_accepted_handle(
    const int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_accepted_handle: Invalid handle");
        return -1;
    }
    return instance.sockets[handle].accepted_handle;
}

//------------------------------------------------------------------------------
// get dataport for handle
const OS_Dataport_t*
get_dataport_for_handle(
    const int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_dataport_for_handle: Invalid handle");
        return NULL;
    }
    return &(instance.sockets[handle].buf);
}

//------------------------------------------------------------------------------
// notify any client that has pending socket events
static void
notify_clients_about_pending_events(
    void)
{
    for (int i = 0; i < instance.camkes_cfg->internal.number_of_clients; i++)
    {
        if (instance.clients[i].needsToBeNotified)
        {
            Debug_LOG_DEBUG("Client %d has pending events",
                            instance.clients[i].clientId);

            Debug_ASSERT(NULL != &instance.clients[i].eventNotify);
            instance.clients[i].eventNotify();
            instance.clients[i].needsToBeNotified = false;
        }
    }
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkStack_init(
    const OS_NetworkStack_CamkesConfig_t* const camkes_config,
    const OS_NetworkStack_AddressConfig_t* const config)
{
    if ((NULL == camkes_config) || (NULL == config))
    {
        Debug_LOG_ERROR("%s: cannot accept NULL arguments", __func__);
        return OS_ERROR_INVALID_PARAMETER;
    }

    instance.camkes_cfg = camkes_config;
    instance.cfg        = config;

    instance.sockets    = instance.camkes_cfg->internal.sockets;
    instance.number_of_sockets
        = camkes_config->internal.number_of_sockets;

    instance.clients    = instance.camkes_cfg->internal.clients;

    network_stack_interface_t network_stack = network_stack_pico_get_config();

    // initialize Network Stack and set API functions
    network_stack.stack_init();
    // initialize NIC
    OS_Error_t err = network_stack.nic_init(instance.cfg);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("initialize_nic() failed, error %d", err);
        return OS_ERROR_GENERIC;
    }

    return OS_SUCCESS;
}


//------------------------------------------------------------------------------
// CAmkES run()
OS_Error_t
OS_NetworkStack_run(void)
{
    if ((NULL == instance.camkes_cfg) || (NULL == instance.cfg))
    {
        Debug_LOG_ERROR("%s: cannot run on missing or failed initialization", __func__);
        return OS_ERROR_INVALID_STATE;
    }

    network_stack_interface_t network_stack = network_stack_pico_get_config();

    // enter endless loop processing events
    for (;;)
    {
        // wait for event ( 1 sec tick, write, read)
        wait_network_event();

        internal_network_stack_thread_safety_mutex_lock();
        // let stack process the event
        network_stack.stack_tick();
        notify_clients_about_pending_events();
        internal_network_stack_thread_safety_mutex_unlock();
    }

    Debug_LOG_WARNING("network_stack_event_loop() terminated gracefully");

    return OS_SUCCESS;
}
