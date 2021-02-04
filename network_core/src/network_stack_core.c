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
#include "network/OS_NetworkStack.h"
#include "OS_NetworkStack.h"
#include "network_config.h"
#include "network_stack_pico.h"
#include <stdlib.h>
#include <stdint.h>

#define SOCKET_FREE   0
#define SOCKET_IN_USE 1
#define CONNECTED 1

typedef struct
{
    const OS_NetworkStack_CamkesConfig_t*   camkes_cfg;
    const OS_NetworkStack_AddressConfig_t*          cfg;
    OS_NetworkStack_SocketResources_t* sockets;
    int number_of_sockets;
} network_stack_t;

// network stack state
static network_stack_t  instance = {0};


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
network_stack_rpc_socket_create(
    int   domain,
    int   socket_type,
    int*  pHandle)
{
    return network_stack_pico_socket_create(domain, socket_type, pHandle);
}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_close(
    int handle)
{
    return network_stack_pico_socket_close(handle);
}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_connect(
    int          handle,
    const char*  name,
    int          port)
{
    return network_stack_pico_socket_connect(handle, name, port);
}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_bind(
    int handle,
    uint16_t port)
{
    return network_stack_pico_socket_bind(handle, port);
}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_listen(
    int handle,
    int backlog)
{
    return network_stack_pico_socket_listen(handle, backlog);
}


//------------------------------------------------------------------------------
// For server wait on accept until client connects. Not much useful for client
// as we cannot accept incoming connections
OS_Error_t
network_stack_rpc_socket_accept(
    int handle,
    int* pClient_handle,
    uint16_t port)
{
    return network_stack_pico_socket_accept(handle, pClient_handle, port);
}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_write(
    int handle,
    size_t* pLen)
{
    return network_stack_pico_socket_write(handle, pLen);
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_read(
    int handle,
    size_t* pLen)
{
    return network_stack_pico_socket_read(handle, pLen);
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_sendto(
    int                 handle,
    size_t*             pLen,
    OS_Network_Socket_t dst_socket)
{
    return network_stack_pico_socket_sendto(handle, pLen, dst_socket);
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_recvfrom(
    int                  handle,
    size_t*              pLen,
    OS_Network_Socket_t* src_socket)
{
    return network_stack_pico_socket_recvfrom(handle, pLen, src_socket);
}

//------------------------------------------------------------------------------
// get implementation socket from a given handle
void*
get_implementation_socket_from_handle(
    int handle)
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
    int handle)
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
    void* impl_sock)
{
    int handle = -1;
    internal_socket_control_block_mutex_lock();
    for (int i = 0; i < instance.number_of_sockets; i++)
        if (instance.sockets[i].status == SOCKET_FREE)
        {
            instance.sockets[i].status = SOCKET_IN_USE;
            instance.sockets[i].implementation_socket = impl_sock;
            instance.sockets[i].listening = false;
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
    int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("Trying to free invalid handle");
        return;
    }
    internal_socket_control_block_mutex_lock();
    instance.sockets[handle].status = SOCKET_FREE;
    instance.sockets[handle].implementation_socket = NULL;
    internal_socket_control_block_mutex_unlock();
}

//------------------------------------------------------------------------------
// free a handle
void
set_accepted_handle(
    int handle,
    int accept_handle)
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
    internal_socket_control_block_mutex_unlock();
}

//------------------------------------------------------------------------------
// get handle of the accepted connection
int
get_accepted_handle(
    int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_accepted_handle: Invalid handle");
        return -1;
    }
    return instance.sockets[handle].accepted_handle;
}

//------------------------------------------------------------------------------
// get notify function for handle
event_notify_func_t
get_notify_conn_func_for_handle(
    int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_notify_conn_func_for_handle: Invalid handle");
        return NULL;
    }
    return instance.sockets[handle].notify_connection;
}

//------------------------------------------------------------------------------
// get wait function for handle
event_wait_func_t
get_wait_conn_func_for_handle(
    int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_wait_conn_func_for_handle: Invalid handle");
        return NULL;
    }
    return instance.sockets[handle].wait_connection;
}

//------------------------------------------------------------------------------
// get notify function for handle
event_notify_func_t
get_notify_write_func_for_handle(
    int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_notify_write_func_for_handle: Invalid handle");
        return NULL;
    }
    return instance.sockets[handle].notify_write;
}

//------------------------------------------------------------------------------
// get wait function for handle
event_wait_func_t
get_wait_write_func_for_handle(
    int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_wait_write_func_for_handle: Invalid handle");
        return NULL;
    }
    return instance.sockets[handle].wait_write;
}

//------------------------------------------------------------------------------
// get notify function for handle
event_notify_func_t
get_notify_read_func_for_handle(
    int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_notify_read_func_for_handle: Invalid handle");
        return NULL;
    }
    return instance.sockets[handle].notify_read;
}

//------------------------------------------------------------------------------
// get wait function for handle
event_wait_func_t
get_wait_read_func_for_handle(
    int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_wait_read_func_for_handle: Invalid handle");
        return NULL;
    }
    return instance.sockets[handle].wait_read;
}

//------------------------------------------------------------------------------
// get dataport for handle
const OS_Dataport_t*
get_dataport_for_handle(
    int handle)
{
    if (handle < 0 || handle >= instance.number_of_sockets)
    {
        Debug_LOG_ERROR("get_dataport_for_handle: Invalid handle");
        return NULL;
    }
    return &(instance.sockets[handle].buf);
}
//------------------------------------------------------------------------------
// CAmkES run()
OS_Error_t
OS_NetworkStack_run(
    const OS_NetworkStack_CamkesConfig_t*  camkes_config,
    const OS_NetworkStack_AddressConfig_t*         config)
{
    OS_Error_t err;

    // remember config
    Debug_ASSERT( NULL != camkes_config );
    instance.camkes_cfg = camkes_config;

    Debug_ASSERT( NULL != config );
    instance.cfg        = config;

    instance.sockets    = camkes_config->internal.sockets;
    instance.number_of_sockets = camkes_config->internal.number_of_sockets;

    network_stack_interface_t network_stack = network_stack_pico_get_config();

    // initialize Network Stack and set API functions
    network_stack.stack_init();
    // initialize NIC
    err = network_stack.nic_init(config);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("initialize_nic() failed, error %d", err);
        return OS_ERROR_GENERIC;
    }

    // notify app after that network stack is initialized
    Debug_LOG_INFO("signal network stack init done");
    notify_app_init_done();

    // enter endless loop processing events
    for (;;)
    {
        // wait for event ( 1 sec tick, write, read)
        wait_network_event();

        internal_network_stack_thread_safety_mutex_lock();
        // let stack process the event
        network_stack.stack_tick();
        internal_network_stack_thread_safety_mutex_unlock();
    }

    Debug_LOG_WARNING("network_stack_event_loop() terminated gracefully");

    return OS_SUCCESS;
}
