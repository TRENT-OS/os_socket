/*
 *  OS Network Stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "LibDebug/Debug.h"
#include "OS_Network.h"
#include "network/OS_NetworkStack.h"
#include "OS_NetworkStackConf.h"
#include "network_config.h"
#include "network_stack_pico.h"
#include <stdlib.h>
#include <stdint.h>

typedef struct
{
    const os_camkes_network_stack_config_t*   camkes_cfg;
    const os_network_stack_config_t*          cfg;
} network_stack_t;


// network stack state
static network_stack_t  instance = {0};

//------------------------------------------------------------------------------
const os_camkes_network_stack_config_t*
config_get_handlers(void)
{
    const os_camkes_network_stack_config_t* handlers = instance.camkes_cfg;

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
    OS_Network_Socket_t* source_socket)
{
    return network_stack_pico_socket_recvfrom(handle, pLen, source_socket);
}

//------------------------------------------------------------------------------
// CAmkES run()
OS_Error_t
OS_NetworkStack_run(
    const os_camkes_network_stack_config_t*  camkes_config,
    const os_network_stack_config_t*         config)
{
    OS_Error_t err;

    // remember config
    Debug_ASSERT( NULL != camkes_config );
    instance.camkes_cfg  = camkes_config;

    Debug_ASSERT( NULL != config );
    instance.cfg         = config;

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

        // let stack process the event
        network_stack.stack_tick();
    }

    Debug_LOG_WARNING("network_stack_event_loop() terminated gracefully");

    return OS_SUCCESS;
}
