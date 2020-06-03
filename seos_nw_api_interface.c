/*
 *  OS Network App CAmkES wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 *  The API's provided here must be used by the Nw Application to create,
 *  connect, write and read data over socket connections.
 *
 */
#include "LibDebug/Debug.h"
#include "OS_Network.h"
#include <camkes.h>
#include <string.h>

//------------------------------------------------------------------------------
// RPC API, prefix "network_stack_rpc" comes from CAmkES RPC, the rest from the
// interface method list.
//------------------------------------------------------------------------------
extern OS_Error_t
network_stack_rpc_socket_create(
    unsigned  domain,
    unsigned  type,
    unsigned* pHandle);
extern OS_Error_t
network_stack_rpc_socket_accept(
    unsigned  handle,
    unsigned* pHandleClient,
    uint16_t  port);
extern OS_Error_t
network_stack_rpc_socket_bind(unsigned handle, uint16_t port);
extern OS_Error_t
network_stack_rpc_socket_listen(unsigned handle, unsigned backlog);
extern OS_Error_t
network_stack_rpc_socket_connect(
    unsigned    handle,
    const char* name,
    uint16_t    port);
extern OS_Error_t
network_stack_rpc_socket_close(unsigned handle);
extern OS_Error_t
network_stack_rpc_socket_write(unsigned handle, size_t* pLen);
extern OS_Error_t
network_stack_rpc_socket_read(unsigned handle, size_t* pLen);

/******************************************************************************/
static void*
get_data_port(void)
{
    return NwAppDataPort;
}

/*******************************************************************************
 * This must actually get called during OS Run time.
 * It must initialise NW stack with Camkes glue before an APP main() is
 * triggered.
 */
OS_Error_t
OS_NetworkAPP_RT(
    OS_Network_Context_t ctx)
{
    // wait for network stack initialization
    event_network_stack_init_done_wait();

    return OS_SUCCESS;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_close(
    OS_NetworkSocket_Handle_t handle)
{
    OS_Error_t err = network_stack_rpc_socket_close(handle);
    return err;
}

/******************************************************************************/
OS_Error_t
OS_NetworkServerSocket_close(
    OS_NetworkServer_Handle_t srvHandle)
{
    OS_Error_t err = network_stack_rpc_socket_close(srvHandle);
    return err;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_write(
    OS_NetworkSocket_Handle_t handle,
    const void*               buf,
    size_t*                   plen)
{
    void* data_port = get_data_port();
    memcpy(data_port, buf, *plen);
    OS_Error_t err = network_stack_rpc_socket_write(handle, plen);
    return err;
}

/******************************************************************************/
OS_Error_t
OS_NetworkServerSocket_accept(
    OS_NetworkServer_Handle_t  srvHandle,
    OS_NetworkSocket_Handle_t* phSocket)
{
    uint16_t   port = 0;
    OS_Error_t err = network_stack_rpc_socket_accept(srvHandle, phSocket, port);
    return err;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_read(
    OS_NetworkSocket_Handle_t handle,
    void* buf,
    size_t* plen)
{
    OS_Error_t err       = network_stack_rpc_socket_read(handle, plen);
    void*      data_port = get_data_port();
    memcpy(buf, data_port, *plen);
    return err;
}

/******************************************************************************/
OS_Error_t
OS_NetworkServerSocket_create(
    OS_Network_Context_t       ctx,
    OS_NetworkServer_Socket_t* pServerStruct,
    OS_NetworkServer_Handle_t* pSrvHandle)
{
    OS_Error_t err = network_stack_rpc_socket_create(
                         pServerStruct->domain,
                         pServerStruct->type,
                         pSrvHandle);
    if (err < 0)
    {
        Debug_LOG_INFO("os_socket_create() failed with error %d", err);
        return err;
    }

    err =
        network_stack_rpc_socket_bind(*pSrvHandle, pServerStruct->listen_port);
    if (err < 0)
    {
        Debug_LOG_INFO("os_socket_bind() failed with error %d", err);
        return err;
    }

    err = network_stack_rpc_socket_listen(*pSrvHandle, pServerStruct->backlog);
    if (err < 0)
    {
        Debug_LOG_INFO("os_socket_listen() failed with error %d", err);
        return err;
    }

    return err;
}

/*******************************************************************************
 * Creates a socket and connects to a remote server
 */
OS_Error_t
OS_NetworkSocket_create(
    OS_Network_Context_t       ctx,
    OS_Network_Socket_t*       pClientStruct,
    OS_NetworkSocket_Handle_t* phandle)
{
    OS_Error_t err = network_stack_rpc_socket_create(
                         pClientStruct->domain,
                         pClientStruct->type,
                         phandle);
    if (err < 0)
    {
        Debug_LOG_INFO("os_socket_create() failed with error %d", err);
        return err;
    }

    err = network_stack_rpc_socket_connect(
              *phandle,
              pClientStruct->name,
              pClientStruct->port);
    if (err < 0)
    {
        Debug_LOG_INFO("os_socket_connect() failed with error %d", err);
        return err;
    }

    return err;
}
