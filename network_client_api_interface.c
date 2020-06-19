/*
 *  OS Network App CAmkES wrapper
 *
 *  Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 *
 *  The API's provided here can be used by the Application to create,
 *  connect, write and read data over socket connections.
 *
 */
#include "LibDebug/Debug.h"
#include "OS_Network.h"
#include "OS_Dataport.h"
#include <camkes.h>
#include <string.h>

//------------------------------------------------------------------------------
// RPC API, prefix "network_stack_rpc" comes from CAmkES RPC, the rest from the
// interface method list.
//------------------------------------------------------------------------------
extern OS_Error_t
network_stack_rpc_socket_create(
    unsigned int  domain,
    unsigned int type,
    unsigned int* pHandle);
extern OS_Error_t
network_stack_rpc_socket_accept(
    unsigned int  handle,
    unsigned int* pHandleClient,
    uint16_t  port);
extern OS_Error_t
network_stack_rpc_socket_bind(unsigned int handle, uint16_t port);
extern OS_Error_t
network_stack_rpc_socket_listen(unsigned int handle, unsigned int backlog);
extern OS_Error_t
network_stack_rpc_socket_connect(
    unsigned int  handle,
    const char* name,
    uint16_t    port);
extern OS_Error_t
network_stack_rpc_socket_close(unsigned int handle);
extern OS_Error_t
network_stack_rpc_socket_write(unsigned int handle, size_t* pLen);
extern OS_Error_t
network_stack_rpc_socket_read(unsigned int handle, size_t* pLen);

/******************************************************************************/
OS_Dataport_t dataport = OS_DATAPORT_ASSIGN(NwAppDataPort);

const OS_Dataport_t
get_data_port(void)
{
    return dataport;
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
    return network_stack_rpc_socket_close(handle);
}

/******************************************************************************/
OS_Error_t
OS_NetworkServerSocket_close(
    OS_NetworkServer_Handle_t srvHandle)
{
    return network_stack_rpc_socket_close(srvHandle);
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_write(
    OS_NetworkSocket_Handle_t handle,
    const void*               buf,
    size_t*                   plen)
{
    const OS_Dataport_t dp = get_data_port();

    if (*plen > OS_Dataport_getSize(dp))
    {
        Debug_LOG_ERROR("Buffer size exceeds dataport size");
        return OS_ERROR_INVALID_PARAMETER;
    }

    memcpy(OS_Dataport_getBuf(dp), buf, *plen);

    return network_stack_rpc_socket_write(handle, plen);
}

/******************************************************************************/
OS_Error_t
OS_NetworkServerSocket_accept(
    OS_NetworkServer_Handle_t  srvHandle,
    OS_NetworkSocket_Handle_t* phSocket)
{
    uint16_t   port = 0;
    return network_stack_rpc_socket_accept(srvHandle, phSocket, port);
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_read(
    OS_NetworkSocket_Handle_t handle,
    void*                     buf,
    size_t*                   plen)
{
    OS_Error_t err = network_stack_rpc_socket_read(handle, plen);

    if (err != OS_SUCCESS)
    {
        return err;
    }

    const OS_Dataport_t dp = get_data_port();

    if (*plen > OS_Dataport_getSize(dp))
    {
        Debug_LOG_ERROR("Buffer size exceeds dataport size");
        return OS_ERROR_INVALID_PARAMETER;
    }

    memcpy(buf, OS_Dataport_getBuf(dp), *plen);

    return OS_SUCCESS;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_recvfrom(
    OS_NetworkSocket_Handle_t handle,
    void*                     buf,
    size_t*                   plen,
    OS_Network_Socket_t*      other)
{
    OS_Error_t err = network_stack_rpc_socket_recvfrom(handle, plen, other);

    if (err != OS_SUCCESS)
    {
        return err;
    }

    const OS_Dataport_t dp = get_data_port();

    if (*plen > OS_Dataport_getSize(dp))
    {
        Debug_LOG_ERROR("Buffer size exceeds dataport size");
        return OS_ERROR_INVALID_PARAMETER;
    }

    memcpy(buf, OS_Dataport_getBuf(dp), *plen);

    return OS_SUCCESS;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_sendto(
    OS_NetworkSocket_Handle_t handle,
    const void*               buf,
    size_t*                   plen,
    OS_Network_Socket_t       other)
{
    const OS_Dataport_t dp = get_data_port();

    if (*plen > OS_Dataport_getSize(dp))
    {
        Debug_LOG_ERROR("Buffer size exceeds dataport size");
        return OS_ERROR_INVALID_PARAMETER;
    }

    memcpy(OS_Dataport_getBuf(dp), buf, *plen);

    return network_stack_rpc_socket_sendto(handle, plen, other);
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_bind(
    OS_NetworkSocket_Handle_t handle,
    uint16_t                  receiving_port)
{
    return network_stack_rpc_socket_bind(handle, receiving_port);
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

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_create() failed with error %d", err);
        return err;
    }

    err =
        network_stack_rpc_socket_bind(*pSrvHandle, pServerStruct->listen_port);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_bind() failed with error %d", err);
        return err;
    }

    err = network_stack_rpc_socket_listen(*pSrvHandle, pServerStruct->backlog);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_listen() failed with error %d", err);
        return err;
    }

    return OS_SUCCESS;
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

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_create() failed with error %d", err);
        return err;
    }

    if (pClientStruct->type == OS_SOCK_DGRAM)
    {
        return OS_SUCCESS;
    }

    err = network_stack_rpc_socket_connect(
              *phandle,
              pClientStruct->name,
              pClientStruct->port);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_connect() failed with error %d", err);
        return err;
    }

    return OS_SUCCESS;
}
