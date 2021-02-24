/*
 * OS Network App CAmkES wrapper
 *
 * The API's provided here can be used by the Application to create,
 * connect, write and read data over socket connections.
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "lib_debug/Debug.h"
#include "OS_Network.h"
#include "OS_Dataport.h"
#include <string.h>
#include "OS_NetworkStackClient.h"

/******************************************************************************/

OS_NetworkStackClient_SocketDataports_t* instance ;

const OS_Dataport_t
get_data_port(int handle)
{
    Debug_ASSERT( handle >= 0 && handle < instance->number_of_sockets );
    return instance->dataport[handle];
}

/*******************************************************************************/
OS_Error_t
OS_NetworkStackClient_init(
    OS_NetworkStackClient_SocketDataports_t* config)
{
    Debug_ASSERT( NULL != config );
    Debug_ASSERT( NULL != config->dataport );
    instance = config;
    return OS_SUCCESS;
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
    size_t                    requestedLen,
    size_t*                   actualLen)
{
    size_t tempLen = requestedLen;

    const OS_Dataport_t dp  = get_data_port(handle);
    const size_t dpSize     = OS_Dataport_getSize(dp);

    if (requestedLen > dpSize)
    {
        Debug_LOG_ERROR("Buffer size %zu exceeds dataport size %zu for handle %d",
                        requestedLen, dpSize, handle);
        return OS_ERROR_INVALID_PARAMETER;
    }

    OS_Error_t err = network_stack_rpc_socket_read(handle, &tempLen);

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }


    if (err != OS_SUCCESS)
    {
        return err;
    }

    memcpy(buf, OS_Dataport_getBuf(dp), tempLen);

    return OS_SUCCESS;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_recvfrom(
    OS_NetworkSocket_Handle_t handle,
    void*                     buf,
    size_t                    requestedLen,
    size_t*                   actualLen,
    OS_Network_Socket_t*      src_socket)
{
    size_t tempLen = requestedLen;

    const OS_Dataport_t dp  = get_data_port(handle);
    const size_t dpSize     = OS_Dataport_getSize(dp);

    if (requestedLen > dpSize)
    {
        Debug_LOG_ERROR("Buffer size %zu exceeds dataport size %zu for handle %d",
                        requestedLen, dpSize, handle);
        return OS_ERROR_INVALID_PARAMETER;
    }

    OS_Error_t err = network_stack_rpc_socket_recvfrom(handle, &tempLen,
                                                       src_socket);

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    if (err != OS_SUCCESS)
    {
        return err;
    }

    memcpy(buf, OS_Dataport_getBuf(dp), tempLen);

    return OS_SUCCESS;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_write(
    OS_NetworkSocket_Handle_t handle,
    const void*               buf,
    size_t                    requestedLen,
    size_t*                   actualLen)
{
    size_t tempLen = requestedLen;

    const OS_Dataport_t dp  = get_data_port(handle);
    const size_t dpSize     = OS_Dataport_getSize(dp);

    if (requestedLen > dpSize)
    {
        Debug_LOG_ERROR("Buffer size %zu exceeds dataport size %zu for handle %d",
                        requestedLen, dpSize, handle);
        return OS_ERROR_INVALID_PARAMETER;
    }

    memcpy(OS_Dataport_getBuf(dp), buf, requestedLen);

    OS_Error_t err = network_stack_rpc_socket_write(handle, &tempLen);

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    return err;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_sendto(
    OS_NetworkSocket_Handle_t handle,
    const void*               buf,
    size_t                    requestedLen,
    size_t*                   actualLen,
    OS_Network_Socket_t       dst_socket)
{
    size_t tempLen = requestedLen;

    const OS_Dataport_t dp  = get_data_port(handle);
    const size_t dpSize     = OS_Dataport_getSize(dp);

    if (requestedLen > dpSize)
    {
        Debug_LOG_ERROR("Buffer size %zu exceeds dataport size %zu for handle %d",
                        requestedLen, dpSize, handle);
        return OS_ERROR_INVALID_PARAMETER;
    }

    memcpy(OS_Dataport_getBuf(dp), buf, requestedLen);

    OS_Error_t err = network_stack_rpc_socket_sendto(handle, &tempLen, dst_socket);

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    return err;
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
