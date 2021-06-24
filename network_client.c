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
#include "interfaces/if_OS_NetworkStack.h"
#include "lib_macros/Check.h"

/******************************************************************************/

OS_NetworkStackClient_SocketDataports_t* instance;

const OS_Dataport_t
get_data_port(OS_NetworkSocket_Handle_t* handle)
{
    return instance->dataport[handle->handleID];
}

/*******************************************************************************/
OS_Error_t
OS_NetworkStackClient_init(
    OS_NetworkStackClient_SocketDataports_t* config)
{
    Debug_ASSERT(NULL != config);
    Debug_ASSERT(NULL != config->dataport);

    CHECK_PTR_NOT_NULL(config);

    instance = config;
    return OS_SUCCESS;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_close(
    OS_NetworkSocket_Handle_t handle)
{
    CHECK_PTR_NOT_NULL(handle.ctx);

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)handle.ctx;

    CHECK_PTR_NOT_NULL(vtable->socket_close);

    return vtable->socket_close(handle.handleID);
}

/******************************************************************************/
OS_Error_t
OS_NetworkServerSocket_close(
    OS_NetworkServer_Handle_t srvHandle)
{
    CHECK_PTR_NOT_NULL(srvHandle.ctx);

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)srvHandle.ctx;

    CHECK_PTR_NOT_NULL(vtable->socket_close);

    return vtable->socket_close(srvHandle.handleID);
}

/******************************************************************************/
OS_Error_t
OS_NetworkServerSocket_accept(
    OS_NetworkServer_Handle_t  srvHandle,
    OS_NetworkSocket_Handle_t* phSocket)
{
    CHECK_PTR_NOT_NULL(srvHandle.ctx);
    CHECK_PTR_NOT_NULL(phSocket);

    uint16_t port = 0;

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)srvHandle.ctx;
    phSocket->ctx                = srvHandle.ctx;

    CHECK_PTR_NOT_NULL(vtable->socket_accept);

    return vtable->socket_accept(srvHandle.handleID, &phSocket->handleID, port);
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_read(
    OS_NetworkSocket_Handle_t handle,
    void*                     buf,
    size_t                    requestedLen,
    size_t*                   actualLen)
{
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(handle.ctx);

    size_t tempLen = requestedLen;

    const OS_Dataport_t dp     = get_data_port(&handle);

    CHECK_DATAPORT_SET(dp);
    CHECK_DATAPORT_SIZE(dp, requestedLen);

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)handle.ctx;

    CHECK_PTR_NOT_NULL(vtable->socket_read);

    OS_Error_t err = vtable->socket_read(handle.handleID, &tempLen);

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
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(handle.ctx);

    size_t tempLen = requestedLen;

    const OS_Dataport_t dp     = get_data_port(&handle);

    CHECK_DATAPORT_SET(dp);
    CHECK_DATAPORT_SIZE(dp, requestedLen);

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)handle.ctx;

    CHECK_PTR_NOT_NULL(vtable->socket_recvfrom);

    OS_Error_t err =
        vtable->socket_recvfrom(handle.handleID, &tempLen, src_socket);

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
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(handle.ctx);

    size_t tempLen = requestedLen;

    const OS_Dataport_t dp     = get_data_port(&handle);

    CHECK_DATAPORT_SET(dp);
    CHECK_DATAPORT_SIZE(dp, requestedLen);

    memcpy(OS_Dataport_getBuf(dp), buf, requestedLen);

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)handle.ctx;

    CHECK_PTR_NOT_NULL(vtable->socket_write);

    OS_Error_t err = vtable->socket_write(handle.handleID, &tempLen);

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
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(handle.ctx);

    size_t tempLen = requestedLen;

    const OS_Dataport_t dp     = get_data_port(&handle);

    CHECK_DATAPORT_SET(dp);
    CHECK_DATAPORT_SIZE(dp, requestedLen);

    memcpy(OS_Dataport_getBuf(dp), buf, requestedLen);

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)handle.ctx;

    CHECK_PTR_NOT_NULL(vtable->socket_sendto);

    OS_Error_t err = vtable->socket_sendto(handle.handleID, &tempLen, dst_socket);

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
    CHECK_PTR_NOT_NULL(handle.ctx);

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)handle.ctx;

    CHECK_PTR_NOT_NULL(vtable->socket_bind);

    return vtable->socket_bind(handle.handleID, receiving_port);
}

/******************************************************************************/
OS_Error_t
OS_NetworkServerSocket_create(
    OS_Network_Context_t       ctx,
    OS_NetworkServer_Socket_t* pServerStruct,
    OS_NetworkServer_Handle_t* pSrvHandle)
{
    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(pServerStruct);
    CHECK_PTR_NOT_NULL(pSrvHandle);

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)ctx;

    OS_NetworkServer_Handle_t localHandle = OS_NetworkServer_Handle_INVALID;

    CHECK_PTR_NOT_NULL(vtable->socket_create);

    OS_Error_t err = vtable->socket_create(
                         pServerStruct->domain,
                         pServerStruct->type,
                         &localHandle.handleID);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_create() failed with error %d", err);
        localHandle = OS_NetworkServer_Handle_INVALID;
        goto exit;
    }

    CHECK_PTR_NOT_NULL(vtable->socket_bind);

    err = vtable->socket_bind(localHandle.handleID, pServerStruct->listen_port);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_bind() failed with error %d", err);
        goto err;
    }

    CHECK_PTR_NOT_NULL(vtable->socket_listen);

    err = vtable->socket_listen(localHandle.handleID, pServerStruct->backlog);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_listen() failed with error %d", err);
        goto err;
    }
    goto exit;

err:
    CHECK_PTR_NOT_NULL(vtable->socket_close);

    vtable->socket_close(localHandle.handleID);
    localHandle = OS_NetworkServer_Handle_INVALID;

exit:
    localHandle.ctx = ctx;
    *pSrvHandle     = localHandle;
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
    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(pClientStruct);
    CHECK_PTR_NOT_NULL(phandle);

    OS_NetworkSocket_Handle_t localHandle = OS_NetworkSocket_Handle_INVALID;

    if_OS_NetworkStack_t* vtable = (if_OS_NetworkStack_t*)ctx;

    CHECK_PTR_NOT_NULL(vtable->socket_create);

    OS_Error_t err = vtable->socket_create(
                         pClientStruct->domain,
                         pClientStruct->type,
                         &localHandle.handleID);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_create() failed with error %d", err);
        localHandle = OS_NetworkSocket_Handle_INVALID;
        goto exit;
    }

    if (pClientStruct->type == OS_SOCK_DGRAM)
    {
        goto exit;
    }

    CHECK_PTR_NOT_NULL(vtable->socket_connect);

    err = vtable->socket_connect(
              localHandle.handleID,
              pClientStruct->name,
              pClientStruct->port);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_connect() failed with error %d", err);
        goto err;
    }
    goto exit;

err:
    CHECK_PTR_NOT_NULL(vtable->socket_close);

    vtable->socket_close(localHandle.handleID);
    localHandle = OS_NetworkSocket_Handle_INVALID;

exit:
    localHandle.ctx = ctx;
    *phandle        = localHandle;
    return err;
}
