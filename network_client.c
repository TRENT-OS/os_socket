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
#include "interfaces/if_OS_Socket.h"
#include "lib_macros/Check.h"

/******************************************************************************/
OS_NetworkStackClient_SocketDataports_t* instance;

/******************************************************************************/
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
OS_NetworkSocket_create(
    const if_OS_Socket_t*      ctx,
    OS_NetworkSocket_Handle_t* phandle,
    int                        domain,
    int                        type)
{
    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(phandle);

    OS_NetworkSocket_Handle_t localHandle = OS_NetworkSocket_Handle_INVALID;

    CHECK_PTR_NOT_NULL(ctx->socket_create);

    OS_Error_t err = ctx->socket_create(
                         domain,
                         type,
                         &localHandle.handleID);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("os_socket_create() failed with error %d", err);
        localHandle = OS_NetworkSocket_Handle_INVALID;
        return err;
    }

    localHandle.ctx = *ctx;
    *phandle        = localHandle;
    return err;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_connect(
    OS_NetworkSocket_Handle_t      handle,
    const OS_NetworkSocket_Addr_t* dstAddr)
{
    CHECK_PTR_NOT_NULL(&handle.ctx.socket_connect);
    CHECK_PTR_NOT_NULL(dstAddr);

    return handle.ctx.socket_connect(handle.handleID, dstAddr);
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_bind(
    OS_NetworkSocket_Handle_t      handle,
    const OS_NetworkSocket_Addr_t* localAddr)
{
    CHECK_PTR_NOT_NULL(&handle.ctx.socket_bind);

    return handle.ctx.socket_bind(handle.handleID, localAddr);
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_listen(
    OS_NetworkSocket_Handle_t handle,
    int                       backlog)
{
    CHECK_PTR_NOT_NULL(&handle.ctx.socket_listen);

    return handle.ctx.socket_listen(handle.handleID, backlog);
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_accept(
    OS_NetworkSocket_Handle_t  handle,
    OS_NetworkSocket_Handle_t* pClientHandle,
    OS_NetworkSocket_Addr_t*   srcAddr)
{
    CHECK_PTR_NOT_NULL(&handle.ctx.socket_accept);
    CHECK_PTR_NOT_NULL(pClientHandle);
    CHECK_PTR_NOT_NULL(srcAddr);

    pClientHandle->ctx = handle.ctx;

    return handle.ctx.socket_accept(
               handle.handleID,
               &pClientHandle->handleID,
               srcAddr);
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_read(
    OS_NetworkSocket_Handle_t handle,
    void*                     buf,
    size_t                    requestedLen,
    size_t*                   actualLen)
{
    CHECK_PTR_NOT_NULL(&handle.ctx.socket_read);
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(actualLen);

    size_t tempLen = requestedLen;

    CHECK_DATAPORT_SET(handle.ctx.dataport);
    CHECK_DATAPORT_SIZE(handle.ctx.dataport, requestedLen);

    OS_Error_t err = handle.ctx.socket_read(handle.handleID, &tempLen);

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    if (err != OS_SUCCESS)
    {
        return err;
    }

    memcpy(buf, OS_Dataport_getBuf(handle.ctx.dataport), tempLen);

    return OS_SUCCESS;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_recvfrom(
    OS_NetworkSocket_Handle_t handle,
    void*                     buf,
    size_t                    requestedLen,
    size_t*                   actualLen,
    OS_NetworkSocket_Addr_t*  srcAddr)
{
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(srcAddr);
    CHECK_PTR_NOT_NULL(&handle.ctx.socket_recvfrom);

    size_t tempLen = requestedLen;

    CHECK_DATAPORT_SET(handle.ctx.dataport);
    CHECK_DATAPORT_SIZE(handle.ctx.dataport, requestedLen);

    OS_Error_t err = handle.ctx.socket_recvfrom(
                         handle.handleID,
                         &tempLen,
                         srcAddr);

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    if (err != OS_SUCCESS)
    {
        return err;
    }

    memcpy(buf, OS_Dataport_getBuf(handle.ctx.dataport), tempLen);

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
    CHECK_PTR_NOT_NULL(&handle.ctx.socket_write);

    size_t tempLen = requestedLen;

    CHECK_DATAPORT_SET(handle.ctx.dataport);
    CHECK_DATAPORT_SIZE(handle.ctx.dataport, requestedLen);

    memcpy(OS_Dataport_getBuf(handle.ctx.dataport), buf, requestedLen);

    OS_Error_t err = handle.ctx.socket_write(handle.handleID, &tempLen);

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    return err;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_sendto(
    OS_NetworkSocket_Handle_t      handle,
    const void*                    buf,
    size_t                         requestedLen,
    size_t*                        actualLen,
    const OS_NetworkSocket_Addr_t* dstAddr)
{
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(dstAddr);
    CHECK_PTR_NOT_NULL(&handle.ctx.socket_sendto);

    size_t tempLen = requestedLen;

    CHECK_DATAPORT_SET(handle.ctx.dataport);
    CHECK_DATAPORT_SIZE(handle.ctx.dataport, requestedLen);

    memcpy(OS_Dataport_getBuf(handle.ctx.dataport), buf, requestedLen);

    OS_Error_t err = handle.ctx.socket_sendto(
                         handle.handleID,
                         &tempLen,
                         dstAddr);

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    return err;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_getPendingEvents(void)
{
    // TODO: Implement this functions with SEOS-2933.
    return OS_ERROR_NOT_IMPLEMENTED;
}

/******************************************************************************/
OS_Error_t
OS_NetworkSocket_close(
    OS_NetworkSocket_Handle_t handle)
{
    CHECK_PTR_NOT_NULL(&handle.ctx.socket_close);

    return handle.ctx.socket_close(handle.handleID);
}
