/*
 * OS Network App CAmkES wrapper
 *
 * The API provided here can be used by the Application to create,
 * connect, write and read data over socket connections.
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "lib_debug/Debug.h"
#include "OS_Network.h"
#include "OS_Dataport.h"
#include <string.h>
#include "interfaces/if_OS_Socket.h"
#include "lib_macros/Check.h"

OS_Error_t
OS_NetworkSocket_create(
    const if_OS_Socket_t* const      ctx,
    OS_NetworkSocket_Handle_t* const phandle,
    const int                        domain,
    const int                        type)
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
        Debug_LOG_TRACE("os_socket_create() failed with error %d", err);
        localHandle = OS_NetworkSocket_Handle_INVALID;
        return err;
    }

    localHandle.ctx = *ctx;
    *phandle        = localHandle;
    return err;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_connect(
    const OS_NetworkSocket_Handle_t      handle,
    const OS_NetworkSocket_Addr_t* const dstAddr)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_connect);
    CHECK_PTR_NOT_NULL(dstAddr);

    return handle.ctx.socket_connect(handle.handleID, dstAddr);
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_bind(
    const OS_NetworkSocket_Handle_t      handle,
    const OS_NetworkSocket_Addr_t* const localAddr)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_bind);

    return handle.ctx.socket_bind(handle.handleID, localAddr);
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_listen(
    const OS_NetworkSocket_Handle_t handle,
    const int                       backlog)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_listen);

    return handle.ctx.socket_listen(handle.handleID, backlog);
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_accept(
    const OS_NetworkSocket_Handle_t  handle,
    OS_NetworkSocket_Handle_t* const pClientHandle,
    OS_NetworkSocket_Addr_t* const   srcAddr)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_accept);
    CHECK_PTR_NOT_NULL(pClientHandle);
    CHECK_PTR_NOT_NULL(srcAddr);

    pClientHandle->ctx = handle.ctx;

    return handle.ctx.socket_accept(
               handle.handleID,
               &pClientHandle->handleID,
               srcAddr);
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_read(
    const OS_NetworkSocket_Handle_t handle,
    void* const                     buf,
    const size_t                    requestedLen,
    size_t* const                   actualLen)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_read);
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(actualLen);

    size_t tempLen = requestedLen;

    CHECK_DATAPORT_SET(handle.ctx.dataport);
    CHECK_DATAPORT_SIZE(handle.ctx.dataport, requestedLen);

    handle.ctx.shared_resource_mutex_lock();

    OS_Error_t err = handle.ctx.socket_read(handle.handleID, &tempLen);
    if (err == OS_SUCCESS)
    {
        memcpy(buf, OS_Dataport_getBuf(handle.ctx.dataport), tempLen);
    }

    handle.ctx.shared_resource_mutex_unlock();

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    return err;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_recvfrom(
    const OS_NetworkSocket_Handle_t handle,
    void* const                     buf,
    const size_t                    requestedLen,
    size_t* const                   actualLen,
    OS_NetworkSocket_Addr_t* const  srcAddr)
{
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(srcAddr);
    CHECK_PTR_NOT_NULL(handle.ctx.socket_recvfrom);

    size_t tempLen = requestedLen;

    CHECK_DATAPORT_SET(handle.ctx.dataport);
    CHECK_DATAPORT_SIZE(handle.ctx.dataport, requestedLen);

    handle.ctx.shared_resource_mutex_lock();

    OS_Error_t err = handle.ctx.socket_recvfrom(
                         handle.handleID,
                         &tempLen,
                         srcAddr);
    if (err == OS_SUCCESS)
    {
        memcpy(buf, OS_Dataport_getBuf(handle.ctx.dataport), tempLen);
    }

    handle.ctx.shared_resource_mutex_unlock();

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    return err;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_write(
    const OS_NetworkSocket_Handle_t handle,
    const void* const               buf,
    const size_t                    requestedLen,
    size_t* const                   actualLen)
{
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(handle.ctx.socket_write);

    size_t tempLen = requestedLen;

    CHECK_DATAPORT_SET(handle.ctx.dataport);
    CHECK_DATAPORT_SIZE(handle.ctx.dataport, requestedLen);

    handle.ctx.shared_resource_mutex_lock();

    memcpy(OS_Dataport_getBuf(handle.ctx.dataport), buf, requestedLen);

    OS_Error_t err = handle.ctx.socket_write(handle.handleID, &tempLen);

    handle.ctx.shared_resource_mutex_unlock();

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    return err;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_sendto(
    const OS_NetworkSocket_Handle_t      handle,
    const void* const                    buf,
    const size_t                         requestedLen,
    size_t* const                        actualLen,
    const OS_NetworkSocket_Addr_t* const dstAddr)
{
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(dstAddr);
    CHECK_PTR_NOT_NULL(handle.ctx.socket_sendto);

    size_t tempLen = requestedLen;

    CHECK_DATAPORT_SET(handle.ctx.dataport);
    CHECK_DATAPORT_SIZE(handle.ctx.dataport, requestedLen);

    handle.ctx.shared_resource_mutex_lock();

    memcpy(OS_Dataport_getBuf(handle.ctx.dataport), buf, requestedLen);

    OS_Error_t err = handle.ctx.socket_sendto(
                         handle.handleID,
                         &tempLen,
                         dstAddr);

    handle.ctx.shared_resource_mutex_unlock();

    if (actualLen != NULL)
    {
        *actualLen = tempLen;
    }

    return err;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_getPendingEvents(
    const if_OS_Socket_t* const ctx,
    void* const                 buf,
    const size_t                bufSize,
    int* const                  numberOfEvents)
{
    CHECK_PTR_NOT_NULL(ctx->socket_getPendingEvents);
    CHECK_PTR_NOT_NULL(buf);
    CHECK_PTR_NOT_NULL(numberOfEvents);

    CHECK_DATAPORT_SET(ctx->dataport);

    ctx->shared_resource_mutex_lock();

    OS_Error_t err = ctx->socket_getPendingEvents(bufSize, numberOfEvents);
    if (err == OS_SUCCESS)
    {
        const int eventDataSize = *numberOfEvents * sizeof(OS_NetworkSocket_Evt_t);

        CHECK_VALUE_IN_CLOSED_INTERVAL(eventDataSize, 0, bufSize);

        memcpy(buf, OS_Dataport_getBuf(ctx->dataport), eventDataSize);
    }

    ctx->shared_resource_mutex_unlock();

    return err;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_NetworkSocket_close(
    const OS_NetworkSocket_Handle_t handle)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_close);

    return handle.ctx.socket_close(handle.handleID);
}
