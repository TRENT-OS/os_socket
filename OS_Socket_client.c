/*
 * OS Socket Client API Implementation
 *
 * The OS Socket Client API implementation provided here can be used by client
 * applications connected to a Network Stack component to create, connect, write
 * and read data over socket connections.
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "OS_Socket.h"
#include "OS_Dataport.h"
#include "interfaces/if_OS_Socket.h"

#include "lib_debug/Debug.h"
#include "lib_macros/Check.h"

#include <string.h>

OS_Error_t
OS_Socket_create(
    const if_OS_Socket_t* const ctx,
    OS_Socket_Handle_t* const   phandle,
    const int                   domain,
    const int                   type)
{
    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(phandle);

    OS_Socket_Handle_t localHandle = OS_Socket_Handle_INVALID;

    CHECK_PTR_NOT_NULL(ctx->socket_create);

    OS_Error_t err = ctx->socket_create(
                         domain,
                         type,
                         &localHandle.handleID);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_TRACE("os_socket_create() failed with error %d", err);
        localHandle = OS_Socket_Handle_INVALID;
        return err;
    }

    localHandle.ctx = *ctx;
    *phandle        = localHandle;
    return err;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_Socket_connect(
    const OS_Socket_Handle_t      handle,
    const OS_Socket_Addr_t* const dstAddr)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_connect);
    CHECK_PTR_NOT_NULL(dstAddr);

    return handle.ctx.socket_connect(handle.handleID, dstAddr);
}

//------------------------------------------------------------------------------
OS_Error_t
OS_Socket_bind(
    const OS_Socket_Handle_t      handle,
    const OS_Socket_Addr_t* const localAddr)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_bind);

    return handle.ctx.socket_bind(handle.handleID, localAddr);
}

//------------------------------------------------------------------------------
OS_Error_t
OS_Socket_listen(
    const OS_Socket_Handle_t handle,
    const int                backlog)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_listen);

    return handle.ctx.socket_listen(handle.handleID, backlog);
}

//------------------------------------------------------------------------------
OS_Error_t
OS_Socket_accept(
    const OS_Socket_Handle_t  handle,
    OS_Socket_Handle_t* const pClientHandle,
    OS_Socket_Addr_t* const   srcAddr)
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
OS_Socket_read(
    const OS_Socket_Handle_t handle,
    void* const              buf,
    const size_t             requestedLen,
    size_t* const            actualLen)
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
OS_Socket_recvfrom(
    const OS_Socket_Handle_t handle,
    void* const              buf,
    const size_t             requestedLen,
    size_t* const            actualLen,
    OS_Socket_Addr_t* const  srcAddr)
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
OS_Socket_write(
    const OS_Socket_Handle_t handle,
    const void* const        buf,
    const size_t             requestedLen,
    size_t* const            actualLen)
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
OS_Socket_sendto(
    const OS_Socket_Handle_t      handle,
    const void* const             buf,
    const size_t                  requestedLen,
    size_t* const                 actualLen,
    const OS_Socket_Addr_t* const dstAddr)
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
OS_NetworkStack_State_t
OS_Socket_getStatus(
    const if_OS_Socket_t* const ctx)
{
    CHECK_PTR_NOT_NULL(ctx->socket_getStatus);

    OS_NetworkStack_State_t networkStackState = ctx->socket_getStatus();

    return networkStackState;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_Socket_getPendingEvents(
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
        const int eventDataSize = *numberOfEvents * sizeof(OS_Socket_Evt_t);

        CHECK_VALUE_IN_CLOSED_INTERVAL(eventDataSize, 0, bufSize);

        memcpy(buf, OS_Dataport_getBuf(ctx->dataport), eventDataSize);
    }

    ctx->shared_resource_mutex_unlock();

    return err;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_Socket_wait(
    const if_OS_Socket_t* const ctx)
{
    CHECK_PTR_NOT_NULL(ctx->socket_wait);

    ctx->socket_wait();

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
OS_Socket_poll(
    const if_OS_Socket_t* const ctx)
{
    CHECK_PTR_NOT_NULL(ctx->socket_poll);

    // Returns non-zero if an event was found.
    int ret = ctx->socket_poll();
    if (ret == 0)
    {
        return OS_ERROR_TRY_AGAIN;
    }
    else
    {
        return OS_SUCCESS;
    }
}

//------------------------------------------------------------------------------
OS_Error_t
OS_Socket_regCallback(
    const if_OS_Socket_t* const ctx,
    void (*callback)(void*),
    void* arg)
{
    CHECK_PTR_NOT_NULL(ctx->socket_regCallback);
    CHECK_PTR_NOT_NULL(callback);
    CHECK_PTR_NOT_NULL(arg);

    // Returns non-zero if the callback could not be registered.
    int ret = ctx->socket_regCallback(callback, arg);
    if (ret)
    {
        return OS_ERROR_GENERIC;
    }
    else
    {
        return OS_SUCCESS;
    }
}

//------------------------------------------------------------------------------
OS_Error_t
OS_Socket_close(
    const OS_Socket_Handle_t handle)
{
    CHECK_PTR_NOT_NULL(handle.ctx.socket_close);

    return handle.ctx.socket_close(handle.handleID);
}
