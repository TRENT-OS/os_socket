/*
 * OS Network Stack
 *
 * The PicoTCP implementation of the TRENTOS-M Network Stack.
 *
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#include <stddef.h>
#include <stdlib.h>

#include "OS_Network.h"
#include "network/OS_Network_types.h"
#include "network_config.h"
#include "network_stack_core.h"
#include "network_stack_pico.h"
#include "network_stack_pico_nic.h"
#include "pico_device.h"
#include "pico_icmp4.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_stack.h"

#include "lib_compiler/compiler.h"
#include "lib_debug/Debug.h"
#include "lib_debug/Debug_OS_Error.h"
#include "lib_macros/Check.h"

//------------------------------------------------------------------------------
static OS_Error_t
pico_err2os(
    pico_err_t err)
{
    switch (err)
    {
    case PICO_ERR_NOERR:
        return OS_SUCCESS;
    case PICO_ERR_ENOENT:
        return OS_ERROR_NOT_FOUND;
    case PICO_ERR_EIO:
    case PICO_ERR_ENXIO:
        return OS_ERROR_IO;
    case PICO_ERR_EAGAIN:
    case PICO_ERR_EBUSY:
        return OS_ERROR_TRY_AGAIN;
    case PICO_ERR_ENOMEM:
        return OS_ERROR_INSUFFICIENT_SPACE;
    case PICO_ERR_EACCESS:
        return OS_ERROR_ACCESS_DENIED;
    case PICO_ERR_EEXIST:
        return OS_ERROR_EXISTS;
    case PICO_ERR_EINVAL:
        return OS_ERROR_INVALID_PARAMETER;
    case PICO_ERR_ENONET:
        return OS_ERROR_NETWORK_NO_ROUTE;
    case PICO_ERR_EPROTO:
        return OS_ERROR_NETWORK_PROTO;
    case PICO_ERR_ENOPROTOOPT:
        return OS_ERROR_NETWORK_PROTO_OPT_NO_SUPPORT;
    case PICO_ERR_EPROTONOSUPPORT:
        return OS_ERROR_NETWORK_PROTO_NO_SUPPORT;
    case PICO_ERR_EOPNOTSUPP:
        return OS_ERROR_NETWORK_OP_NO_SUPPORT;
    case PICO_ERR_EADDRINUSE:
        return OS_ERROR_NETWORK_ADDR_IN_USE;
    case PICO_ERR_EADDRNOTAVAIL:
        return OS_ERROR_NETWORK_ADDR_NOT_AVAILABLE;
    case PICO_ERR_ENETDOWN:
        return OS_ERROR_NETWORK_DOWN;
    case PICO_ERR_ENETUNREACH:
        return OS_ERROR_NETWORK_UNREACHABLE;
    case PICO_ERR_ECONNRESET:
        return OS_ERROR_NETWORK_CONN_RESET;
    case PICO_ERR_EISCONN:
        return OS_ERROR_NETWORK_CONN_ALREADY_BOUND;
    case PICO_ERR_ENOTCONN:
        return OS_ERROR_NETWORK_CONN_NONE;
    case PICO_ERR_ESHUTDOWN:
        return OS_ERROR_NETWORK_CONN_SHUTDOWN;
    case PICO_ERR_ETIMEDOUT:
        return OS_ERROR_TIMEOUT;
    case PICO_ERR_ECONNREFUSED:
        return OS_ERROR_NETWORK_CONN_REFUSED;
    case PICO_ERR_EHOSTDOWN:
        return OS_ERROR_NETWORK_HOST_DOWN;
    case PICO_ERR_EHOSTUNREACH:
        return OS_ERROR_NETWORK_HOST_UNREACHABLE;
    case PICO_ERR_EINPROGRESS:
        return OS_ERROR_IN_PROGRESS;
    default:
        // PICO_ERR_EPERM
        // PICO_ERR_EINTR
        // PICO_ERR_EFAULT
        return OS_ERROR_GENERIC;
    }
}

//------------------------------------------------------------------------------
__attribute__((unused)) static const char*
pico_err2str(
    pico_err_t err)
{
#define CASE_PIC_ERR_STR(_code_)  case PICO_ERR_ ## _code_: return #_code_

    switch (err)
    {
        CASE_PIC_ERR_STR(NOERR);
        CASE_PIC_ERR_STR(EPERM);
        CASE_PIC_ERR_STR(ENOENT);
        CASE_PIC_ERR_STR(EINTR);
        CASE_PIC_ERR_STR(EIO);
        CASE_PIC_ERR_STR(ENXIO);
        CASE_PIC_ERR_STR(EAGAIN);
        CASE_PIC_ERR_STR(ENOMEM);
        CASE_PIC_ERR_STR(EACCESS);
        CASE_PIC_ERR_STR(EFAULT);
        CASE_PIC_ERR_STR(EBUSY);
        CASE_PIC_ERR_STR(EEXIST);
        CASE_PIC_ERR_STR(EINVAL);
        CASE_PIC_ERR_STR(ENONET);
        CASE_PIC_ERR_STR(EPROTO);
        CASE_PIC_ERR_STR(ENOPROTOOPT);
        CASE_PIC_ERR_STR(EPROTONOSUPPORT);
        CASE_PIC_ERR_STR(EOPNOTSUPP);
        CASE_PIC_ERR_STR(EADDRINUSE);
        CASE_PIC_ERR_STR(EADDRNOTAVAIL);
        CASE_PIC_ERR_STR(ENETDOWN);
        CASE_PIC_ERR_STR(ENETUNREACH);
        CASE_PIC_ERR_STR(ECONNRESET);
        CASE_PIC_ERR_STR(EISCONN);
        CASE_PIC_ERR_STR(ENOTCONN);
        CASE_PIC_ERR_STR(ESHUTDOWN);
        CASE_PIC_ERR_STR(ETIMEDOUT);
        CASE_PIC_ERR_STR(ECONNREFUSED);
        CASE_PIC_ERR_STR(EHOSTDOWN);
        CASE_PIC_ERR_STR(EHOSTUNREACH);
        CASE_PIC_ERR_STR(EINPROGRESS);
    default:
        break;
    }
    return "PICO_ERR_???";
}

network_stack_interface_t
network_stack_pico_get_config(void)
{
    network_stack_interface_t config;

    config.nic_init   = pico_nic_initialize;
    config.stack_init = pico_stack_init;
    config.stack_tick = pico_stack_tick;

    return config;
}

//------------------------------------------------------------------------------
static int
translate_socket_domain(
    const unsigned int domain)
{
    switch (domain)
    {
    //----------------------------------------
    case OS_AF_INET:
        return PICO_PROTO_IPV4;
    //----------------------------------------
    // case OS_AF_INET6:
    //    return PICO_PROTO_IPV6;
    //----------------------------------------
    default:
        break;
    }

    Debug_LOG_ERROR("unsupported socket domain %u", domain);

    return -1;
}


//------------------------------------------------------------------------------
static int
translate_socket_type(
    const unsigned int socket_type)
{
    switch (socket_type)
    {
    //----------------------------------------
    case OS_SOCK_STREAM:
        return PICO_PROTO_TCP;
    //----------------------------------------
    case OS_SOCK_DGRAM:
        return PICO_PROTO_UDP;
    //----------------------------------------
    default:
        break;
    }

    Debug_LOG_ERROR("unsupported socket type %u", socket_type);

    return -1;
}


//------------------------------------------------------------------------------
int
helper_socket_set_option_int(
    struct pico_socket* s,
    int                 option,
    int                 value)
{
    return pico_socket_setoption(s, option, &value);
}


//------------------------------------------------------------------------------
// This is called from the PicoTCP main tick loop to report socket events
static void
handle_pico_socket_event(
    uint16_t            event_mask,
    struct pico_socket* pico_socket)
{
    int handle = get_handle_from_implementation_socket(pico_socket);
    // Negative handle means that there is no TRENTOS socket for the given pico
    // socket. This can happen if accept wasn't called yet on an incoming
    // connection or close was called on the socket and the socket is in the
    // process of being shut down.
    if (handle < 0)
    {
        if (TCPSTATE(pico_socket) == PICO_SOCKET_STATE_TCP_CLOSE_WAIT)
        {
            // if the remote closes the socket before we called accept on it,
            // it enters the CLOSE WAIT state. There is no correstponding TRENTOS
            // socket we can close and we can't create one so we have to close
            // the pico socket here in order to avoid a handle leak.
            pico_socket_close(pico_socket);
            Debug_LOG_TRACE("[socket %d/%p] CLOSE WAIT", handle, pico_socket);
            return;
        }
        if (TCPSTATE(pico_socket) == PICO_SOCKET_STATE_TCP_CLOSING)
        {
            Debug_LOG_TRACE("[socket %d/%p] SOCKET CLOSING", handle, pico_socket);
            return;
        }
        if (TCPSTATE(pico_socket) == PICO_SOCKET_STATE_TCP_CLOSED)
        {
            Debug_LOG_TRACE("[socket %d/%p] SOCKET CLOSED", handle, pico_socket);
            return;
        }
        if (TCPSTATE(pico_socket) == PICO_SOCKET_STATE_TCP_TIME_WAIT)
        {
            Debug_LOG_TRACE("[socket %d/%p] TIME WAIT", handle, pico_socket);
            return;
        }
        return;
    }

    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);
    if (NULL == socket)
    {
        Debug_LOG_ERROR("%s: failed to get socket from handle %d",
                        __func__, handle);
        return;
    }
    Debug_LOG_TRACE("Event for handle %d/%p Value: 0x%x State %x",
                    handle, pico_socket, event_mask, TCPSTATE(pico_socket));

    char srcAddr[IP_ADD_STR_MAX_LEN];
    pico_ipv4_to_string(srcAddr, pico_socket->remote_addr.ip4.addr);

    if (event_mask & PICO_SOCK_EV_CONN)
    {
        Debug_LOG_TRACE("[socket %d/%p] PICO_SOCK_EV_CONN", handle, pico_socket);

        if (pico_socket->state & PICO_SOCKET_STATE_TCP_LISTEN)
        {
            // SYN has arrived
            Debug_LOG_INFO("[socket %d/%p] received incoming connection request",
                           handle,
                           pico_socket);
            socket->eventMask |= OS_SOCK_EV_CONN_ACPT;
            socket->pendingConnections++;
        }
        else
        {
            // SYN-ACK has arrived
            Debug_LOG_INFO("[socket %d/%p] connection established to %s",
                           handle,
                           pico_socket,
                           srcAddr);
            socket->eventMask |= OS_SOCK_EV_CONN_EST;
        }
    }

    if (event_mask & PICO_SOCK_EV_RD)
    {
        Debug_LOG_TRACE("[socket %d/%p] PICO_SOCK_EV_RD", handle, pico_socket);
        socket->eventMask |= OS_SOCK_EV_READ;
    }

    if (event_mask & PICO_SOCK_EV_WR)
    {
        Debug_LOG_TRACE("[socket %d/%p] PICO_SOCK_EV_WR", handle, pico_socket);
        // notify app, which is waiting to write
        socket->eventMask |= OS_SOCK_EV_WRITE;
    }

    if (event_mask & PICO_SOCK_EV_CLOSE)
    {
        Debug_LOG_INFO("[socket %d/%p] connection closed by %s",
                       handle, pico_socket, srcAddr);
        socket->eventMask |= OS_SOCK_EV_CLOSE;
    }

    if (event_mask & PICO_SOCK_EV_FIN)
    {
        Debug_LOG_TRACE("[socket %d/%p] PICO_SOCK_EV_FIN", handle, pico_socket);
        socket->eventMask |= OS_SOCK_EV_FIN;
        // If PICO_SOCK_EV_FIN is set by picoTCP, the implementation_socket will
        // be freed automatically and may not be accessed any more.
    }

    if (event_mask & PICO_SOCK_EV_ERR)
    {
        OS_Error_t err        = pico_err2os(pico_err);
        socket->current_error = err;
        Debug_LOG_ERROR("[socket %d/%p] PICO_SOCK_EV_ERR, OS error = %d (%s)",
                        handle,
                        pico_socket,
                        err,
                        Debug_OS_Error_toString(err));
        socket->eventMask |= OS_SOCK_EV_ERROR;

        // If err = PICO_ERR_ECONNREFUSED is set by picoTCP, the
        // implementation_socket will be freed automatically and may not be
        // accessed any more;
        // Workaround: set OS_SOCK_EV_FIN.
        if (pico_err == PICO_ERR_ECONNREFUSED)
        {
            Debug_LOG_DEBUG("[socket %d/%p] PICO_SOCK_EV_ERR & PICO_ERR_ECONNREFUSED",
                            handle, pico_socket);
            socket->eventMask |= OS_SOCK_EV_FIN;
        }
    }

    OS_NetworkStack_Client_t* client = get_client_from_clientId(
                                           socket->clientId);

    client->needsToBeNotified = true;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_create(
    const int  domain,
    const int  socket_type,
    int* const pHandle,
    const int  clientId,
    void*      buffer,
    const int  buffer_size)
{
    int pico_domain = translate_socket_domain(domain);
    if (pico_domain < 0)
    {
        Debug_LOG_ERROR("unsupported domain %d", domain);
        return OS_ERROR_NETWORK_PROTO_NO_SUPPORT;
    }

    int pico_type = translate_socket_type(socket_type);
    if (pico_type < 0)
    {
        Debug_LOG_ERROR("unsupported type %d", socket_type);
        return OS_ERROR_NETWORK_PROTO_NO_SUPPORT;
    }

    internal_network_stack_thread_safety_mutex_lock();
    struct pico_socket* pico_socket =
        pico_socket_open(pico_domain, pico_type, &handle_pico_socket_event);
    pico_err_t cur_pico_err = pico_err;
    internal_network_stack_thread_safety_mutex_unlock();
    if (NULL == pico_socket)
    {
        // try to detailed error from PicoTCP. Actually, nw_socket_open()
        // should return a proper error code and populate a handle passed as
        // pointer parameter, so we don't need to access pico_err here.
        Debug_LOG_ERROR("socket opening failed, pico_err = %d (%s)",
                        cur_pico_err, pico_err2str(cur_pico_err));
        return pico_err2os(cur_pico_err);
    }

    if (socket_type == OS_SOCK_STREAM) // TCP socket
    {
        helper_socket_set_option_int(
            pico_socket,
            PICO_TCP_NODELAY,
            PICO_TCP_NAGLE_DISABLE);
    }

    int handle = reserve_handle(pico_socket, clientId);

    if (handle == -1)
    {
        internal_network_stack_thread_safety_mutex_lock();
        if (pico_socket_close(pico_socket) != 0)
        {
            cur_pico_err = pico_err;
        }
        internal_network_stack_thread_safety_mutex_unlock();

        if (PICO_ERR_NOERR != cur_pico_err)
        {
            Debug_LOG_ERROR("socket closing failed, pico_err = %d (%s)",
                            cur_pico_err, pico_err2str(cur_pico_err));
        }
        Debug_LOG_ERROR("No free socket could be found");
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    socket->buf_io    = buffer;
    OS_Dataport_t tmp = OS_DATAPORT_ASSIGN_SIZE(socket->buf_io, buffer_size);
    socket->buf       = tmp;

    Debug_ASSERT(socket != NULL); // can't be null, as we got a valid handle above

    socket->current_error = pico_err2os(cur_pico_err);
    *pHandle              = handle;

    Debug_LOG_INFO("[socket %d/%p] socket opened", handle, pico_socket);

    helper_socket_set_option_int(
        pico_socket,
        PICO_TCP_NODELAY,
        PICO_TCP_NAGLE_DISABLE);

    // number of probes for TCP keepalive
    helper_socket_set_option_int(
        pico_socket,
        PICO_SOCKET_OPT_KEEPCNT,
        PICO_TCP_KEEPALIVE_COUNT);

    // timeout in ms for TCP keepalive probes
    helper_socket_set_option_int(
        pico_socket,
        PICO_SOCKET_OPT_KEEPIDLE,
        PICO_TCP_KEEPALIVE_PROBE_TIMEOUT);

    // timeout in ms for TCP keep alive retries
    helper_socket_set_option_int(
        pico_socket,
        PICO_SOCKET_OPT_KEEPINTVL,
        PICO_TCP_KEEPALIVE_RETRY_TIMEOUT);

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_close(
    const int handle,
    const int clientId)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);
    struct pico_socket* pico_socket = socket->implementation_socket;

    if (!(socket->eventMask & OS_SOCK_EV_FIN))
    {
        CHECK_SOCKET(pico_socket, handle);

        internal_network_stack_thread_safety_mutex_lock();
        int ret = pico_socket_close(pico_socket);
        OS_Error_t err =  pico_err2os(pico_err);
        socket->current_error = err;
        socket->eventMask     &= ~(OS_SOCK_EV_CLOSE);
        internal_network_stack_thread_safety_mutex_unlock();

        if (ret < 0)
        {
            Debug_LOG_ERROR("[socket %d/%p] nw_socket_close() failed with error %d, translating to OS error %d (%s)",
                            handle, pico_socket, ret,
                            err, Debug_OS_Error_toString(err));
            free_handle(handle, clientId);
            return err;
        }
    }

    free_handle(handle, clientId);

    Debug_LOG_INFO("[socket %d/%p] socket closed", handle, pico_socket);

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_connect(
    const int                            handle,
    const OS_NetworkSocket_Addr_t* const dstAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    if (socket->eventMask & OS_SOCK_EV_FIN)
    {
        return OS_ERROR_CONNECTION_CLOSED;
    }

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    Debug_LOG_DEBUG("[socket %d/%p] open connection to %s:%u ...",
                    handle, pico_socket, dstAddr->addr, dstAddr->port);

    struct pico_ip4 dst;
    if (pico_string_to_ipv4((char*)dstAddr->addr, &dst.addr) < 0)
    {
        Debug_LOG_ERROR("[socket %d/%p] pico_string_to_ipv4() failed translating name '%s'",
                        handle, pico_socket, dstAddr->addr);
        return OS_ERROR_INVALID_PARAMETER;
    }

    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_connect(pico_socket, &dst, short_be(dstAddr->port));
    OS_Error_t err =  pico_err2os(pico_err);
    socket->current_error = err;
    internal_network_stack_thread_safety_mutex_unlock();
    if (ret < 0)
    {
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_connect() failed with error %d, translating to OS error %d (%s)",
                        handle, pico_socket, ret,
                        err, Debug_OS_Error_toString(err));
        return err;
    }

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_bind(
    const int                            handle,
    const OS_NetworkSocket_Addr_t* const localAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    if (socket->eventMask & OS_SOCK_EV_FIN)
    {
        return OS_ERROR_CONNECTION_CLOSED;
    }

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    Debug_LOG_INFO("[socket %d/%p] binding to port %d", handle, pico_socket,
                   localAddr->port);

    struct pico_ip4 convertedAddr;
    if (pico_string_to_ipv4((char*)localAddr->addr, &convertedAddr.addr) < 0)
    {
        Debug_LOG_ERROR("[socket %d/%p] pico_string_to_ipv4() failed translating name '%s'",
                        handle, pico_socket, localAddr->addr);
        return OS_ERROR_INVALID_PARAMETER;
    }

    uint16_t be_port = short_be(localAddr->port);
    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_bind(pico_socket, &convertedAddr, &be_port);
    OS_Error_t err = pico_err2os(pico_err);
    socket->current_error = err;
    internal_network_stack_thread_safety_mutex_unlock();
    if (ret < 0)
    {
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_bind() failed with error %d, translating to OS error %d (%s)",
                        handle, pico_socket, ret,
                        err, Debug_OS_Error_toString(err));
        return err;
    }

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_listen(
    const int handle,
    const int backlog)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    if (socket->eventMask & OS_SOCK_EV_FIN)
    {
        return OS_ERROR_CONNECTION_CLOSED;
    }

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_listen(pico_socket, backlog);
    OS_Error_t err = pico_err2os(pico_err);
    socket->current_error = err;
    internal_network_stack_thread_safety_mutex_unlock();
    if (ret < 0)
    {
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_listen() failed with error %d, translating to OS error %d (%s)",
                        handle, pico_socket, ret,
                        err, Debug_OS_Error_toString(err));
        return err;
    }

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_accept(
    const int                      handle,
    int* const                     pClient_handle,
    OS_NetworkSocket_Addr_t* const srcAddr)
{
    uint16_t        port = 0;
    struct pico_ip4 orig = { 0 };

    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    if (socket->eventMask & OS_SOCK_EV_FIN)
    {
        return OS_ERROR_CONNECTION_CLOSED;
    }

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    internal_network_stack_thread_safety_mutex_lock();

    struct pico_socket* s_in = pico_socket_accept(pico_socket, &orig, &port);
    OS_Error_t          err  = pico_err2os(pico_err);
    socket->current_error    = err;
    if (socket->pendingConnections > 0)
    {
        socket->pendingConnections--;
    }

    if (socket->pendingConnections == 0)
    {
        socket->eventMask &= ~OS_SOCK_EV_CONN_ACPT;
    }

    if (NULL == s_in)
    {
        if (err != OS_ERROR_TRY_AGAIN)
        {
            Debug_LOG_ERROR(
                "[socket %p] nw_socket_accept() failed, OS error = %d (%s)",
                pico_socket,
                err,
                Debug_OS_Error_toString(err));
        }
        internal_network_stack_thread_safety_mutex_unlock();
        return err;
    }

    int accepted_handle = reserve_handle(s_in, socket->clientId);
    if (accepted_handle == -1)
    {
        pico_socket_close(s_in);
        internal_network_stack_thread_safety_mutex_unlock();
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    // The default values below are taken from the TCP unit tests of
    // PicoTCP, see tests/examples/tcpecho.c

    helper_socket_set_option_int(
        s_in,
        PICO_TCP_NODELAY,
        PICO_TCP_NAGLE_DISABLE);

    // number of probes for TCP keepalive
    helper_socket_set_option_int(
        s_in,
        PICO_SOCKET_OPT_KEEPCNT,
        PICO_TCP_KEEPALIVE_COUNT);

    // timeout in ms for TCP keepalive probes
    helper_socket_set_option_int(
        s_in,
        PICO_SOCKET_OPT_KEEPIDLE,
        PICO_TCP_KEEPALIVE_PROBE_TIMEOUT);

    // timeout in ms for TCP keep alive retries
    helper_socket_set_option_int(
        s_in,
        PICO_SOCKET_OPT_KEEPINTVL,
        PICO_TCP_KEEPALIVE_RETRY_TIMEOUT);

    set_parent_handle(accepted_handle, handle);

    *pClient_handle = accepted_handle;

    char acptAddr[IP_ADD_STR_MAX_LEN];
    pico_ipv4_to_string(acptAddr, orig.addr);

    Debug_LOG_INFO(
        "[socket %d/%p] accepted incoming connection from %s:%d",
        accepted_handle,
        get_implementation_socket_from_handle(accepted_handle),
        acptAddr,
        port);

    DECL_UNUSED_VAR(struct pico_socket * client_socket) =
        get_implementation_socket_from_handle(
            *pClient_handle);

    Debug_LOG_DEBUG("[socket %d/%p] incoming connection socket %d/%p",
                    handle, pico_socket, *pClient_handle, client_socket);

    OS_NetworkStack_SocketResources_t* socket_client;

    socket_client = get_socket_from_handle(*pClient_handle);

    CHECK_CLIENT_ID(socket_client);

    socket_client->buf_io = socket->buf_io;
    socket_client->buf    = socket->buf;
    internal_network_stack_thread_safety_mutex_unlock();

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_write(
    const int     handle,
    size_t* const pLen)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    if (socket->eventMask & OS_SOCK_EV_FIN)
    {
        return OS_ERROR_CONNECTION_CLOSED;
    }

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    uint8_t* buf = OS_Dataport_getBuf(socket->buf);
    size_t len = *pLen;

    CHECK_DATAPORT_SIZE(socket->buf, len);

    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_write(pico_socket,
                                buf,
                                len);
    OS_Error_t err = pico_err2os(pico_err);
    socket->current_error = err;
    internal_network_stack_thread_safety_mutex_unlock();

    if (ret < 0)
    {
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_write() failed with error %d, translating to OS error %d (%s)",
                        handle, pico_socket, ret,
                        err, Debug_OS_Error_toString(err));
        *pLen = 0;
        return err;
    }

    *pLen = ret;

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_read(
    const int     handle,
    size_t* const pLen)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    if (socket->eventMask & OS_SOCK_EV_FIN)
    {
        return OS_ERROR_CONNECTION_CLOSED;
    }

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    size_t len = *pLen; /* App requested length */

    uint8_t* buf = OS_Dataport_getBuf(socket->buf);

    CHECK_DATAPORT_SIZE(socket->buf, len);

    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_read(pico_socket, buf, len);
    OS_Error_t err = pico_err2os(pico_err);
    socket->current_error = err;
    internal_network_stack_thread_safety_mutex_unlock();

    // Encountered a read error in picoTcp.
    if (ret < 0)
    {
        if (err == OS_ERROR_NETWORK_CONN_SHUTDOWN)
        {
            Debug_LOG_INFO("[socket %d/%p] read() found connection closed",
                           handle, pico_socket);
        }
        else
        {
            Debug_LOG_ERROR("[socket %d/%p] nw_socket_read() failed with "
                            "error %d, translating to OS error %d (%s)",
                            handle, pico_socket, ret, err,
                            Debug_OS_Error_toString(err));
        }

        socket->eventMask &= ~OS_SOCK_EV_READ;

        *pLen = 0;

        return err;
    }

    // No further data available in the queue.
    else if (ret == 0)
    {
        socket->eventMask &= ~OS_SOCK_EV_READ;
        *pLen = ret;

        return OS_ERROR_TRY_AGAIN;
    }

    // Successfully read some data.
    else if (ret > 0)
    {
#if (Debug_Config_LOG_LEVEL >= Debug_LOG_LEVEL_TRACE)
        Debug_LOG_TRACE("[socket %d/%p] read data length=%d, data follows below",
                        handle, pico_socket, ret);

        Debug_hexDump(
            Debug_LOG_LEVEL_TRACE,
            "",
            OS_Dataport_getBuf(socket->buf),
            ret);
#endif
        if (len > ret)
        {
            socket->eventMask &= ~OS_SOCK_EV_READ;
        }
        *pLen = ret;
    }

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_sendto(
    const int                            handle,
    size_t* const                        pLen,
    const OS_NetworkSocket_Addr_t* const dstAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    if (socket->eventMask & OS_SOCK_EV_FIN)
    {
        return OS_ERROR_CONNECTION_CLOSED;
    }

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    uint8_t* buf = OS_Dataport_getBuf(socket->buf);
    size_t len = *pLen;

    CHECK_DATAPORT_SIZE(socket->buf, len);

    struct pico_ip4 dst = {};
    uint16_t        dport;
    pico_string_to_ipv4((char*)dstAddr->addr, &dst.addr);
    dport = short_be(dstAddr->port);

    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_sendto(pico_socket,
                                 buf,
                                 len,
                                 &dst,
                                 dport);
    OS_Error_t err = pico_err2os(pico_err);
    socket->current_error = err;
    internal_network_stack_thread_safety_mutex_unlock();

    if (ret < 0)
    {
        Debug_LOG_ERROR(
            "[socket %d/%p] nw_socket_sendto() failed with error %d, "
            "translating to OS error %d (%s)",
            handle,
            pico_socket,
            ret,
            err,
            Debug_OS_Error_toString(err));
        *pLen = 0;
        return err;
    }

    *pLen = ret;

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_recvfrom(
    const int                      handle,
    size_t* const                  pLen,
    OS_NetworkSocket_Addr_t* const srcAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    if (socket->eventMask & OS_SOCK_EV_FIN)
    {
        return OS_ERROR_CONNECTION_CLOSED;
    }

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    size_t len = *pLen;

    uint8_t* buf = OS_Dataport_getBuf(socket->buf);

    CHECK_DATAPORT_SIZE(socket->buf, len);

    struct pico_ip4 src = {0};
    uint16_t sport = 0;

    int ret;

    internal_network_stack_thread_safety_mutex_lock();
    ret = pico_socket_recvfrom(pico_socket, buf, len, &src, &sport);
    OS_Error_t err = pico_err2os(pico_err);
    socket->current_error = err;
    internal_network_stack_thread_safety_mutex_unlock();

    // Encountered a read error in picoTcp.
    if (ret < 0)
    {
        Debug_LOG_ERROR(
            "[socket %d/%p] nw_socket_recvfrom() failed with error %d, "
            "translating to OS error %d (%s)", handle, pico_socket, ret, err,
            Debug_OS_Error_toString(err));

        socket->eventMask &= ~OS_SOCK_EV_READ;
        *pLen = 0;

        return err;
    }
    else
    {
        // No further data could be read and the origin address and remote port
        // number are unchanged, meaning there is no further data in the queue.
        if ((ret == 0) && (src.addr == 0) && (sport == 0))
        {
            socket->eventMask &= ~OS_SOCK_EV_READ;
            *pLen = ret;

            return OS_ERROR_TRY_AGAIN;
        }
        // No further data could be read but the origin address and remote port
        // number were changed, meaning there is further data in the queue.
        else
        {
#if (Debug_Config_LOG_LEVEL >= Debug_LOG_LEVEL_TRACE)
            Debug_LOG_TRACE(
                "[socket %d/%p] read data length=%d, data follows below",
                handle,
                socket,
                len);

            Debug_hexDump(
                Debug_LOG_LEVEL_TRACE,
                "",
                OS_Dataport_getBuf(socket->buf),
                len);
#endif
            *pLen = ret;

            // If srcAddr is NULL it means the user doesn't want the
            // sender's information.
            if (NULL != srcAddr)
            {
                pico_ipv4_to_string((char*)srcAddr->addr, src.addr);

                srcAddr->port = short_be(sport);
            }
        }
    }

    return OS_SUCCESS;
}
