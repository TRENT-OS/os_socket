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
static void
handle_incoming_connection(OS_NetworkStack_SocketResources_t* socket)
{
    Debug_ASSERT(socket != NULL);// can't be null, as callers do the check
    uint16_t port = 0;
    struct pico_ip4 orig = {0};
    struct pico_socket* pico_socket = socket->implementation_socket;
    Debug_ASSERT(pico_socket !=
                 NULL); // can't be null, as we got a valid socket above

    // This call into the pico stack happens in the context of the stack tick
    // function and is protected by a mutex used there.
    struct pico_socket* s_in = pico_socket_accept(pico_socket, &orig, &port);
    OS_Error_t err =  pico_err2os(pico_err);
    socket->current_error = err;

    if (NULL == s_in)
    {
        Debug_LOG_ERROR("[socket %p] nw_socket_accept() failed, OS error = %d (%s)",
                        pico_socket, err, Debug_OS_Error_toString(err));
        return;
    }

    char peer[30] = {0};
    pico_ipv4_to_string(peer, orig.addr);

    // ToDo: port might be in big endian here, in this case we should
    //       better use short_be(port)

    Debug_LOG_INFO("[socket %p] connection from %s:%d established using socket %p",
                   pico_socket, peer, port, s_in);

    // The default values below are taken from the TCP unit tests of
    // PicoTCP, see tests/examples/tcpecho.c

    // disable nagle algorithm (1=disable, 0=enable)
    helper_socket_set_option_int(s_in, PICO_TCP_NODELAY, 1);

    // number of probes for TCP keepalive
    helper_socket_set_option_int(s_in, PICO_SOCKET_OPT_KEEPCNT, 5);

    // timeout in ms for TCP keepalive probes
    helper_socket_set_option_int(s_in, PICO_SOCKET_OPT_KEEPIDLE, 30000);

    // timeout in ms for TCP keep alive retries
    helper_socket_set_option_int(s_in, PICO_SOCKET_OPT_KEEPINTVL, 5000);

    int accepted_handle = reserve_handle(s_in, socket->clientId);
    set_accepted_handle(get_handle_from_implementation_socket(pico_socket),
                        accepted_handle);
}

//------------------------------------------------------------------------------
// This is called from the PicoTCP main tick loop to report socket events
static void
handle_pico_socket_event(
    uint16_t            event_mask,
    struct pico_socket* pico_socket)
{
    int handle = get_handle_from_implementation_socket(pico_socket);
    if (handle < 0)
    {
        if (pico_socket->state & (PICO_SOCKET_STATE_SHUT_LOCAL |
                                  PICO_SOCKET_STATE_SHUT_REMOTE |
                                  PICO_SOCKET_STATE_TCP_CLOSED))
        {
            // Don't log an ERROR here, as an invalid handle can also result
            // from a recently closed socket that receives final teardown
            // events.
            Debug_LOG_TRACE(
                "%s: invalid handle %d. "
                "Handle might already be freed due to recent close(). ",
                __func__, handle);
        }
        else
        {
            Debug_LOG_ERROR("%s: invalid handle %d", __func__, handle);
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
    Debug_LOG_DEBUG("Event for handle %d/%p Value: 0x%x State %x",
                    handle, pico_socket, event_mask, TCPSTATE(pico_socket));

    socket->event = event_mask;

    if (event_mask & PICO_SOCK_EV_CONN)
    {
        Debug_LOG_DEBUG("[socket %p] PICO_SOCK_EV_CONN", pico_socket);

        if (pico_socket->state & PICO_SOCKET_STATE_TCP_LISTEN)
        {
            // SYN has arrived
            handle_incoming_connection(socket);
        }
        else
        {
            // SYN-ACK has arrived
            Debug_LOG_INFO("[socket %p] incoming connection established",
                           pico_socket);
        }
        internal_notify_connection(handle);
    }

    if (event_mask & PICO_SOCK_EV_RD)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_RD", pico_socket);
        internal_notify_read(handle);
    }

    if (event_mask & PICO_SOCK_EV_WR)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_WR", pico_socket);
        // notify app, which is waiting to write
        internal_notify_write(handle);
    }

    if (event_mask & PICO_SOCK_EV_CLOSE)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_CLOSE", pico_socket);
        internal_notify_read(handle);
    }

    if (event_mask & PICO_SOCK_EV_FIN)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_FIN", pico_socket);
        internal_notify_read(handle);
    }

    if (event_mask & PICO_SOCK_EV_ERR)
    {
        OS_Error_t err          =  pico_err2os(pico_err);
        socket->current_error   = err;
        Debug_LOG_ERROR("[socket %p] PICO_SOCK_EV_ERR, OS error = %d (%s)",
                        pico_socket,
                        err,
                        Debug_OS_Error_toString(err));
        internal_notify_connection(handle);
        internal_notify_read(handle);
    }
}

OS_Error_t
network_stack_pico_socket_create(
    const int  domain,
    const int  socket_type,
    int* const pHandle,
    const int  clientID,
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
        // disable nagle algorithm (1=disable, 0=enable)
        helper_socket_set_option_int(pico_socket, PICO_TCP_NODELAY, 1);
    }

    int handle = reserve_handle(pico_socket, clientID);

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

    socket->current_error   = pico_err2os(cur_pico_err);
    *pHandle                = handle;

    Debug_LOG_INFO("[socket %d/%p] created new socket", handle, pico_socket);
    return OS_SUCCESS;
}

OS_Error_t
network_stack_pico_socket_close(
    const int handle)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_close(pico_socket);
    OS_Error_t err =  pico_err2os(pico_err);
    socket->current_error = err;
    internal_network_stack_thread_safety_mutex_unlock();

    if (ret < 0)
    {
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_close() failed with error %d, translating to OS error %d (%s)",
                        handle, pico_socket, ret,
                        err, Debug_OS_Error_toString(err));
        free_handle(handle);
        return err;
    }

    free_handle(handle);

    Debug_LOG_INFO("[socket %d/%p] close() handle", handle, pico_socket);

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_connect(
    const int                            handle,
    const OS_NetworkSocket_Addr_t* const dstAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

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

    Debug_LOG_DEBUG("[socket %d/%p] connect waiting ...", handle, pico_socket);
    internal_wait_connection(handle);
    internal_network_stack_thread_safety_mutex_lock();
    err = socket->current_error;
    internal_network_stack_thread_safety_mutex_unlock();

    if ((pico_socket->state & PICO_SOCKET_STATE_CONNECTED) == 0)
    {
        Debug_LOG_ERROR("[socket %d/%p] could not connect socket, OS error %d (%s)",
                        handle, pico_socket, err, Debug_OS_Error_toString(err));
        return err;
    }

    Debug_LOG_INFO("[socket %d/%p] connection established to %s:%u",
                   handle, pico_socket, dstAddr->addr, dstAddr->port);

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_bind(
    const int                            handle,
    const OS_NetworkSocket_Addr_t* const localAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

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
    OS_Error_t err =  pico_err2os(pico_err);
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
// For server wait on accept until client connects. Not much useful for client
// as we cannot accept incoming connections
OS_Error_t
network_stack_pico_socket_accept(
    const int                      handle,
    int* const                     pClient_handle,
    OS_NetworkSocket_Addr_t* const srcAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    struct pico_socket* pico_socket = socket->implementation_socket;

    // set default
    *pClient_handle = -1;

    CHECK_SOCKET(pico_socket, handle);

    Debug_LOG_DEBUG("[socket %d/%p] accept waiting ...", handle, pico_socket);
    internal_wait_connection(handle);
    internal_network_stack_thread_safety_mutex_lock();
    OS_Error_t err = socket->current_error;


    *pClient_handle = get_accepted_handle(handle);
    Debug_LOG_INFO("Accepted [socket %d/%p]",
                   get_accepted_handle(handle),
                   get_implementation_socket_from_handle(get_accepted_handle(handle)));

    struct pico_socket* client_socket = get_implementation_socket_from_handle(
                                            *pClient_handle);

    if (client_socket == NULL)
    {
        if (err == OS_SUCCESS)
        {
            err = OS_ERROR_GENERIC;

            Debug_LOG_ERROR("[socket %d/%p] OS success but no client to accept, "
                            "escalated to OS error %d (%s)",
                            handle, pico_socket, err, Debug_OS_Error_toString(err));
        }
        else
        {
            Debug_LOG_ERROR("[socket %d/%p] no client to accept, OS error %d (%s)",
                            handle, pico_socket, err, Debug_OS_Error_toString(err));
        }

        return err;
    }

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

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    uint8_t* buf = OS_Dataport_getBuf(socket->buf);
    size_t len = *pLen;

    CHECK_DATAPORT_SIZE(socket->buf, len);

    internal_wait_write(handle);

    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_write(pico_socket,
                                buf,
                                len);
    OS_Error_t err =  pico_err2os(pico_err);
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

    socket->event = 0;
    *pLen       = ret;

    internal_notify_main_loop();

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
// Is a blocking call. Wait until we get a read event from Stack
OS_Error_t
network_stack_pico_socket_read(
    const int     handle,
    size_t* const pLen)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    OS_Error_t retval = OS_SUCCESS;
    int tot_len = 0;
    size_t len = *pLen; /* App requested length */

    uint8_t* buf = OS_Dataport_getBuf(socket->buf);

    CHECK_DATAPORT_SIZE(socket->buf, len);

    internal_notify_main_loop();

    do
    {
        internal_network_stack_thread_safety_mutex_lock();
        int ret = pico_socket_read(pico_socket, buf + tot_len, len - tot_len);
        OS_Error_t err =  pico_err2os(pico_err);
        socket->current_error = err;
        internal_network_stack_thread_safety_mutex_unlock();

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

            retval = err;
            break;
        }

        if ((0 == ret) && (len > 0))
        {
            /* wait for a new RD event -- also wait possibly for a CLOSE event */
            internal_wait_read(handle);
            if (socket->event  & PICO_SOCK_EV_CLOSE)
            {
                /* closing of socket must be done by the app after return */
                socket->event  = 0;
                Debug_LOG_INFO("[socket %d/%p] read() unblocked due to connection closed",
                               handle, pico_socket);
                retval = OS_ERROR_NETWORK_CONN_SHUTDOWN; /* return 0 on a properly closed socket */
                break;
            }
        }

        tot_len += (unsigned)ret;
    }
    while (0 == tot_len);

#if (Debug_Config_LOG_LEVEL >= Debug_LOG_LEVEL_TRACE)

    Debug_LOG_TRACE("[socket %d/%p] read data length=%d, data follows below",
                    handle, pico_socket, tot_len);

    Debug_hexDump(
        Debug_LOG_LEVEL_TRACE,
        "",
        OS_Dataport_getBuf(*app_port),
        tot_len);
#endif

    *pLen = tot_len;

    return retval;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_sendto(
    const int                            handle,
    size_t* const                        pLen,
    const OS_NetworkSocket_Addr_t* const dstAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

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
    OS_Error_t err =  pico_err2os(pico_err);
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

    socket->event = 0;
    *pLen       = ret;

    internal_notify_main_loop();

    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
// Is a blocking call. Wait until we get a read event from Stack
OS_Error_t
network_stack_pico_socket_recvfrom(
    const int                      handle,
    size_t* const                  pLen,
    OS_NetworkSocket_Addr_t* const srcAddr)
{
    OS_NetworkStack_SocketResources_t* socket = get_socket_from_handle(handle);

    struct pico_socket* pico_socket = socket->implementation_socket;

    CHECK_SOCKET(pico_socket, handle);

    OS_Error_t retval = OS_SUCCESS;
    size_t     len    = *pLen;

    uint8_t* buf = OS_Dataport_getBuf(socket->buf);

    CHECK_DATAPORT_SIZE(socket->buf, len);

    struct pico_ip4 src = {};
    uint16_t        sport;

    int ret;

    internal_notify_main_loop();

    // pico_socket_recvfrom will from time to time return 0 bytes read,
    // even though there is a valid datagram to return. Although 0 payload is a
    // valid UDP packet, it looks like picotcp treats it as a try-again
    // condition (see example apps). So we wait/loop here until we get
    // something to return.
    do
    {
        internal_wait_read(handle);

        internal_network_stack_thread_safety_mutex_lock();
        ret = pico_socket_recvfrom(pico_socket, buf, len, &src, &sport);
        OS_Error_t err =  pico_err2os(pico_err);
        socket->current_error = err;
        internal_network_stack_thread_safety_mutex_unlock();

        if (ret < 0)
        {
            Debug_LOG_ERROR(
                "[socket %d/%p] nw_socket_read() failed with error %d, "
                "translating to OS error %d (%s)", handle, pico_socket, ret, err,
                Debug_OS_Error_toString(err));

            return err;
        }
        // If srcAddr is NULL it means the user doesn't want the
        // sender's information.
        if (NULL != srcAddr)
        {
            pico_ipv4_to_string((char*)srcAddr->addr, src.addr);

            srcAddr->port = short_be(sport);
        }
    }
    while (ret == 0);

#if (Debug_Config_LOG_LEVEL >= Debug_LOG_LEVEL_TRACE)

    Debug_LOG_TRACE(
        "[socket %d/%p] read data length=%d, data follows below",
        handle,
        socket,
        len);

    Debug_hexDump(
        Debug_LOG_LEVEL_TRACE,
        "",
        OS_Dataport_getBuf(*app_port),
        len);
#endif

    *pLen = ret;

    return retval;
}
