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
#include "network_config.h"
#include "network_stack_core.h"
#include "network_stack_pico_nic.h"
#include "pico_device.h"
#include "pico_icmp4.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_stack.h"

#include "lib_debug/Debug.h"

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
    unsigned int domain)
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
    unsigned int socket_type)
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
    struct pico_socket*  s,
    int                  option,
    int                  value)
{
    return pico_socket_setoption(s, option, &value);
}


//------------------------------------------------------------------------------
static void
handle_incoming_connection(
    struct pico_socket*  socket)
{
    uint16_t port = 0;
    struct pico_ip4 orig = {0};
    internal_network_stack_thread_safety_mutex_lock();
    struct pico_socket* s_in = pico_socket_accept(socket, &orig, &port);
    internal_network_stack_thread_safety_mutex_unlock();
    if (NULL == s_in)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %p] nw_socket_accept() failed, pico_err = %d (%s)",
                        socket, cur_pico_err, pico_err2str(cur_pico_err));
        return;
    }

    char peer[30] = {0};
    pico_ipv4_to_string(peer, orig.addr);

    // ToDo: port might be in big endian here, in this case we should
    //       better use short_be(port)

    Debug_LOG_INFO("[socket %p] connection from %s:%d established using socket %p",
                   socket, peer, port, s_in);

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

    int accepted_handle = reserve_handle(s_in);
    set_accepted_handle(get_handle_from_implementation_socket(socket),
                        accepted_handle);
}

//------------------------------------------------------------------------------
// This is called from the PicoTCP main tick loop to report socket events
static void
handle_pico_socket_event(
    uint16_t             event_mask,
    struct pico_socket*  socket)
{
    Debug_LOG_DEBUG("Event for handle %d/%p Value: 0x%x State %x",
                    get_handle_from_implementation_socket(socket), socket,
                    event_mask, TCPSTATE(socket));
    // remember the last event
    int handle = get_handle_from_implementation_socket(socket);
    if (handle == -1)
    {
        return;
    }
    OS_NetworkStack_SocketResources_t* sock = get_socket_from_handle(handle);
    sock->event = event_mask;


    if (event_mask & PICO_SOCK_EV_CONN)
    {
        Debug_LOG_DEBUG("[socket %p] PICO_SOCK_EV_CONN", socket);

        if (socket->state & PICO_SOCKET_STATE_TCP_LISTEN)
        {
            // SYN has arrived
            handle_incoming_connection(socket);
            sock->event = event_mask; // no event is pending
        }
        else
        {
            // SYN-ACK has arrived
            Debug_LOG_INFO(
                "[socket %p] incoming connection established",
                socket);
        }
        internal_notify_connection(handle);
    }

    if (event_mask & PICO_SOCK_EV_RD)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_RD", socket);
        internal_notify_read(handle);
    }

    if (event_mask & PICO_SOCK_EV_WR)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_WR", socket);
        // notify app, which is waiting to write
        internal_notify_write(handle);
        // notify network stack loop about an event
        internal_notify_main_loop();
    }

    if (event_mask & PICO_SOCK_EV_CLOSE)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_CLOSE", socket);
        internal_notify_read(handle);
    }

    if (event_mask & PICO_SOCK_EV_FIN)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_FIN", socket);
        internal_notify_read(handle);
    }

    if (event_mask & PICO_SOCK_EV_ERR)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %p] PICO_SOCK_EV_ERR, pico_err = %d (%s)",
                        socket, cur_pico_err, pico_err2str(cur_pico_err));
        internal_notify_connection(handle);
        internal_notify_read(handle);
    }
}

OS_Error_t
network_stack_pico_socket_create(
    int   domain,
    int   socket_type,
    int*  pHandle)
{
    int pico_domain = translate_socket_domain(domain);
    if (pico_domain < 0)
    {
        Debug_LOG_ERROR("unsupported domain %d", domain);
        return OS_ERROR_GENERIC;
    }

    int pico_type = translate_socket_type(socket_type);
    if (pico_type < 0)
    {
        Debug_LOG_ERROR("unsupported type %d", socket_type);
        return OS_ERROR_GENERIC;
    }
    internal_network_stack_thread_safety_mutex_lock();
    struct pico_socket* socket = pico_socket_open(pico_domain,
                                                  pico_type,
                                                  &handle_pico_socket_event);
    internal_network_stack_thread_safety_mutex_unlock();
    if (NULL == socket)
    {
        // try to detailed error from PicoTCP. Actually, nw_socket_open()
        // should return a proper error code and populate a handle passed as
        // pointer parameter, so we don't need to access pico_err here.
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("socket opening failed, pico_err = %d (%s)",
                        cur_pico_err, pico_err2str(cur_pico_err));
        return OS_ERROR_GENERIC;
    }

    if (socket_type == OS_SOCK_STREAM) // TCP socket
    {
        // disable nagle algorithm (1=disable, 0=enable)
        helper_socket_set_option_int(socket, PICO_TCP_NODELAY, 1);
    }

    *pHandle = reserve_handle(socket);

    if (*pHandle == -1)
    {
        internal_network_stack_thread_safety_mutex_lock();
        pico_socket_close(socket);
        internal_network_stack_thread_safety_mutex_unlock();
        Debug_LOG_ERROR("No free socket could be found");
        return OS_ERROR_GENERIC;
    }

    Debug_LOG_INFO("[socket %d/%p] created new socket", *pHandle, socket);

    return OS_SUCCESS;
}

OS_Error_t
network_stack_pico_socket_close(
    int handle)
{
    struct pico_socket* socket = get_implementation_socket_from_handle(handle);
    if (socket == NULL)
    {
        Debug_LOG_ERROR("[socket %d] close() with invalid handle", handle);
        return OS_ERROR_INVALID_HANDLE;
    }
    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_close(socket);
    internal_network_stack_thread_safety_mutex_unlock();
    if (ret < 0)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_close() failed with error %d, pico_err %d (%s)",
                        handle, socket, ret,
                        cur_pico_err, pico_err2str(cur_pico_err));
        free_handle(handle);
        return OS_ERROR_GENERIC;
    }
    free_handle(handle);
    Debug_LOG_INFO("[socket %d/%p] close() handle", handle, socket);
    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_connect(
    int          handle,
    const char*  name,
    int          port)
{

    struct pico_socket* socket = get_implementation_socket_from_handle(handle);
    if (socket == NULL)
    {
        Debug_LOG_ERROR("[socket %d] connect() with invalid handle", handle);
        return OS_ERROR_INVALID_HANDLE;
    }

    Debug_LOG_DEBUG("[socket %d/%p] open connection to %s:%d ...",
                    handle, socket, name, port);

    struct pico_ip4 dst;
    pico_string_to_ipv4(name, &dst.addr);
    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_connect(socket, &dst, short_be(port));
    internal_network_stack_thread_safety_mutex_unlock();
    if (ret < 0)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_connect() failed with error %d, pico_err %d (%s)",
                        handle, socket, ret,
                        cur_pico_err, pico_err2str(cur_pico_err));
        return OS_ERROR_GENERIC;
    }

    Debug_LOG_DEBUG("[socket %d/%p] connect waiting ...", handle, socket);
    internal_wait_connection(handle);

    if ((socket->state & PICO_SOCKET_STATE_CONNECTED) == 0)
    {
        Debug_LOG_ERROR("[socket %d/%p] could not connect socket",
                        handle, socket);
        return OS_ERROR_GENERIC;
    }

    Debug_LOG_INFO("[socket %d/%p] connection established to %s:%d",
                   handle, socket, name, port);

    return OS_SUCCESS;

}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_bind(
    int handle,
    uint16_t port)
{
    struct pico_socket* socket = get_implementation_socket_from_handle(handle);
    if (socket == NULL)
    {
        Debug_LOG_ERROR("[socket %d] bind() with invalid handle", handle);
        return OS_ERROR_INVALID_HANDLE;
    }

    Debug_LOG_INFO("[socket %d/%p] binding to port %d", handle, socket, port);

    struct pico_ip4 ZERO_IP4 = { 0 };
    uint16_t be_port = short_be(port);
    internal_network_stack_thread_safety_mutex_lock();
    int ret = pico_socket_bind(socket, &ZERO_IP4, &be_port);
    internal_network_stack_thread_safety_mutex_unlock();
    if (ret < 0)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_bind() failed with error %d, pico_err %d (%s)",
                        handle, socket, ret,
                        cur_pico_err, pico_err2str(cur_pico_err));
        return OS_ERROR_GENERIC;
    }

    return OS_SUCCESS;

}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_listen(
    int handle,
    int backlog)
{

    struct pico_socket* socket = get_implementation_socket_from_handle(handle);
    if (socket == NULL)
    {
        Debug_LOG_ERROR("[socket %d] listen() with invalid handle", handle);
        return OS_ERROR_INVALID_HANDLE;
    }

    // currently we support just one incoming connection, so everything is hard
    // coded
    int handle_socket_server = 0;
    if (handle_socket_server != handle)
    {
        Debug_LOG_ERROR("[socket %d/%p] only socket handle %d is currently allowed",
                        handle, socket, handle_socket_server);
        return OS_ERROR_INVALID_HANDLE;
    }
    int ret = pico_socket_listen(socket, backlog);
    if (ret < 0)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_listen() failed with error %d, pico_err %d (%s)",
                        handle, socket, ret,
                        cur_pico_err, pico_err2str(cur_pico_err));
        return OS_ERROR_GENERIC;
    }

    return OS_SUCCESS;

}

//------------------------------------------------------------------------------
// For server wait on accept until client connects. Not much useful for client
// as we cannot accept incoming connections
OS_Error_t
network_stack_pico_socket_accept(
    int handle,
    int* pClient_handle,
    uint16_t port)
{
    // set default
    *pClient_handle = -1;

    struct pico_socket* socket = get_implementation_socket_from_handle(handle);
    if (socket == NULL)
    {
        Debug_LOG_ERROR("[socket %d] accept() with invalid handle", handle);
        return OS_ERROR_INVALID_HANDLE;
    }

    Debug_LOG_DEBUG("[socket %d/%p] accept waiting ...", handle, socket);
    internal_wait_connection(handle);

    *pClient_handle = get_accepted_handle(handle);
    Debug_LOG_INFO("Accepted [socket %d/%p]",
                   get_accepted_handle(handle),
                   get_implementation_socket_from_handle(get_accepted_handle(handle)));

    struct pico_socket* client_socket = get_implementation_socket_from_handle(
                                            *pClient_handle);

    if (client_socket == NULL )
    {
        Debug_LOG_ERROR("[socket %d/%p] no client to accept", handle, socket);
        return OS_ERROR_GENERIC;
    }

    Debug_LOG_DEBUG("[socket %d/%p] incoming connection socket %d/%p",
                    handle, socket, *pClient_handle, client_socket);

    return OS_SUCCESS;

}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_write(
    int handle,
    size_t* pLen)
{
    struct pico_socket* socket = get_implementation_socket_from_handle(handle);
    if (NULL == socket)
    {
        Debug_LOG_ERROR("[socket %d] write() with invalid handle", handle);
        *pLen = 0;
        return OS_ERROR_INVALID_HANDLE;
    }

    const OS_Dataport_t*    app_port    = get_app_port(handle);
    size_t                  len         = *pLen;
    size_t                  dpSize      = OS_Dataport_getSize(*app_port);

    if (len > dpSize)
    {
        Debug_LOG_ERROR("Buffer size %zu exceeds dataport size %zu",
                        len, dpSize);
        return OS_ERROR_INVALID_PARAMETER;
    }

    internal_wait_write(handle);

    int ret = pico_socket_write(socket, OS_Dataport_getBuf(*app_port), len);
    OS_NetworkStack_SocketResources_t* sock = get_socket_from_handle(handle);
    sock->event = 0;

    if (ret < 0)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_write() failed with error %d, pico_err %d (%s)",
                        handle, socket, ret,
                        cur_pico_err, pico_err2str(cur_pico_err));
        *pLen = 0;
        return OS_ERROR_GENERIC;
    }

    *pLen = ret;
    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
// Is a blocking call. Wait until we get a read event from Stack
OS_Error_t
network_stack_pico_socket_read(
    int handle,
    size_t* pLen)
{
    struct pico_socket* socket = get_implementation_socket_from_handle(handle);
    if (NULL == socket)
    {
        Debug_LOG_ERROR("[socket %d] read() with invalid handle", handle);
        *pLen = 0;
        return OS_ERROR_INVALID_HANDLE;
    }

    OS_Error_t retval = OS_SUCCESS;
    int tot_len = 0;
    size_t len = *pLen; /* App requested length */

    const OS_Dataport_t*    app_port    = get_app_port(handle);
    uint8_t*                buf         = OS_Dataport_getBuf(*app_port);
    size_t                  dpSize      = OS_Dataport_getSize(*app_port);

    if (len > dpSize)
    {
        Debug_LOG_ERROR("Buffer size %zu exceeds dataport size %zu",
                        len, dpSize);
        return OS_ERROR_INVALID_PARAMETER;
    }

    do
    {
        int ret = pico_socket_read(socket, buf + tot_len, len - tot_len);
        if (ret < 0)
        {
            pico_err_t cur_pico_err = pico_err;
            if (cur_pico_err == PICO_ERR_ESHUTDOWN)
            {
                Debug_LOG_INFO("[socket %d/%p] read() found connection closed",
                               handle, socket);
                retval = OS_ERROR_CONNECTION_CLOSED;
                break;
            }

            Debug_LOG_ERROR("[socket %d/%p] nw_socket_read() failed with error %d, pico_err %d (%s)",
                            handle, socket, ret,
                            cur_pico_err, pico_err2str(cur_pico_err));

            retval =  OS_ERROR_GENERIC;
            break;
        }

        if ((0 == ret) && (len > 0))
        {

            OS_NetworkStack_SocketResources_t* sock = get_socket_from_handle(handle);

            /* wait for a new RD event -- also wait possibly for a CLOSE event */
            internal_wait_read(handle);
            if (sock->event  & PICO_SOCK_EV_CLOSE)
            {
                /* closing of socket must be done by the app after return */
                sock->event  = 0;
                Debug_LOG_INFO("[socket %d/%p] read() unblocked due to connection closed",
                               handle, socket);
                retval = OS_ERROR_CONNECTION_CLOSED; /* return 0 on a properly closed socket */
                break;
            }
        }

        tot_len += (unsigned)ret;

    }
    while (0 == tot_len);

#if (Debug_Config_LOG_LEVEL >= Debug_LOG_LEVEL_TRACE)

    Debug_LOG_TRACE("[socket %d/%p] read data length=%d, data follows below",
                    handle, socket, tot_len);

    Debug_hexDump(TRACE, OS_Dataport_getBuf(*app_port), tot_len);
#endif

    *pLen = tot_len;
    return retval;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_pico_socket_sendto(
    int                 handle,
    size_t*             pLen,
    OS_Network_Socket_t dst_socket)
{
    struct pico_socket* socket = get_implementation_socket_from_handle(handle);
    if (NULL == socket)
    {
        Debug_LOG_ERROR("[socket %d] sendto() with invalid handle", handle);
        *pLen = 0;
        return OS_ERROR_INVALID_HANDLE;
    }
    const OS_Dataport_t*    app_port    = get_app_port(handle);
    size_t                  len         = *pLen;
    size_t                  dpSize      = OS_Dataport_getSize(*app_port);

    if (len > dpSize)
    {
        Debug_LOG_ERROR("Buffer size %zu exceeds dataport size %zu",
                        len, dpSize);
        return OS_ERROR_INVALID_PARAMETER;
    }

    struct pico_ip4 dst = {};
    uint16_t        dport;
    pico_string_to_ipv4(dst_socket.name, &dst.addr);
    dport = short_be(dst_socket.port);

    int ret = pico_socket_sendto(socket, OS_Dataport_getBuf(*app_port), len, &dst,
                                 dport);

    OS_NetworkStack_SocketResources_t* sock = get_socket_from_handle(handle);
    sock->event = 0;

    if (ret < 0)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR(
            "[socket %d/%p] nw_socket_sendto() failed with error %d, "
            "pico_err %d (%s)",
            handle,
            socket,
            ret,
            cur_pico_err,
            pico_err2str(cur_pico_err));
        *pLen = 0;
        return OS_ERROR_GENERIC;
    }

    *pLen = ret;
    return OS_SUCCESS;
}

//------------------------------------------------------------------------------
// Is a blocking call. Wait until we get a read event from Stack
OS_Error_t
network_stack_pico_socket_recvfrom(
    int                  handle,
    size_t*              pLen,
    OS_Network_Socket_t* source_socket)
{
    struct pico_socket* socket = get_implementation_socket_from_handle(handle);
    if (NULL == socket)
    {
        Debug_LOG_ERROR("[socket %d] read() with invalid handle", handle);
        *pLen = 0;
        return OS_ERROR_INVALID_HANDLE;
    }

    OS_Error_t retval = OS_SUCCESS;
    size_t     len    = *pLen;

    const OS_Dataport_t*    app_port   = get_app_port(handle);
    uint8_t*                buf        = OS_Dataport_getBuf(*app_port);;
    size_t                  dpSize     = OS_Dataport_getSize(*app_port);

    struct pico_ip4 src = {};
    uint16_t        sport;

    int ret;

    if (len > dpSize)
    {
        Debug_LOG_ERROR("Buffer size %zu exceeds dataport size %zu",
                        len, dpSize);
        return OS_ERROR_INVALID_PARAMETER;
    }
    // pico_socket_recvfrom will from time to time return 0 bytes read,
    // even though there is a valid datagram to return. Although 0 payload is a
    // valid UDP packet, it looks like picotcp treats it as a try-again
    // condition (see example apps). So we wait/loop here until we get
    // something to return.
    do
    {
        internal_wait_read(handle);

        ret = pico_socket_recvfrom(socket, buf, len, &src, &sport);

        if (ret < 0)
        {
            pico_err_t cur_pico_err = pico_err;

            Debug_LOG_ERROR(
                "[socket %d/%p] nw_socket_read() failed with error %d, "
                "pico_err %d (%s)", handle, socket, ret, cur_pico_err,
                pico_err2str(cur_pico_err));

            return OS_ERROR_GENERIC;
        }

        pico_ipv4_to_string(source_socket->name, src.addr);

        source_socket->port = short_be(sport);
    }
    while (ret == 0);

#if (Debug_Config_LOG_LEVEL >= Debug_LOG_LEVEL_TRACE)

    Debug_LOG_TRACE(
        "[socket %d/%p] read data length=%d, data follows below",
        handle, socket, tot_len);

    Debug_hexDump(TRACE, OS_Dataport_getBuf(*app_port), tot_len);
#endif

    *pLen = ret;
    return retval;
}
