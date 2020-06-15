/*
 *  OS Network Stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "LibDebug/Debug.h"
#include "OS_Network.h"
#include "os_util/OS_NetworkStack.h"
#include "OS_NetworkStackConf.h"
#include "network_config.h"
#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_socket.h"
#include "pico_device.h"
#include <stdlib.h>
#include <stdint.h>

// all PICO_PROTO_xxx are positive values, so we can use this as marker
#define INVALID_SOCKET_TYPE_OR_DOMAIN   (-1)

typedef struct
{
    const os_camkes_network_stack_config_t*   camkes_cfg;
    const os_network_stack_config_t*          cfg;

    struct pico_device          seos_nic;

    struct pico_socket* socket[2];

    int
    event; /**< Pico Internal event representing current state of connected socket */
    int                         read; /**< Has read len */
} network_stack_t;


// network stack state
static network_stack_t  instance = {0};

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


//------------------------------------------------------------------------------
const os_camkes_network_stack_config_t*
config_get_handlers(void)
{
    const os_camkes_network_stack_config_t* handlers = instance.camkes_cfg;

    Debug_ASSERT( NULL != handlers );

    return handlers;
}


//------------------------------------------------------------------------------
// get socket from a given handle
static struct pico_socket*
get_pico_socket_from_handle(
    int handle)
{

    return (0 == handle) ? instance.socket[0]
           : (1 == handle) ? instance.socket[1]
           : NULL;

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
    return INVALID_SOCKET_TYPE_OR_DOMAIN;
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
    return INVALID_SOCKET_TYPE_OR_DOMAIN;
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
#if defined(OS_NWSTACK_AS_SERVER)
static void
handle_incoming_connection(
    struct pico_socket*  socket)
{
    // Currently, we only support exactly one incoming connection, thus
    // everything is hard-coded here. Also, there is a quick hack here to
    // forget the existing connection of a new one comes in - this is good
    // enough for now, but need to be implemented properly eventually.
    const int handle_socket_server = 0;
    const int handle_socket_client = 1;

    Debug_ASSERT( socket == instance.socket[handle_socket_server] );

    instance.socket[handle_socket_client] = NULL;

    uint16_t port = 0;
    struct pico_ip4 orig = {0};
    struct pico_socket* s_in = pico_socket_accept(socket, &orig, &port);
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

    instance.socket[handle_socket_client] = s_in;
}
#endif // defined(OS_NWSTACK_AS_SERVER)


//------------------------------------------------------------------------------
// This is called from the PicoTCP main tick loop to report socket events
static void
handle_pico_socket_event(
    uint16_t             event_mask,
    struct pico_socket*  socket)
{
    // remember the last event
    instance.event = event_mask;

    if (event_mask & PICO_SOCK_EV_CONN)
    {
        Debug_LOG_INFO("[socket %p] PICO_SOCK_EV_CONN", socket);

#if defined(OS_NWSTACK_AS_CLIENT)

        // SYN-ACK has arrived
        Debug_LOG_INFO("[socket %p] incoming connection established", socket);

#elif defined(OS_NWSTACK_AS_SERVER)

        // SYN has arrived
        handle_incoming_connection(socket);
        instance.event = 0; // no event is pending

#else
#error "Error: Configure as client or server!!"
#endif

        internal_notify_connection();
    }

    if (event_mask & PICO_SOCK_EV_RD)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_RD", socket);
        internal_notify_read();
    }

    if (event_mask & PICO_SOCK_EV_WR)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_WR", socket);
        // notify app, which is waiting to write
        internal_notify_write();
        // notify network stack loop about an event
        internal_notify_main_loop();
    }

    if (event_mask & PICO_SOCK_EV_CLOSE)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_CLOSE", socket);
        internal_notify_read();
    }

    if (event_mask & PICO_SOCK_EV_FIN)
    {
        Debug_LOG_TRACE("[socket %p] PICO_SOCK_EV_FIN", socket);
        internal_notify_read();
    }

    if (event_mask & PICO_SOCK_EV_ERR)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %p] PICO_SOCK_EV_ERR, pico_err = %d (%s)",
                        socket, cur_pico_err, pico_err2str(cur_pico_err));
        internal_notify_read();
    }
}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_create(
    int   domain,
    int   socket_type,
    int*  pHandle)
{
    int pico_domain = translate_socket_domain(domain);
    if (INVALID_SOCKET_TYPE_OR_DOMAIN == pico_domain)
    {
        Debug_LOG_ERROR("unsupported domain %d", domain);
        return OS_ERROR_GENERIC;
    }

    int pico_type = translate_socket_type(socket_type);
    if (INVALID_SOCKET_TYPE_OR_DOMAIN == pico_type)
    {
        Debug_LOG_ERROR("unsupported type %d", socket_type);
        return OS_ERROR_GENERIC;
    }

    struct pico_socket* socket = pico_socket_open(pico_domain,
                                                  pico_type,
                                                  &handle_pico_socket_event);
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

    int handle = 0; // we support just one socket at the moment
    Debug_LOG_INFO("[socket %d/%p] created new socket", handle, socket);

    instance.socket[handle] = socket;
    *pHandle = handle;

    return OS_SUCCESS;
}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_close(
    int handle)
{
    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (socket == NULL)
    {
        Debug_LOG_ERROR("[socket %d] close() with invalid handle", handle);
        return OS_ERROR_INVALID_HANDLE;
    }

    int ret = pico_socket_close(socket);
    if (ret < 0)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_close() failed with error %d, pico_err %d (%s)",
                        handle, socket, ret,
                        cur_pico_err, pico_err2str(cur_pico_err));
        return OS_ERROR_GENERIC;
    }

    return OS_SUCCESS;
}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_connect(
    int          handle,
    const char*  name,
    int          port)
{

#if defined(OS_NWSTACK_AS_SERVER)

    Debug_LOG_ERROR("[socket %d] connect() not supported in server-only mode",
                    handle);
    return OS_ERROR_NOT_SUPPORTED;

#else // not OS_NWSTACK_AS_SERVER

    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (socket == NULL)
    {
        Debug_LOG_ERROR("[socket %d] connect() with invalid handle", handle);
        return OS_ERROR_INVALID_HANDLE;
    }

    Debug_LOG_DEBUG("[socket %d/%p] open connection to %s:%d ...",
                    handle, socket, name, port);

    struct pico_ip4 dst;
    pico_string_to_ipv4(name, &dst.addr);
    int ret = pico_socket_connect(socket, &dst, short_be(port));
    if (ret < 0)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("[socket %d/%p] nw_socket_connect() failed with error %d, pico_err %d (%s)",
                        handle, socket, ret,
                        cur_pico_err, pico_err2str(cur_pico_err));
        return OS_ERROR_GENERIC;
    }

    Debug_LOG_DEBUG("[socket %d/%p] connect waiting ...", handle, socket);
    internal_wait_connection();

    Debug_LOG_INFO("[socket %d/%p] connection esablished to %s:%d",
                   handle, socket, name, port);

    return OS_SUCCESS;

#endif // [not] OS_NWSTACK_AS_SERVER

}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_bind(
    int handle,
    uint16_t port)
{
    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (socket == NULL)
    {
        Debug_LOG_ERROR("[socket %d] bind() with invalid handle", handle);
        return OS_ERROR_INVALID_HANDLE;
    }

    Debug_LOG_INFO("[socket %d/%p] binding to port %d", handle, socket, port);

    struct pico_ip4 ZERO_IP4 = { 0 };
    uint16_t be_port = short_be(port);
    int ret = pico_socket_bind(socket, &ZERO_IP4, &be_port);
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
network_stack_rpc_socket_listen(
    int handle,
    int backlog)
{
#if defined(OS_NWSTACK_AS_CLIENT)

    Debug_LOG_ERROR("[socket %d] listen() not supported in client-only mode",
                    handle);
    return OS_ERROR_NOT_SUPPORTED;

#else // not OS_NWSTACK_AS_CLIENT

    struct pico_socket* socket = get_pico_socket_from_handle(handle);
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

#endif // [not] OS_NWSTACK_AS_CLIENT

}


//------------------------------------------------------------------------------
// For server wait on accept until client connects. Not much useful for client
// as we cannot accept incoming connections
OS_Error_t
network_stack_rpc_socket_accept(
    int handle,
    int* pClient_handle,
    uint16_t port)
{
    // set default
    *pClient_handle = 0;

#if defined(OS_NWSTACK_AS_CLIENT)

    Debug_LOG_ERROR("[socket %d] accept() not supported in client-only mode",
                    handle);
    return OS_ERROR_NOT_SUPPORTED;

#else // not OS_NWSTACK_AS_CLIENT

    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (socket == NULL)
    {
        Debug_LOG_ERROR("[socket %d] accept() with invalid handle", handle);
        return OS_ERROR_INVALID_HANDLE;
    }

    // currently we support just one incoming connection, so everything is hard
    // coded
    int handle_socket_server = 0;
    int handle_socket_client = 1;

    if (handle_socket_server != handle)
    {
        Debug_LOG_ERROR("[socket %d/%p] only socket handle %d is currently allowed",
                        handle, socket, handle_socket_server);
        return OS_ERROR_INVALID_HANDLE;
    }

    Debug_LOG_DEBUG("[socket %d/%p] accept waiting ...", handle, socket);
    internal_wait_connection();

    // ToDO: the static code analyser raises a warning here if we build the
    //       network stack with
    struct pico_socket* client_socket = instance.socket[handle_socket_client];
    if (client_socket == NULL )
    {
        Debug_LOG_ERROR("[socket %d/%p] no client to accept", handle, socket);
        return OS_ERROR_GENERIC;
    }

    Debug_LOG_DEBUG("[socket %d/%p] incoming connection socket %d/%p",
                    handle, socket, handle_socket_client, client_socket);

    *pClient_handle = handle_socket_client;
    return OS_SUCCESS;

#endif // [not] OS_NWSTACK_AS_CLIENT

}


//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_write(
    int handle,
    size_t* pLen)
{
    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (NULL == socket)
    {
        Debug_LOG_ERROR("[socket %d] write() with invalid handle", handle);
        *pLen = 0;
        return OS_ERROR_INVALID_HANDLE;
    }

    internal_wait_write();

    const OS_SharedBuffer_t* app_port = get_app_port();

    int ret = pico_socket_write(socket, app_port->buffer, *pLen);
    instance.event = 0;

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
network_stack_rpc_socket_read(
    int handle,
    size_t* pLen)
{
    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (NULL == socket)
    {
        Debug_LOG_ERROR("[socket %d] read() with invalid handle", handle);
        *pLen = 0;
        return OS_ERROR_INVALID_HANDLE;
    }

    OS_Error_t retval = OS_SUCCESS;
    int tot_len = 0;
    size_t len = *pLen; /* App requested length */

    const OS_SharedBuffer_t* app_port = get_app_port();
    uint8_t* buf = app_port->buffer;

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
            /* wait for a new RD event -- also wait possibly for a CLOSE event */
            internal_wait_read();
            if (instance.event & PICO_SOCK_EV_CLOSE)
            {
                /* closing of socket must be done by the app after return */
                instance.event = 0;
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

    Debug_hexDump(TRACE, app_port->buffer, tot_len);
#endif

    *pLen = tot_len;
    return retval;
}

//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_sendto(
    int                 handle,
    size_t*             pLen,
    OS_Network_Socket_t dst_socket)
{
    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (NULL == socket)
    {
        Debug_LOG_ERROR("[socket %d] sendto() with invalid handle", handle);
        *pLen = 0;
        return OS_ERROR_INVALID_HANDLE;
    }
    const OS_SharedBuffer_t* app_port = get_app_port();

    struct pico_ip4 dst = {};
    uint16_t        dport;
    pico_string_to_ipv4(dst_socket.name, &dst.addr);
    dport = short_be(dst_socket.port);

    int ret = pico_socket_sendto(socket, app_port->buffer, *pLen, &dst, dport);
    instance.event = 0;

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
network_stack_rpc_socket_recvfrom(
    int                  handle,
    size_t*              pLen,
    OS_Network_Socket_t* source_socket)
{
    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (NULL == socket)
    {
        Debug_LOG_ERROR("[socket %d] read() with invalid handle", handle);
        *pLen = 0;
        return OS_ERROR_INVALID_HANDLE;
    }

    OS_Error_t retval = OS_SUCCESS;
    size_t     len    = *pLen;

    const OS_SharedBuffer_t* app_port = get_app_port();
    uint8_t*                 buf      = app_port->buffer;

    struct pico_ip4 src = {};
    uint16_t        sport;

    int ret;

    // pico_socket_recvfrom will from time to time return 0 bytes read,
    // even though there is a valid datagram to return. Although 0 payload is a
    // valid UDP packet, it looks like picotcp treats it as a try-again
    // condition (see example apps). So we wait/loop here until we get
    // something to return.
    do
    {
        internal_wait_read();

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

    Debug_hexDump(TRACE, app_port->buffer, tot_len);
#endif

    *pLen = ret;
    return retval;
}

//------------------------------------------------------------------------------
// NIC Driver interface
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Called by PicoTCP to send one frame
static int
nic_send_frame(
    struct pico_device*  dev,
    void*                buf,
    int                  len)
{
    // currently we support only one NIC
    Debug_ASSERT( &(instance.seos_nic) == dev );

    const OS_SharedBuffer_t* nic_in = get_nic_port_to();
    void* wrbuf = nic_in->buffer;

    // copy data it into shared buffer
    size_t wr_len = len;
    memcpy(wrbuf, buf, wr_len);
    // call driver
    OS_Error_t err = nic_rpc_dev_write(&wr_len);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("nic_rpc_dev_write() failed, error %d", err);
        return -1;
    }

    Debug_ASSERT( wr_len == len );

    return len;
}


//------------------------------------------------------------------------------
// Called after notification from driver and regularly from PicoTCP stack tick
static int
nic_poll_data(
    struct pico_device*  dev,
    int                  loop_score)
{
    // currently we support only one NIC
    Debug_ASSERT( &(instance.seos_nic) == dev );

    // loop_score indicates max number of frames that can be processed during
    // the invocation of this poll. Since we still lack the concept of frames
    // in the shared memory, we can't do much here. Pretend there is one
    // frame in the buffer and give it to PicoTCP
    if (loop_score > 0)
    {
        const OS_SharedBuffer_t* nw_in = get_nic_port_from();
        OS_NetworkStack_RxBuffer_t* nw_rx = (OS_NetworkStack_RxBuffer_t*)nw_in->buffer;

        size_t len = nw_rx->len;
        if (len > 0)
        {
            Debug_LOG_DEBUG("incoming frame len %zu", len);
            loop_score--;
            pico_stack_recv(dev, nw_rx->data, (uint32_t)len);

            // set flag in shared memory that data has been read
            nw_rx->len = 0;
        }
    }
    return loop_score;
}


//------------------------------------------------------------------------------
static void
nic_destroy(
    struct pico_device* dev)
{
    // currently we support only one NIC
    Debug_ASSERT( &(instance.seos_nic) == dev );

    memset(dev, 0, sizeof(*dev));
}


//------------------------------------------------------------------------------
static OS_Error_t
initialize_nic(void)
{
    // currently we support only one NIC
    struct pico_device* dev = &instance.seos_nic;

    memset(dev, 0, sizeof(*dev));

    dev->send    = nic_send_frame;
    dev->poll    = nic_poll_data;
    dev->destroy = nic_destroy;

    //---------------------------------------------------------------
    // get MAC from NIC driver
    OS_Error_t err = nic_rpc_get_mac();
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("nic_rpc_get_mac() failed, error %d", err);
        nic_destroy(dev);
        return OS_ERROR_GENERIC;
    }

    const OS_SharedBuffer_t* nw_in = get_nic_port_from();
    OS_NetworkStack_RxBuffer_t* nw_rx = (OS_NetworkStack_RxBuffer_t*)nw_in->buffer;
    uint8_t* mac = nw_rx->data;

    Debug_LOG_INFO("MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );

    static const char* drv_name  = "tapdriver";
    int ret = pico_device_init(dev, drv_name, mac);
    if (ret != 0)
    {
        Debug_LOG_ERROR("pico_device_init() failed, error %d", ret);
        nic_destroy(dev);
        return OS_ERROR_GENERIC;
    }

    Debug_LOG_INFO("PicoTCP Device created: %s", drv_name);

    //---------------------------------------------------------------
    // assign IPv4 configuration

    struct pico_ip4 ipaddr;
    pico_string_to_ipv4(instance.cfg->dev_addr, &ipaddr.addr);

    struct pico_ip4 netmask;
    pico_string_to_ipv4(instance.cfg->subnet_mask, &netmask.addr);

    // assign IP address and netmask
    pico_ipv4_link_add(dev, ipaddr, netmask);


    struct pico_ip4 gateway;
    pico_string_to_ipv4(instance.cfg->gateway_addr, &gateway.addr);

    // add default route via gateway
    const struct pico_ip4 ZERO_IP4 = { 0 };
    (void)pico_ipv4_route_add(ZERO_IP4, ZERO_IP4, gateway, 1, NULL);

    return OS_SUCCESS;
}


//------------------------------------------------------------------------------
// CAmkES run()
OS_Error_t
OS_NetworkStack_run(
    const os_camkes_network_stack_config_t*  camkes_config,
    const os_network_stack_config_t*         config)
{
    OS_Error_t err;

    // remember config
    Debug_ASSERT( NULL != camkes_config );
    instance.camkes_cfg  = camkes_config;

    Debug_ASSERT( NULL != config );
    instance.cfg         = config;

    // initialize PicoTCP and set API functions
    pico_stack_init();

    // initialize NIC
    err = initialize_nic();
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("initialize_nic() failed, error %d", err);
        return OS_ERROR_GENERIC;
    }

    // notify app after that network stack is initialized
    Debug_LOG_INFO("signal network stack init done");
    notify_app_init_done();

    // enter endless loop processing events
    for (;;)
    {
        // wait for event ( 1 sec tick, write, read)
        wait_network_event();

        // let PicoTCP process the event
        pico_stack_tick();
    }

    Debug_LOG_WARNING("network_stack_event_loop() terminated gracefully");

    return OS_SUCCESS;
}
