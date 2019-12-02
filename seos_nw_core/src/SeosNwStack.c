/*
 *  SEOS Network Stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "LibDebug/Debug.h"
#include "SeosNwStack.h"
#include "SeosNwCommon.h"
#include "seos_nw_api.h"


//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
static void seos_nw_socket_event(uint16_t ev, struct pico_socket* s);



/* Abstraction of pico API */
const seos_nw_api_vtable nw_api_if =
{
    .nw_socket_open       =  pico_socket_open,
    .nw_socket_read       =  pico_socket_read,
    .nw_socket_write      =  pico_socket_write,
    .nw_socket_connect    =  pico_socket_connect,
    .nw_socket_bind       =  pico_socket_bind,
    .nw_socket_listen     =  pico_socket_listen,
    .nw_socket_accept     =  pico_socket_accept,
    .nw_socket_close      =  pico_socket_close,
    .nw_socket_setoption  =  pico_socket_setoption

};

// As of now there is only one app per network stack and there is also only one
// socket. Hence one global variable can be used which represents the network
// stack

static SeosNwstack seos_nw;
static SeosNwstack* pseos_nw = NULL;
Seos_nw_camkes_info* pnw_camkes;


/*******************************************************************************
 *  This is called as part of pico_tick every x ms.
 */
static void
seos_nw_socket_event(uint16_t ev,
                     struct pico_socket* s)
{
    pseos_nw->event = ev;
    /* begin of client if */
#ifdef SEOS_NWSTACK_AS_CLIENT
    if (ev & PICO_SOCK_EV_CONN)
    {
        Debug_LOG_INFO("Connection established with server. for socket =%p", s);
    }
#elif SEOS_NWSTACK_AS_SERVER
    if (ev & PICO_SOCK_EV_CONN)
    {
        char peer[30] = {0};
        uint32_t ka_val = 0;
        uint16_t port = 0;
        int nodelay = 1; /* 1 = disable nagle algorithm , 0 = enable nagle algorithm */
        pseos_nw->client_socket = NULL;

        struct pico_ip4 orig = {0};

        pseos_nw->client_socket = pseos_nw->vtable->nw_socket_accept(pseos_nw->socket,
                                  &orig, &port);
        if (pseos_nw->client_socket != NULL )
        {
            pico_ipv4_to_string(peer, orig.addr);
            Debug_LOG_INFO("Connection established with client %s:%d:%d", peer,
                           short_be(port), port);

            /* The rational behind choosing below values for TCP keep alive comes from
               the TCP unit tests of picotcp. Same values are chosen as done in Picotcp unit tests.
               Please see tests/examples/tcpecho.c of Picotcp
            */
            pico_socket_setoption(pseos_nw->client_socket, PICO_TCP_NODELAY, &nodelay);
            /* Set keepalive options */
            ka_val = 5; /* set no of probes for TCP keepalive */
            pico_socket_setoption(pseos_nw->client_socket, PICO_SOCKET_OPT_KEEPCNT,
                                  &ka_val);
            ka_val = 30000; /* set timeout for TCP keepalive probes (in ms) */
            pico_socket_setoption(pseos_nw->client_socket, PICO_SOCKET_OPT_KEEPIDLE,
                                  &ka_val);
            ka_val = 5000; /* set interval between TCP keep alive retries in case of no reply (in ms) */
            pico_socket_setoption(pseos_nw->client_socket, PICO_SOCKET_OPT_KEEPINTVL,
                                  &ka_val);
            pseos_nw->event = 0; //Clear the event finally
        }
        else
        {
            Debug_LOG_WARNING("%s: error accept-2 of pico socket : %s", __FUNCTION__,
                              seos_nw_strerror(pico_err));
        }
        pnw_camkes->pCamkesglue->e_conn_emit();
    }

#else
#error "Error: Configure as client or server!!"

#endif

    if (ev & PICO_SOCK_EV_RD)
    {
        Debug_LOG_TRACE("Read event Rx. for socket =%p", s);
        pnw_camkes->pCamkesglue->e_read_emit();   //e_read_emit();
    }

    if (ev & PICO_SOCK_EV_WR)
    {
        Debug_LOG_TRACE("Write event Rx. for socket =%p", s);
        pnw_camkes->pCamkesglue->e_write_emit();   // emit to unblock app which is waiting to write
        pnw_camkes->pCamkesglue->e_write_nwstacktick(); // Perform nw stack tick now as we received write event from stack
    }

    if (ev & PICO_SOCK_EV_CLOSE)
    {
        Debug_LOG_DEBUG("Socket received close from peer");
        pnw_camkes->pCamkesglue->e_read_emit();
    }

    if (ev & PICO_SOCK_EV_FIN)
    {
        Debug_LOG_DEBUG("Socket closed");
        pnw_camkes->pCamkesglue->e_read_emit();
    }

    if (ev & PICO_SOCK_EV_ERR)
    {
        Debug_LOG_ERROR("Socket error received: %s. Bailing out",
                        seos_nw_strerror(pico_err));
        pnw_camkes->pCamkesglue->e_read_emit();
    }
}


//------------------------------------------------------------------------------
seos_err_t
network_stack_rpc_socket_create(
    int   domain,
    int   type,
    int*  pHandle)
{
    switch (domain)
    {
    case SEOS_AF_INET:
        domain = PICO_PROTO_IPV4;
        break;

    case SEOS_AF_INET6:
        domain = PICO_PROTO_IPV6;
        break;

    default:
        Debug_LOG_WARNING("unsupported domain %d", domain);
        return SEOS_ERROR_GENERIC;
    }

    switch (type)
    {
    case SEOS_SOCK_STREAM:
        type = PICO_PROTO_TCP;
        break;

    case SEOS_SOCK_DGRAM:
        type = PICO_PROTO_UDP;
        break;

    default:
        Debug_LOG_WARNING("unsupported type %d", domain);
        return SEOS_ERROR_GENERIC;
    }

    pseos_nw->socket = pseos_nw->vtable->nw_socket_open(domain,
                                                        type,
                                                        &seos_nw_socket_event);
    if (pseos_nw->socket == NULL)
    {
        // try to detailed error from PicoTCP. Actually, nw_socket_open()
        // should return a proper error code and populate a handle passed as
        // pointer parameter, so we don't need to access pico_err here.
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("socket opening failed, pico_err = %d, %s",
                        cur_pico_err, seos_nw_strerror(cur_pico_err));
        return SEOS_ERROR_GENERIC;
    }

    Debug_LOG_INFO("new socket is %p", pseos_nw->socket);

    int nodelay = 1; // nagle algorithm: 1=disable, 0=enable
    pseos_nw->vtable->nw_socket_setoption(pseos_nw->socket,
                                          PICO_TCP_NODELAY,
                                          &nodelay);

    pseos_nw->in_use = 1;
    pseos_nw->socket_fd = 0;
    *pHandle = pseos_nw->socket_fd;

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
// get socket from a given handle
static struct pico_socket*
get_pico_socket_from_handle(
    int handle)
{
#ifdef SEOS_NWSTACK_AS_CLIENT

    // we support only one handle
    return (0 == handle) ? pseos_nw->socket : NULL;

#elif SEOS_NWSTACK_AS_SERVER

    // handle = 0: server socket
    // handle = 1: client connection


    return (0 == handle) ? pseos_nw->socket
           : (1 == handle) ? pseos_nw->client_socket
           : NULL;

#else
#error "Error: Configure as client or server!!"
#endif
}


//------------------------------------------------------------------------------
seos_err_t
network_stack_rpc_socket_close(
    int handle)
{
    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (socket == NULL)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    int ret = pseos_nw->vtable->nw_socket_close(socket);
    if (ret < 0)
    {
        pico_err_t cur_pico_err = pico_err;
        Debug_LOG_ERROR("socket closing failed with error %d, pico_err %d (%s)",
                        ret, cur_pico_err, seos_nw_strerror(cur_pico_err));
        return SEOS_ERROR_GENERIC;
    }

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
seos_err_t
network_stack_rpc_socket_connect(
    int          handle,
    const char*  name,
    int          port)
{
    struct pico_ip4 dst;
    uint16_t send_port = short_be(port);
    pico_string_to_ipv4(name, &dst.addr);

    Debug_LOG_INFO("Connecting socket to %p, addr: %s,send_port %x",
                   pseos_nw->socket, name, send_port);

    int connect = pseos_nw->vtable->nw_socket_connect(pseos_nw->socket, &dst,
                                                      send_port);

    if (connect < 0)
    {
        Debug_LOG_WARNING("%s: error connecting to %s: %u : %s", __FUNCTION__, name,
                          short_be(send_port), seos_nw_strerror(pico_err));
        return SEOS_ERROR_GENERIC;
    }

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
seos_err_t
network_stack_rpc_socket_write(
    int handle,
    size_t* pLen)
{
    int bytes_written = 0;

    pnw_camkes->pCamkesglue->c_write_wait(); // wait for wr evnt from pico

    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (socket != NULL)
    {
        bytes_written = pseos_nw->vtable->nw_socket_write(socket,
                                                          (unsigned char*)pnw_camkes->pportsglu->Appdataport, *pLen);
        Debug_LOG_TRACE(" actual write done =%s, %s", __FUNCTION__,
                        (char*)pnw_camkes->pportsglu->Appdataport);

        pseos_nw->event = 0;

        if (bytes_written < 0)
        {
            Debug_LOG_WARNING("%s: error writing to pico socket :%s", __FUNCTION__,
                              seos_nw_strerror(pico_err));
            return SEOS_ERROR_GENERIC;
        }

        *pLen = bytes_written;   // copy actual bytes written to app

        return SEOS_SUCCESS;
    }
    return SEOS_ERROR_INVALID_HANDLE;
}


//------------------------------------------------------------------------------
seos_err_t
network_stack_rpc_socket_bind(
    int handle,
    uint16_t port)
{
    struct pico_ip4 ZERO_IP4 = { 0 };
    pseos_nw->bind_ip_addr = ZERO_IP4;

    Debug_LOG_TRACE("%s:binding port addr : %d,%d", __FUNCTION__, port,
                    short_be(port));
    port = short_be(port);

    int bind = pseos_nw->vtable->nw_socket_bind(pseos_nw->socket,
                                                &pseos_nw->bind_ip_addr, &port);
    if (bind < 0)
    {
        Debug_LOG_WARNING("%s: error binding-2 to pico socket: %s", __FUNCTION__,
                          seos_nw_strerror(pico_err));
        return SEOS_ERROR_GENERIC;
    }
    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
seos_err_t
network_stack_rpc_socket_listen(
    int handle,
    int backlog)
{
    int listen = pseos_nw->vtable->nw_socket_listen(pseos_nw->socket, backlog);

    if (listen < 0)
    {
        Debug_LOG_WARNING("%s: error listen to pico socket: %s", __FUNCTION__,
                          seos_nw_strerror(pico_err));
        return SEOS_ERROR_GENERIC;
    }
    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
// For server wait on accept until client connects. Not much useful for client
// as we cannot accept incoming connections
seos_err_t
network_stack_rpc_socket_accept(
    int handle,
    int* pClient_handle,
    uint16_t port)
{
    pnw_camkes->pCamkesglue->c_conn_wait(); //for server wait for pico event
    if (pseos_nw->client_socket == NULL )
    {
        Debug_LOG_WARNING("%s: socket is NULL", __FUNCTION__);
        return SEOS_ERROR_GENERIC;
    }

    // Requires change when Multi threading is added.
    // As of now Incoming socket handle set to 1
    *pClient_handle = 1;
    return SEOS_SUCCESS; // as we have only one incoming connection
}


//------------------------------------------------------------------------------
// Is a blocking call. Wait until we get a read event from Stack
seos_err_t
network_stack_rpc_socket_read(
    int handle,
    size_t* pLen)
{
    seos_err_t retval = SEOS_SUCCESS;
    int picoReadBytes = 0;
    int tot_len = 0;
    size_t len = *pLen; /* App requested length */
    void* buf = pnw_camkes->pportsglu->Appdataport; /* App data port */

    struct pico_socket* socket_handle = get_pico_socket_from_handle(handle);
    if (NULL == socket_handle)
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        while (SEOS_SUCCESS == retval && 0 == tot_len)
        {
            picoReadBytes = pseos_nw->vtable->nw_socket_read(socket_handle,
                                                             buf + tot_len,
                                                             len - tot_len);
            if (picoReadBytes < 0)
            {
                Debug_LOG_ERROR("Read returning with error %d: %s",
                                pico_err, seos_nw_strerror(pico_err));
                if (pico_err == PICO_ERR_ESHUTDOWN)
                {
                    Debug_LOG_INFO("%s: connection closed by peer for socket (handle) %d", __func__,
                                   handle);
                    retval = SEOS_ERROR_CONNECTION_CLOSED;
                }
                else
                {
                    Debug_LOG_ERROR("%s: error %d reading from socket (handle) %d", __func__,
                                    pico_err, handle);
                    retval =  SEOS_ERROR_GENERIC;
                }
            }
            else if (0 == picoReadBytes)
            {
                if (len > 0)
                {
                    /* wait for a new RD event -- also wait possibly for a CLOSE event */
                    pnw_camkes->pCamkesglue->c_read_wait();
                    if (pseos_nw->event & PICO_SOCK_EV_CLOSE)
                    {
                        /* closing of socket must be done by the app after return */
                        pseos_nw->event = 0;
                        Debug_LOG_DEBUG("Socket close received");
                        retval = SEOS_ERROR_CONNECTION_CLOSED; /* return 0 on a properly closed socket */
                    }
                }
            }
            else
            {
                tot_len += picoReadBytes;
            }
        } // end of while()
    }
#if (Debug_Config_LOG_LEVEL >=  Debug_LOG_LEVEL_TRACE)
    Debug_LOG_TRACE("%s(), Read data length=%d, and Data:", __FUNCTION__,
                    tot_len);
    for (int i = 0; i <= tot_len; i++)
    {
        Debug_PRINTF("%02x ", ((uint8_t*)pnw_camkes->pportsglu->Appdataport)[i]);
        if (i % 16 == 0)
        {
            Debug_PRINTF("\n");
        }
    }
    Debug_PRINTF("\n");
#endif
    *pLen = tot_len;
    return retval;
}


//------------------------------------------------------------------------------
void network_stack_rpc_init()
{
    pnw_camkes->pCamkesglue->c_initdone();   // wait for nw stack to initialise
}


//------------------------------------------------------------------------------
static seos_err_t
network_config_init(
    Seos_nw_camkes_info*        nw_camkes,
    SeosNwstack*                seos_nw,
    const seos_nw_api_vtable*   nw_api_if,
    seos_nw_config*             nw_stack_config)
{

    struct pico_ip4 ipaddr;
    struct pico_device* dev;

    /* Call the driver Create device callback for device creation */

    dev = nw_stack_config->driver_create_device();

    pico_string_to_ipv4(nw_stack_config->dev_addr, &ipaddr.addr);

    if (!dev)
    {
        Debug_LOG_ERROR("%s():Error creating tap device", __FUNCTION__);
        return SEOS_ERROR_GENERIC;
    }

    // create IPv4 interface wih address and netmask
    struct pico_ip4 netmask;
    pico_string_to_ipv4(nw_stack_config->subnet_mask, &netmask.addr);
    pico_ipv4_link_add(dev, ipaddr, netmask);

    const struct pico_ip4 ZERO_IP4 = { 0 };

    // add default route via gateway
    struct pico_ip4 gateway;
    pico_string_to_ipv4(nw_stack_config->gateway_addr, &gateway.addr);
    (void)pico_ipv4_route_add(ZERO_IP4, ZERO_IP4, gateway, 1, NULL);

    // setup network stack
    seos_nw->ip_addr = ipaddr;
    seos_nw->vtable = nw_api_if;
    seos_nw->in_use = 1; // Required for multi threading

    // notify app after that network stack is initialized
    nw_camkes->pCamkesglue->e_initdone();

    // enter endles loop processing events
    for (;;)
    {
        // wait for event (write, read or 1 sec timeout)
        nw_camkes->pCamkesglue->c_nwstacktick_wait();
        // let PicoTCP process the event
        pico_stack_tick();
    }

    Debug_LOG_FATAL("tick loop terminated");
    return SEOS_ERROR_GENERIC;
}

//------------------------------------------------------------------------------
// CAmkES run() must call this
seos_err_t
Seos_NwStack_init(
    Seos_nw_camkes_info*        nw_camkes_info,
    seos_nw_config*             nw_stack_config)
{
    if (nw_camkes_info == NULL)
    {
        Debug_LOG_ERROR("nw_camkes_info is NULL");
        return SEOS_ERROR_GENERIC;
    }

    pnw_camkes = nw_camkes_info;

    pseos_nw  = &seos_nw;

    pico_stack_init();

    // this may not return
    seos_err_t ret = network_config_init(pnw_camkes, pseos_nw, &nw_api_if,
                                         nw_stack_config);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_FATAL("network_config_init() failed with %d", ret);
        return SEOS_ERROR_GENERIC;
    }

    return SEOS_SUCCESS;
}
