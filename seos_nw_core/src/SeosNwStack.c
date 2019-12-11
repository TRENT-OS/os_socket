/*
 *  SEOS Network Stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "LibDebug/Debug.h"
#include "seos_nw_api.h"
#include "seos_network_stack.h"
#include "seos_api_network_stack.h"
#include "SeosNwCommon.h"
#include "SeosNwStack.h"

/* Abstraction of pico API */
static const seos_nw_api_vtable picotcp_funcs =
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


// network stack state
static network_stack_t  instance_seos_nw = {0};
static network_stack_t* pseos_nw = NULL;

//------------------------------------------------------------------------------
// Configuration
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
void
wait_network_event(void)
{
    event_wait_func_t do_wait = pseos_nw->camkes_cfg->wait_loop_event;
    if (!do_wait)
    {
        Debug_LOG_WARNING("wait_loop_event not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
void
internal_notify_main_loop(void)
{
    event_notify_func_t do_notify = pseos_nw->camkes_cfg->internal.notify_loop;
    if (!do_notify)
    {
        Debug_LOG_WARNING("internal.notify_main_loop not set");
        return;
    }

    do_notify();
}


//------------------------------------------------------------------------------
void
internal_notify_read(void)
{
    event_notify_func_t do_notify = pseos_nw->camkes_cfg->internal.notify_read;
    if (!do_notify)
    {
        Debug_LOG_WARNING("notify_read not set");
        return;
    }

    do_notify();
}

//------------------------------------------------------------------------------
void
internal_wait_read(void)
{
    event_wait_func_t do_wait = pseos_nw->camkes_cfg->internal.wait_read;
    if (!do_wait)
    {
        Debug_LOG_WARNING("internal.wait_read not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
void
internal_notify_write(void)
{
    event_notify_func_t do_notify = pseos_nw->camkes_cfg->internal.notify_write;
    if (!do_notify)
    {
        Debug_LOG_WARNING("notify_write not set");
        return;
    }

    do_notify();
}


//------------------------------------------------------------------------------
void
internal_wait_write(void)
{
    event_wait_func_t do_wait = pseos_nw->camkes_cfg->internal.wait_write;
    if (!do_wait)
    {
        Debug_LOG_WARNING("internal.wait_write not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
void
internal_notify_connection(void)
{
    event_notify_func_t do_notify =
        pseos_nw->camkes_cfg->internal.notify_connection;
    if (!do_notify)
    {
        Debug_LOG_WARNING("internal.notify_connection not set");
        return;
    }

    do_notify();
}


//------------------------------------------------------------------------------
void
internal_wait_connection(void)
{
    event_wait_func_t do_wait = pseos_nw->camkes_cfg->internal.wait_connection;
    if (!do_wait)
    {
        Debug_LOG_WARNING("internal.wait_connection not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
void
wait_nic_init_done(void)
{
    event_wait_func_t do_wait = pseos_nw->camkes_cfg->drv_nic.wait_init_done;
    if (!do_wait)
    {
        Debug_LOG_WARNING("drv_nic.wait_init_done not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
const seos_shared_buffer_t*
get_nic_port_from(void)
{
    // network stack -> driver (aka output)
    const seos_shared_buffer_t* port = &(pseos_nw->camkes_cfg->drv_nic.from);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->buffer );
    Debug_ASSERT( 0 != port->len );

    return port;
}


//------------------------------------------------------------------------------
const seos_shared_buffer_t*
get_nic_port_to(void)
{
    // driver -> network stack (aka input)
    const seos_shared_buffer_t* port = &(pseos_nw->camkes_cfg->drv_nic.to);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->buffer );
    Debug_ASSERT( 0 != port->len );

    return port;
}


//------------------------------------------------------------------------------
seos_err_t
nic_rpc_dev_write(
    size_t* pLen)
{
    return pseos_nw->camkes_cfg->drv_nic.rpc.dev_write(pLen);
}


//------------------------------------------------------------------------------
seos_err_t
nic_rpc_get_mac(void)
{
    Debug_LOG_INFO("%s", __func__);
    return pseos_nw->camkes_cfg->drv_nic.rpc.get_mac();
}


//------------------------------------------------------------------------------
void
notify_app_init_done(void)
{
    event_notify_func_t do_notify = pseos_nw->camkes_cfg->app.notify_init_done;
    if (!do_notify)
    {
        Debug_LOG_WARNING("app.notify_init_done not set");
        return;
    }

    Debug_LOG_INFO("%s", __func__);
    do_notify();
}


//------------------------------------------------------------------------------
const seos_shared_buffer_t*
get_app_port(void)
{
    // network stack -> driver (aka output)
    const seos_shared_buffer_t* port = &(pseos_nw->camkes_cfg->app.port);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->buffer );
    Debug_ASSERT( 0 != port->len );

    return port;
}


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
        internal_notify_connection();
    }

#else
#error "Error: Configure as client or server!!"

#endif

    if (ev & PICO_SOCK_EV_RD)
    {
        Debug_LOG_TRACE("Read event Rx. for socket =%p", s);
        internal_notify_read();
    }

    if (ev & PICO_SOCK_EV_WR)
    {
        Debug_LOG_TRACE("Write event Rx. for socket =%p", s);
        // notify app, which is waiting to write
        internal_notify_write();
        // notify network stack loop about an event
        internal_notify_main_loop();
    }

    if (ev & PICO_SOCK_EV_CLOSE)
    {
        Debug_LOG_DEBUG("Socket received close from peer");
        internal_notify_read();
    }

    if (ev & PICO_SOCK_EV_FIN)
    {
        Debug_LOG_DEBUG("Socket closed");
        internal_notify_read();
    }

    if (ev & PICO_SOCK_EV_ERR)
    {
        Debug_LOG_ERROR("Socket error received: %s. Bailing out",
                        seos_nw_strerror(pico_err));
        internal_notify_read();
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

    struct pico_socket* socket = get_pico_socket_from_handle(handle);
    if (socket != NULL)
    {
        internal_wait_write();
        const seos_shared_buffer_t* app_port = get_app_port();

        bytes_written = pseos_nw->vtable->nw_socket_write(socket,
                                                          app_port->buffer,
                                                          *pLen);

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
    internal_wait_connection();
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

    const seos_shared_buffer_t* app_port = get_app_port();
    uint8_t* buf = app_port->buffer;

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
                    internal_wait_read();
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
        Debug_PRINTF("%02x ", ((uint8_t*)app_port->buffer)[i]);
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
// NIC Driver interface
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
static int
nic_send_data(
    struct pico_device*  dev,
    void*                buf,
    int                  len)
{
    const seos_shared_buffer_t* nic_in = get_nic_port_to();
    void* wrbuf = nic_in->buffer;

    // copy data it into shared buffer
    size_t wr_len = len;
    memcpy(wrbuf, buf, wr_len);
    // call driver
    seos_err_t err = nic_rpc_dev_write(&wr_len);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("nic_rpc_dev_write() failed, error %d", err);
        return -1;
    }

    return len;
}


//------------------------------------------------------------------------------
// Called after notification from driver and regularly from PicoTCP stack tick
static int
nic_poll_data(
    struct pico_device*  dev,
    int                  loop_score)
{
    // loop_score indicates max number of frames that can be processed during
    // the invocation of this poll. Since we still lack the convept of frames
    // in the shared memory, we can't do much here. Predend there is one
    // frame in the buffer and give it to PicoTCP
    if (loop_score > 0)
    {
        const seos_shared_buffer_t* nw_in = get_nic_port_from();
        Rx_Buffer* nw_rx = (Rx_Buffer*)nw_in->buffer;

        size_t len = nw_rx->len;
        if (len > 0)
        {
            Debug_LOG_INFO("incomming data len %zu", len);
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
    // currently we only have one static device
    if (&pseos_nw->seos_dev != dev)
    {
        Debug_LOG_ERROR("dev (%p) is not seos_dev (%p)", dev, &pseos_nw->seos_dev);
    }

    memset(dev, 0, sizeof(*dev));
}


//------------------------------------------------------------------------------
struct pico_device*
seos_network_device_create(void)
{
    struct pico_device* dev = &pseos_nw->seos_dev;

    memset(dev, 0, sizeof(*dev));

    dev->send    = nic_send_data;
    dev->poll    = nic_poll_data;
    dev->destroy = nic_destroy;

    // get MAC from NIC driver
    seos_err_t err = nic_rpc_get_mac();
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("nic_rpc_get_mac() failed, error %d", err);
        nic_destroy(dev);
        return NULL;
    }

    const seos_shared_buffer_t* nw_in = get_nic_port_from();
    Rx_Buffer* nw_rx = (Rx_Buffer*)nw_in->buffer;
    uint8_t* mac = nw_rx->data;

    Debug_LOG_INFO("MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );

    static const char* drv_name  = "tapdriver";
    int ret = pico_device_init(dev, drv_name, mac);
    if (ret != 0)
    {
        Debug_LOG_ERROR("pico_device_init() failed, error %d", ret);
        nic_destroy(dev);
        return NULL;
    }

    Debug_LOG_INFO("Device created: %s", drv_name);

    return dev;
}


//------------------------------------------------------------------------------
// initialization
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
static seos_err_t
network_stack_init(void)
{
    // initialize PicoTCP
    pico_stack_init();

    struct pico_ip4 ipaddr;
    pico_string_to_ipv4(pseos_nw->cfg->dev_addr, &ipaddr.addr);
    pseos_nw->ip_addr = ipaddr;

    struct pico_ip4 netmask;
    pico_string_to_ipv4(pseos_nw->cfg->subnet_mask, &netmask.addr);

    struct pico_ip4 gateway;
    pico_string_to_ipv4(pseos_nw->cfg->gateway_addr, &gateway.addr);

    // wait for NIC init
    Debug_LOG_INFO("waiting for NIC init");
    wait_nic_init_done();

    // set PicoTCP functions
    pseos_nw->vtable = &picotcp_funcs;

    struct pico_device* dev = seos_network_device_create();
    if (!dev)
    {
        Debug_LOG_ERROR("seos_network_device_create() failed");
        return SEOS_ERROR_GENERIC;
    }

    // assign IP address and netmask
    pico_ipv4_link_add(dev, ipaddr, netmask);

    // add default route via gateway
    const struct pico_ip4 ZERO_IP4 = { 0 };
    (void)pico_ipv4_route_add(ZERO_IP4, ZERO_IP4, gateway, 1, NULL);

    // notify app after that network stack is initialized
    Debug_LOG_INFO("signal network stack init done");
    notify_app_init_done();

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
static seos_err_t
network_stack_event_loop(void)
{
    // enter endless loop processing events
    for (;;)
    {
        // wait for event ( 1 sec tick, write, read)
        wait_network_event();

        // let PicoTCP process the event
        pico_stack_tick();
    }

    Debug_LOG_FATAL("network stack loop terminated");
    return SEOS_ERROR_GENERIC;
}


//------------------------------------------------------------------------------
// CAmkES run()
seos_err_t
seos_network_stack_run(
    const seos_camkes_network_stack_config_t*  camkes_config,
    const seos_network_stack_config_t*         config)
{
    seos_err_t err;

    // we have only one instance
    pseos_nw = &instance_seos_nw;

    // remember config
    pseos_nw->camkes_cfg  = camkes_config;
    pseos_nw->cfg         = config;

    err = network_stack_init();
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("network_stack_init() failed, error %d", err);
        return SEOS_ERROR_GENERIC;
    }

    err = network_stack_event_loop();
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("network_stack_event_loop() failed, error %d", err);
        return SEOS_ERROR_GENERIC;
    }

    Debug_LOG_WARNING("network_stack_event_loop() terminated gracefully");

    return SEOS_SUCCESS;
}
