/*
 *  SEOS Network Stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosNwChanmuxIf.h"
#include "LibDebug/Debug.h"
#include "SeosNwStack.h"
#include "SeosNwCommon.h"
#include "Seos_pico_dev_chan_mux.h"
#include "seos_nw_api.h"


//------------------------------------------------------------------------------
// SEOS system configuration

#if defined(NETWORK_CONFIG_H_FILE)

#define NETWORK_XSTR(s)    NETWORK_STR(d)
#define NETWORK_STR(s)     #s
#include NETWORK_XSTR(NETWORK_CONFIG_H_FILE)

#else

// for legacy compatibility, we have to provide this default config file
// until every SEOS system has been extended to provide one.
#include "../../configs/SeosNwConfig.h"

#endif

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
static SeosNwstack** ppseos_nw = NULL ;
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
    if (pnw_camkes->instanceID  == SEOS_NWSTACK_AS_CLIENT)
    {
        if (ev & PICO_SOCK_EV_CONN)
        {
            Debug_LOG_INFO("Connection established with server. for socket =%p", s);
        }

    }/* end of Client if */
    else /* begin of server */
    {
        if (ev & PICO_SOCK_EV_CONN)
        {
            char peer[30] = {0};
            uint32_t ka_val = 0;
            uint16_t port = 0;

            pseos_nw->client_socket = NULL;

            struct pico_ip4 orig =
            {
                0
            };

            int yes = 1;
            pseos_nw->client_socket = pseos_nw->vtable->nw_socket_accept(pseos_nw->socket,
                                      &orig, &port);
            if (pseos_nw->client_socket != NULL )
            {
                pico_ipv4_to_string(peer, orig.addr);
                Debug_LOG_INFO("Connection established with client %s:%d:%d", peer,
                               short_be(port), port);
                pico_socket_setoption(pseos_nw->client_socket, PICO_TCP_NODELAY, &yes);
                /* Set keepalive options */
                ka_val = 5;
                pico_socket_setoption(pseos_nw->client_socket, PICO_SOCKET_OPT_KEEPCNT,
                                      &ka_val);
                ka_val = 30000;
                pico_socket_setoption(pseos_nw->client_socket, PICO_SOCKET_OPT_KEEPIDLE,
                                      &ka_val);
                ka_val = 5000;
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

    }   // end of server

    if (ev & PICO_SOCK_EV_RD)
    {
        Debug_LOG_TRACE("Read event Rx. for socket =%p", s);
        pnw_camkes->pCamkesglue->e_read_emit();   //e_read_emit();
    }

    if (ev & PICO_SOCK_EV_WR)
    {
        pnw_camkes->pCamkesglue->e_write_emit();   // emit to unblock app which is waiting to write
        Debug_LOG_TRACE("Write event Rx. for socket =%p", s);
        pnw_camkes->pCamkesglue->e_write_nwstacktick(); // Perform nw stack tick now as we received write event from stack
    }

    if (ev & PICO_SOCK_EV_CLOSE)
    {
        Debug_LOG_INFO("Socket received close from peer");
        pnw_camkes->pCamkesglue->e_read_emit();
        return;
    }

    if (ev & PICO_SOCK_EV_FIN)
    {
        Debug_LOG_INFO("Socket closed. Exit normally");
        exit(1);
    }

    if (ev & PICO_SOCK_EV_ERR)
    {
        Debug_LOG_INFO("Socket error received: %s. Bailing out",
                       seos_nw_strerror(pico_err));
        exit(1);
    }
}


//------------------------------------------------------------------------------
seos_err_t
seos_socket_create(int domain,
                   int type,
                   int* pHandle )
{

    if (domain == SEOS_AF_INET6)
    {
        domain = PICO_PROTO_IPV6;
    }
    else
    {
        domain = PICO_PROTO_IPV4;
    }

    if (type == SEOS_SOCK_STREAM)
    {
        type = PICO_PROTO_TCP;
    }
    else
    {
        type = PICO_PROTO_UDP;
    }

    pseos_nw->socket = pseos_nw->vtable->nw_socket_open(domain, type,
                                                        &seos_nw_socket_event);

    if (pseos_nw->socket == NULL)
    {
        Debug_LOG_WARNING("error opening socket %s:%s", __FUNCTION__,
                          seos_nw_strerror(pico_err));
        return SEOS_ERROR_GENERIC;
    }
    int yes = 1;
    pseos_nw->vtable->nw_socket_setoption(pseos_nw->socket, PICO_TCP_NODELAY, &yes);

    Debug_LOG_INFO("socket address = %p", pseos_nw->socket);

    /* For now it is just 1 app support, handle will be 0 and this code is not much useful.*/
    /* revisit when multi thread support is supported */
    for (int i = 0; i < SEOS_MAX_NO_NW_THREADS; i++)
    {
        // Relook when multi threading is supported. Fine for 1 app per instance
        if (ppseos_nw[i] != NULL)
        {
            pseos_nw->in_use = 1;
            pseos_nw->socket_fd = i;
            *pHandle = pseos_nw->socket_fd;
            break;
        }
        else
        {
            return SEOS_ERROR_GENERIC;
        }
    }
    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
seos_err_t
seos_socket_close(int handle)
{
    int close;

    if (pnw_camkes->instanceID  == SEOS_NWSTACK_AS_CLIENT)
    {
        close = pseos_nw->vtable->nw_socket_close(pseos_nw->socket);
    }
    else
    {
        if (handle == 1)
        {
            close = pseos_nw->vtable->nw_socket_close(pseos_nw->client_socket);
        }
        else
        {
            close = pseos_nw->vtable->nw_socket_close(pseos_nw->socket);
        }

    }

    if (close < 0)
    {
        Debug_LOG_WARNING("%s: error closing pico socket :%s", __FUNCTION__,
                          seos_nw_strerror(pico_err));
        return SEOS_ERROR_GENERIC;

    }
    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
seos_err_t
seos_socket_connect(int handle,
                    const char* name,
                    int port)
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
seos_socket_write(int handle,
                  size_t* pLen)
{
    int bytes_written = 0;

    pnw_camkes->pCamkesglue->c_write_wait(); // wait for wr evnt from pico


    if (pnw_camkes->instanceID == SEOS_NWSTACK_AS_CLIENT)
    {
        bytes_written = pseos_nw->vtable->nw_socket_write(pseos_nw->socket,
                                                          (unsigned char*)pnw_camkes->pportsglu->Appdataport, *pLen);
    }
    else
    {
        bytes_written = pseos_nw->vtable->nw_socket_write(pseos_nw->client_socket,
                                                          (unsigned char*)pnw_camkes->pportsglu->Appdataport, *pLen);
    }

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


//------------------------------------------------------------------------------
seos_err_t
seos_socket_bind(int handle,
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
seos_socket_listen(int handle,
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
seos_socket_accept(int handle,
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
seos_socket_read(int handle,
                 size_t* pLen)
{
    int retval = 0;
    int tot_len = 0;
    size_t len = *pLen; /* App requested length */
    void* buf = pnw_camkes->pportsglu->Appdataport; /* App data port */

    if (len <= 0) /* nothing can be done and is an error*/
    {
        Debug_LOG_WARNING("%s() Invalid param length %d", __FUNCTION__, *pLen);
        return SEOS_ERROR_GENERIC;
    }

    struct pico_socket* socket_handle = (pnw_camkes->instanceID ==
                                         SEOS_NWSTACK_AS_CLIENT) ?
                                        pseos_nw->socket : pseos_nw->client_socket;

    while (tot_len < len)
    {

        retval = pseos_nw->vtable->nw_socket_read(socket_handle,
                                                  buf + tot_len, len - tot_len);
        /* nw_socket_read() failed */
        if (retval < 0)
        {
            /* data was received */
            if (tot_len > 0)
            {
                Debug_LOG_WARNING("Read returning with error %d: %s",
                                  tot_len, seos_nw_strerror(pico_err));
                *pLen = tot_len;
            }
            /* no data was received yet
               If no messages are available to be received and the peer has
               performed an orderly shutdown, read shall return Success. */
            if (pico_err == PICO_ERR_ESHUTDOWN)
            {
                *pLen = 0;
                return SEOS_SUCCESS;
            }
            /* Otherwise, the function shall return SEOS_ERROR_GENERIC */
            return SEOS_ERROR_GENERIC;
        }
        /* If received 0 bytes, return  amount of bytes received */
        if (retval == 0)
        {
            pseos_nw->event = 0;
            if (tot_len > 0)
            {
                Debug_LOG_INFO("Read returning %d", tot_len);
                *pLen = tot_len;
                return SEOS_SUCCESS;
            }
        }

        if (retval > 0)
        {
            /* continue until retval = 0, socket buffer empty */
            tot_len += retval;
            continue;
        }

        /* We have a blocking socket. We need to wait until data becomes
           available to be able to return from this function.

           If recv bytes (retval) < len-tot_len: socket empty, we need to wait
           for a new RD event */
        if (retval < (len - tot_len))
        {
            /* wait for a new RD event -- also wait possibly for a CLOSE event */
            pnw_camkes->pCamkesglue->c_read_wait();
            if (pseos_nw->event & PICO_SOCK_EV_CLOSE)
            {
                /* closing of socket must be done by the app after return */
                pseos_nw->event = 0;
                Debug_LOG_INFO("Socket close received");
                *pLen = 0;
                return SEOS_ERROR_CONNECTION_CLOSED; /* return 0 on a properly closed socket */
            }
        }

        tot_len += retval;

    } // end of while()

    Debug_LOG_TRACE("%s(), Read data length=%d, and Data:", __FUNCTION__,
                    tot_len);
    for (int i = 0; i <= tot_len; i++)
    {
        Debug_LOG_TRACE("%02x\t", ((uint8_t*)pnw_camkes->pportsglu->Appdataport)[i]);
    }

    Debug_LOG_TRACE("Read returning %d (full block)", tot_len);
    *pLen = tot_len;
    return SEOS_SUCCESS;

}


//------------------------------------------------------------------------------
void seos_network_init()
{
    pnw_camkes->pCamkesglue->c_initdone();   // wait for nw stack to initialise
}


//------------------------------------------------------------------------------
// CAmkES run() must call this
seos_err_t
Seos_NwStack_init(Seos_nw_camkes_info* nw_camkes_info)
{
    if (nw_camkes_info == NULL)
    {
        Debug_LOG_ERROR("nw_camkes_info is NULL");
        return SEOS_ERROR_GENERIC;
    }

    pnw_camkes = nw_camkes_info;

    pseos_nw  = &seos_nw;
    // for now we have only one socket per app and hence use 0.
    ppseos_nw = &pseos_nw;

    pico_stack_init();

    // this may not return
    seos_err_t ret = network_config_init(pnw_camkes, pseos_nw, &nw_api_if);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_FATAL("network_config_init() failed with %d", ret);
        return SEOS_ERROR_GENERIC;
    }

    return SEOS_SUCCESS;
}

