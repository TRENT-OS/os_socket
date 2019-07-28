/*
 *  SEOS Network Stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * As of now supports single application and does not support multithreading.
 * Multi app support to be added later
 */

#include "SeosNwChanmuxIf.h"
#include "LibDebug/Debug.h"
#include "SeosNwStack.h"
#include "SeosNwCommon.h"
#include "seos_socket.h"
#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "Seos_pico_dev_chan_mux.h"
#include "pico_socket.h"
//#include "Seos_socket_Config.h"


#define NUM_PING 10

static void nw_socket_event(uint16_t ev, struct pico_socket *s);


/* Nw Api to implement */
typedef struct _nw_api_vtable_t
{
    struct pico_socket * (*nw_socket_open)(uint16_t net, uint16_t proto,void (*wakeup)(uint16_t ev, struct pico_socket *s));
    int (*nw_socket_read)(struct pico_socket *s, void *buf, int len);
    int (*nw_socket_write)(struct pico_socket *s, const void *buf, int len);
    int (*nw_socket_connect)(struct pico_socket *s, const void *srv_addr, uint16_t remote_port);
    int (*nw_socket_bind)(struct pico_socket *s, void *local_addr, uint16_t *port);
    int (*nw_socket_listen)(struct pico_socket *s, int backlog);
    struct pico_socket* (*nw_socket_accept)(struct pico_socket *s, void *orig,uint16_t *local_port);
    int (*nw_socket_close)(struct pico_socket *s);
    int (*nw_socket_setoption)(struct pico_socket *s, int option, void *value);
}nw_api_vtable;


/* Abstraction of pico API */
nw_api_vtable nw_api_if =
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



// Structure to describe pico
typedef struct {
	struct pico_socket *socket;
    const  nw_api_vtable* vtable;
    const  nw_camkes_glue* pCamkesglu;
	struct pico_ip4 ip_addr;
	struct pico_ip4 bind_ip_addr;
	struct pico_socket *client_socket;
    int listen_port;
    int event;
    int read;
}NwStack;


const nw_chanmux_ports_glue* pChanmuxportsglu;
uint8_t instanceID;   /* So that it can be used across other files */



static void  *Appdatabuf;
static NwStack nw;
static NwStack *nwpStack = NULL;



/* To be removed later once Debug Log has support for error handling */
extern const char* nw_strerror(int e);


/* TAP IP address */
static const char* tap_ip_address[]=
 {
//     "192.168.82.91",
//     "192.168.82.92"

     "192.168.178.91",
     "192.168.178.92"

 };

static const char* subnet_masks[]=
 {
     "255.255.255.0",
     "255.255.0.0",
     "255.0.0.0"
 };

static const char* gateway_ip[]=
{
   // "192.168.82.1"
        "192.168.178.1"
};

static const char* cloud_ip[]=
{
     "51.144.118.31"
};

/*
 *
 *  This is called as part of pico_tick every x ms.
 */
static void nw_socket_event(uint16_t ev, struct pico_socket *s)
{
     nwpStack->event = ev;
  /* begin of client if */
  if(instanceID  == SEOS_NWSTACK_AS_CLIENT)
  {
        if (ev & PICO_SOCK_EV_CONN)
        {
            Debug_LOG_INFO("Connection established with server. for socket =%p\n",s);
        }

        if (ev & PICO_SOCK_EV_RD)
        {
                Debug_LOG_TRACE("Read event Rx. for socket =%p\n",s);
                int len = PAGE_SIZE;

                nwpStack->read = nwpStack->vtable->nw_socket_read(nwpStack->socket,(unsigned char*)pChanmuxportsglu->Appdataport,len);
                nwpStack->event = 0;
                Debug_LOG_TRACE("Read data for socket =%p,length=%d,data%s \n",s,nwpStack->read,(char*)pChanmuxportsglu->Appdataport);

                if(nwpStack->read <0)
                {
                    Debug_LOG_INFO("%s: error read of pico socket :%s \n",__FUNCTION__,strerror(pico_err));
                    nwpStack->read = -1;
                }
                nwpStack->pCamkesglu->e_read_emit();   //e_read_emit();
        }


  }/* end of Client if */

  else /* begin of server */
  {
        if (ev & PICO_SOCK_EV_CONN)
        {
            char peer[30] = {0};
            uint32_t ka_val = 0;
            uint16_t port = 0;

            nwpStack->client_socket = NULL;

            struct pico_ip4 orig = {
                0
            };

            int yes = 1;
            nwpStack->client_socket = nwpStack->vtable->nw_socket_accept(nwpStack->socket,&orig,&port);
            if(nwpStack->client_socket != NULL )
            {
               pico_ipv4_to_string(peer, orig.addr);
               Debug_LOG_INFO("Connection established with client %s:%d.\n", peer, short_be(port));
               pico_socket_setoption(nwpStack->client_socket, PICO_TCP_NODELAY, &yes);
               /* Set keepalive options */
               ka_val = 5;
               pico_socket_setoption(nwpStack->client_socket, PICO_SOCKET_OPT_KEEPCNT, &ka_val);
               ka_val = 30000;
               pico_socket_setoption(nwpStack->client_socket, PICO_SOCKET_OPT_KEEPIDLE, &ka_val);
               ka_val = 5000;
               pico_socket_setoption(nwpStack->client_socket, PICO_SOCKET_OPT_KEEPINTVL, &ka_val);
               nwpStack->event = 0; //Clear the event finally
               nwpStack->pCamkesglu->e_conn_emit();
            }
           else
            {
               Debug_LOG_INFO("%s: error accept-2 of pico socket : %s \n",__FUNCTION__,nw_strerror(pico_err));
            }
        }

         if (ev & PICO_SOCK_EV_RD)
         {
               Debug_LOG_TRACE("Read from client for socket =%p\n",s);
               int len = PAGE_SIZE;

               nwpStack->read = nwpStack->vtable->nw_socket_read(nwpStack->client_socket,(unsigned char*)pChanmuxportsglu->Appdataport,len);

               Debug_LOG_TRACE("Read data for socket =%p,length=%d,data%s \n",nwpStack->client_socket,nwpStack->read,(char*)pChanmuxportsglu->Appdataport);
               nwpStack->event = 0;

               if(nwpStack->read<0)
               {
                   Debug_LOG_INFO("%s: error read-2 of pico socket :%s \n",__FUNCTION__,nw_strerror(pico_err));
                   nwpStack->read = -1; /* Return -1 to app in case of error */
               }
               nwpStack->pCamkesglu->e_read_emit();
         }

  }   // end of server


  if (ev & PICO_SOCK_EV_WR)
    {
             nwpStack->pCamkesglu->e_write_emit();   // emit to unblock app which is waiting to write
             Debug_LOG_TRACE("Write event Rx. for socket =%p\n",s);
             nwpStack->pCamkesglu->e_write_nwstacktick(); // Perform nw stack tick now as we received write event from stack
    }


    if (ev & PICO_SOCK_EV_CLOSE)
    {
       Debug_LOG_INFO("Socket received close from peer\n");
    }

    if (ev & PICO_SOCK_EV_FIN)
    {
       Debug_LOG_INFO("Socket closed. Exit normally. \n");
       exit(1);
    }


    if (ev & PICO_SOCK_EV_ERR)
    {
       Debug_LOG_INFO("Socket error received: %s. Bailing out.\n", nw_strerror(pico_err));
       exit(1);
    }

}

/*
 *   Function: NwStackIf_socket()
 *
 *   Return values:
 *   true = success
 *   false = failure
 */

int NwStackIf_socket(int domain, int type)
{

    if (domain == AF_INET6)
        domain = PICO_PROTO_IPV6;
    else
        domain = PICO_PROTO_IPV4;

    if (type == SOCK_STREAM)
        type = PICO_PROTO_TCP;
    else
        type = PICO_PROTO_UDP;

    nwpStack->socket = nwpStack->vtable->nw_socket_open(domain, type, &nw_socket_event);

    if(nwpStack->socket == NULL)
    {
        Debug_LOG_INFO("error opening socket %s:%s\n", __FUNCTION__,nw_strerror(pico_err));
        return -1;
    }
    int yes=1;
    nwpStack->vtable->nw_socket_setoption(nwpStack->socket, PICO_TCP_NODELAY, &yes);

    Debug_LOG_INFO("socket address = %p\n",nwpStack->socket);
    return 0;
}


/*
 *   Function: NwStackIf_close()
 *
 *   Return values:
 *   0 = success
 *  -1 = failure
 */
int NwStackIf_close()
{
    int close = nwpStack->vtable->nw_socket_close(nwpStack->socket);

    if(close <0)
    {
       Debug_LOG_INFO("%s: error closing pico socket :%s \n",__FUNCTION__,nw_strerror(pico_err));
    }
    return close;
}

/*
 *   Function: NwStackIf_connect()
 *
 *   Return values:
 *   0 = success
 *  -1 = failure
 */
int NwStackIf_connect(const char* name, int port)
{
    struct pico_ip4 dst;
    uint16_t send_port = short_be(port);
    pico_string_to_ipv4(name, &dst.addr);

    Debug_LOG_INFO("Connecting socket to %p, addr: %s,send_port %x\n",nwpStack->socket,name,send_port);

    int connect = nwpStack->vtable->nw_socket_connect(nwpStack->socket,&dst,send_port);

    if(connect <0)
    {
      Debug_LOG_INFO("%s: error connecting to %s: %u : %s \n", __FUNCTION__, name, short_be(send_port), nw_strerror(pico_err));
    }
    return connect;
}


/*
 *   Function: NwStackIf_write()
 *
 *   Return values:
 *   no of written bytes = success
 *  -1 = failure
 */
int NwStackIf_write(int len)
{
    int bytes_written = 0;

    nwpStack->pCamkesglu->c_write_wait(); // wait for wr evnt from pico

    if(nwpStack->event & PICO_SOCK_EV_WR)
    {
        bytes_written = nwpStack->vtable->nw_socket_write(nwpStack->socket,(unsigned char*)pChanmuxportsglu->Appdataport ,len);

        Debug_LOG_TRACE(" actual write done =%s, %s\n",__FUNCTION__,(char*)pChanmuxportsglu->Appdataport);
        nwpStack->event = 0;

        if(bytes_written < 0)
        {
          Debug_LOG_INFO("%s: error writing to pico socket :%s \n",__FUNCTION__,nw_strerror(pico_err));
          return -1;
        }

    }
   return bytes_written;
}

/*
 *   Function: NwStackIf_bind()
 *
 *   Return values:
 *   0 = success
 *  -1 = failure
 */
int NwStackIf_bind(uint16_t port)
{
    if(instanceID == SEOS_NWSTACK_AS_CLIENT)
    {
       int bind = nwpStack->vtable->nw_socket_bind(nwpStack->socket,&nwpStack->ip_addr,&port);

       if(bind <0)
       {
           Debug_LOG_INFO("%s: error binding to pico socket: %s \n",__FUNCTION__,nw_strerror(pico_err));
       }
       return bind;
    }
    else
    {
        struct pico_ip4 ZERO_IP4 = { 0 };
        nwpStack->bind_ip_addr = ZERO_IP4;
        port = short_be(5555);

        int bind = nwpStack->vtable->nw_socket_bind(nwpStack->socket,&nwpStack->bind_ip_addr,&port);
        if(bind <0)
        {
            Debug_LOG_INFO("%s: error binding-2 to pico socket: %s \n",__FUNCTION__,nw_strerror(pico_err));
        }
        return bind;

    }
}


/*
 *   Function: NwStackIf_listen()
 *
 *   Return values:
 *   0 = success
 *  -1 = failure
 */
int NwStackIf_listen(int backlog)
{
    int listen = nwpStack->vtable->nw_socket_listen(nwpStack->socket,backlog);

    if(listen <0)
    {
        Debug_LOG_INFO("%s: error listen to pico socket: %s \n",__FUNCTION__,nw_strerror(pico_err));
    }
    return listen;
}


/*
 *   Function: NwStackIf_accept()
 *
 *   Return values:
 *   0 = success
 *  -1 = failure
 *   For server wait on accept until client connects
 *   Not much useful for client as we cannot accept incoming connections
 */
int NwStackIf_accept(uint16_t port)
{
    if(instanceID == SEOS_NWSTACK_AS_CLIENT )
    {
        struct pico_ip4 origin = {0};
        struct pico_socket *sock_client = {0};
        char peer[30] = {0};

        sock_client = nwpStack->vtable->nw_socket_accept(nwpStack->socket,&origin,&port);

        if(sock_client != NULL)
        {
            pico_ipv4_to_string(peer, origin.addr);
            Debug_LOG_INFO("Connection established with %s:%d\n",peer,short_be(port));
            return 0;
        }
        Debug_LOG_INFO("%s: error accept of pico socket : %s \n",__FUNCTION__,nw_strerror(pico_err));
        return -1;
    }
    else
    {
        nwpStack->pCamkesglu->c_conn_wait();              //for server wait for pico event
        return 0;
    }
}

/*
 *   Function: NwStackIf_read()
 *   Return values:
 *   read bytes = success
 *  -1 = failure
 *   Is a blocking call. Wait until we get a read event from Stack
 */

int NwStackIf_read(int len)
{

    nwpStack->pCamkesglu->c_read_wait();  // wait for rd event from pico

    return nwpStack->read;
}



void NwStackIf_App_init(char* nwAppPort)
{
    Appdatabuf = (void*) nwAppPort;

}


//------------------------------------------------------------------------------
// called by NwStack CAmkES wrapper
int
NwStack_seos_init()
{
    struct pico_ip4 ipaddr, netmask;
    struct pico_device* dev;


    pico_stack_init();  //init nw stack = pico

    if(instanceID == SEOS_NWSTACK_AS_CLIENT)
    {
        dev = pico_chan_mux_tap_create("tap0");   //create tap0 device
    }
    else
    {
        dev = pico_chan_mux_tap_create("tap1");   //create tap1 device
    }

    if (!dev)
    {
        Debug_LOG_INFO("Error creating tap dev %s\n",__FUNCTION__);
        return -1;
    }



    /* assign the IP address to the tap interface */
    if(instanceID == SEOS_NWSTACK_AS_CLIENT)
     {
        pico_string_to_ipv4(tap_ip_address[0], &ipaddr.addr);
     }
    else
     {
        pico_string_to_ipv4(tap_ip_address[1], &ipaddr.addr);
     }

     pico_string_to_ipv4(subnet_masks[0], &netmask.addr);
     pico_ipv4_link_add(dev, ipaddr, netmask);

     struct pico_ip4 ZERO_IP4 = { 0 };
     struct pico_ip4 gateway,zero=ZERO_IP4;
     int route;
     struct pico_ip4 dst;

     // add default route and gateway to cloud server
     pico_string_to_ipv4(gateway_ip[0], &gateway.addr);
     route = pico_ipv4_route_add(zero,zero,gateway,1, NULL);
     pico_string_to_ipv4(cloud_ip[0], &dst.addr);
     route = pico_ipv4_route_add(dst,zero,gateway,1, NULL);

     gateway = pico_ipv4_route_get_gateway(&dst);
     Debug_LOG_INFO("gateway address dst =%x and route =%d\n",gateway.addr,route);

     nwpStack->ip_addr= ipaddr;
     nwpStack->vtable = &nw_api_if;

     nwpStack->pCamkesglu->e_initdone();

     for(;;)
    {

        nwpStack->pCamkesglu->c_nwstacktick_wait(); // wait for either Wr, Rd or timeout=1 sec
        pico_stack_tick();
    }
}



// run() when you instantiate SeosNwStack component  must call this
int
Seos_NwStack_init(int instance, nw_camkes_glue *pNwCamkes, nw_chanmux_ports_glue *dataportglu)
{
    int ret;
    nwpStack = &nw;
    Debug_LOG_TRACE("init nwpStack value = %p\n",nwpStack);
    if(pNwCamkes != NULL)
    {
        nwpStack->pCamkesglu = pNwCamkes;

        pChanmuxportsglu = dataportglu;

        if(instance == 0)
        {
            instanceID = SEOS_NWSTACK_AS_CLIENT;
        }
        else if (instance == 1)
        {
            instanceID = SEOS_NWSTACK_AS_SERVER;
        }
        else
        {
            Debug_LOG_INFO("Wrong Instance ID passed. NwStackinit() failed %d\n ", instance);
            return -1;
        }

    }
    else
    {
        return -1;
    }
   /* Configure stack as client or server */

    ret = NwStack_seos_init();  // should never return as this starts pico_stack_tick().

    if(ret<0)  // is possible when proxy does not run with use_tap =1 param. Just print and exit
    {
        Debug_LOG_INFO("Network Stack Init() Failed...Exiting NwStack\n");
    }
    return 0;
}
