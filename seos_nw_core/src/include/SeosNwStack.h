/*
 * SEOS Network Stack
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosNwStack.h
 *
 * @brief Core Network stack header info.

 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */


#pragma once

#include <stdlib.h>
#include <stdint.h>
#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_socket.h"

#define SEOS_MAX_NO_NW_THREADS   1

enum
{
    SEOS_NWSTACK_AS_CLIENT,    //0
    SEOS_NWSTACK_AS_SERVER,    // 1
    SEOS_NONE
};

/* Nw Api to implement */
typedef struct _nw_api_vtable_t
{
    struct pico_socket* (*nw_socket_open)(uint16_t net, uint16_t proto,
                                          void (*wakeup)(uint16_t ev, struct pico_socket* s));
    int (*nw_socket_read)(struct pico_socket* s, void* buf, int len);
    int (*nw_socket_write)(struct pico_socket* s, const void* buf, int len);
    int (*nw_socket_connect)(struct pico_socket* s, const void* srv_addr,
                             uint16_t remote_port);
    int (*nw_socket_bind)(struct pico_socket* s, void* local_addr, uint16_t* port);
    int (*nw_socket_listen)(struct pico_socket* s, int backlog);
    struct pico_socket* (*nw_socket_accept)(struct pico_socket* s, void* orig,
                                            uint16_t* local_port);
    int (*nw_socket_close)(struct pico_socket* s);
    int (*nw_socket_setoption)(struct pico_socket* s, int option, void* value);
} nw_api_vtable;



// Structure to describe pico nw stack
typedef struct _SeosNwstack_t
{
    struct pico_socket* socket;
    const    nw_api_vtable* vtable;
    struct   pico_ip4 ip_addr;
    struct   pico_ip4 bind_ip_addr;
    struct   pico_socket* client_socket;
    int      listen_port;
    int      event;
    int      read;
    int      socket_fd;
    uint8_t  in_use;
} SeosNwstack;


/* Camkes structure to be filled during component instantiation */
typedef struct _nw_camkes_glue_t
{
    void (*e_write_emit)();  // emit and wait when there is pico event to write
    void (*c_write_wait)();
    void (*e_read_emit)();   // emit and wait when there is event to read
    void (*c_read_wait)();
    void (*e_conn_emit)();   // emit and wait when connected in case of server
    void (*c_conn_wait)();
    void (*e_write_nwstacktick)(); // tick nw stack when there is write event
    void (*c_nwstacktick_wait)();
    void (*e_initdone)();          // inform app after nw stack is initialised
    void (*c_initdone)();
} nw_camkes_signal_glue;


typedef struct _nw_ports_glue_t
{
    void* ChanMuxDataPort;
    void* ChanMuxCtrlPort;
    void* Appdataport;
} nw_ports_glue;



typedef struct
    _Seos_nw_camkes_info_t    /* So that it can be used across other files */
{
    nw_camkes_signal_glue* pCamkesglue;
    nw_ports_glue* pportsglu;
    uint8_t instanceID;
} Seos_nw_camkes_info;


/**
* @brief Instantiate Network Stack
*
* @param Seos_nw_camkes_info, structure containing Camkes signals used, ports used and instance ID
*        nw_camkes_signal_glue => contains emit and wait signals used in the Network stack
*        nw_ports_glue         => contains data ports used by network stack. This would be Chanmux ports and App port.
*        instanceID            => Either SEOS_NWSTACK_AS_CLIENT  or SEOS_NWSTACK_AS_SERVER
* @return Success or Failure.
* @retval SEOS_SUCCESS or SEOS_ERROR_GENERIC
*
*/

extern int
Seos_NwStack_init(Seos_nw_camkes_info* p);

