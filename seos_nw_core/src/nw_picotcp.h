/*
 *  SEOS Network Stack PicoTCP Glue Layer
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_socket.h"
#include "pico_device.h"
#include <stdlib.h>
#include <stdint.h>


typedef struct
{
    struct pico_socket* (*nw_socket_open)(uint16_t net,
                                          uint16_t proto,              /**< is pico_socket_open() */
                                          void (*wakeup)(uint16_t ev, struct pico_socket* s));
    int (*nw_socket_read)(struct pico_socket* s, void* buf,
                          int len);               /**< is pico_socket_read() */
    int (*nw_socket_write)(struct pico_socket* s, const void* buf,
                           int len);        /**< is pico_socket_write() */
    int (*nw_socket_connect)(struct pico_socket* s,
                             const void* srv_addr,           /**< is pico_socket_connect() */
                             uint16_t remote_port);
    int (*nw_socket_bind)(struct pico_socket* s, void* local_addr,
                          uint16_t* port); /**< is pico_socket_bind() */
    int (*nw_socket_listen)(struct pico_socket* s,
                            int backlog);                    /**< is pico_socket_listen() */
    struct pico_socket* (*nw_socket_accept)(struct pico_socket* s,
                                            void* orig,      /**< is pico_socket_accept() */
                                            uint16_t* local_port);
    int (*nw_socket_close)(struct pico_socket*
                           s);                                  /**< is pico_socket_close() */
    int (*nw_socket_setoption)(struct pico_socket* s, int option,
                               void* value);     /**< is pico_socket_setoption() */
} seos_nw_api_vtable;


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
