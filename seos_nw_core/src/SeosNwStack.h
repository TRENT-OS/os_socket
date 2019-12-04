/*
 *  SEOS Network Stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "SeosError.h"
#include <stdlib.h>
#include <stdint.h>


/*****************************/
/*        PICO API           */
/*****************************/

/**
 * @brief   seos_nw_api_vtable contains function pointers to picotcp api
 * @ingroup SeosNWStack

*/
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



/**
 * @brief   SeosNwstack contains elements representing the stack.
            Some of them defined and not used will be required for future.

 * @ingroup SeosNWStack

*/

typedef struct
{
    const seos_camkes_network_stack_config_t*  camkes_cfg;
    const seos_network_stack_config_t*         cfg;
    const seos_nw_api_vtable*                  vtable; /**< PicoTCP functions */

    struct pico_device         seos_dev;
    struct pico_ip4            ip_addr;
    // As of now there is only one app per network stack and there is also only
    // one socket. Hence one global variable can be used which represents the
    // network stack
    struct pico_socket*
        socket; /**< represents an opened socket in the stack */
    struct pico_ip4            bind_ip_addr; /**<  bind ip addr */
    struct pico_socket*
        client_socket; /**< represents a connected socket when the Nw Stack is configured as server*/
    int                        listen_port; /**< listen port for server to listen */
    int
    event; /**< Pico Internal event representing current state of connected socket */
    int                        read; /**< Has read len */
    int                        in_use;
    int                        socket_fd; /**< socket handle */
} network_stack_t;



struct pico_device*
seos_network_device_create(void);
