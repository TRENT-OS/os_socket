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
    struct pico_socket* (*socket_open)(
        uint16_t  net,
        uint16_t  proto,
        void (*wakeup)(
            uint16_t ev,
            struct pico_socket* s));

    int (*socket_read)(
        struct pico_socket*  s,
        void*                buf,
        int                  len);

    int (*socket_write)(
        struct pico_socket*  s,
        const void*          buf,
        int                  len);

    int (*socket_connect)(
        struct pico_socket*  s,
        const void*          srv_addr,
        uint16_t             remote_port);

    int (*socket_bind)(
        struct pico_socket*  s,
        void*                local_addr,
        uint16_t*            port);

    int (*socket_listen)(
        struct pico_socket*  s,
        int                  backlog);

    struct pico_socket* (*socket_accept)(
        struct pico_socket*  s,
        void*                orig,
        uint16_t*            local_port);

    int (*socket_close)(
        struct pico_socket*  s);

    int (*socket_setoption)(
        struct pico_socket*  s,
        int                  option,
        void*                value);
} picotcp_api_vtable_t;


// Abstraction of PicoTCP API
static const picotcp_api_vtable_t picotcp_funcs =
{
    .socket_open       =  pico_socket_open,
    .socket_read       =  pico_socket_read,
    .socket_write      =  pico_socket_write,
    .socket_connect    =  pico_socket_connect,
    .socket_bind       =  pico_socket_bind,
    .socket_listen     =  pico_socket_listen,
    .socket_accept     =  pico_socket_accept,
    .socket_close      =  pico_socket_close,
    .socket_setoption  =  pico_socket_setoption
};
