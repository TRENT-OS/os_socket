/*
 * OS Network Stack
 *
 * The PicoTCP implementation of the TRENTOS-M Network Stack.
 *
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Network.h"
#include "network/OS_Network_types.h"
#include "network_config.h"
#include <stdint.h>
#include <stdlib.h>

network_stack_interface_t
network_stack_pico_get_config(void);

OS_Error_t
network_stack_pico_socket_create(
    const int domain,
    const int socket_type,
    int* const pHandle,
    const int  clientId,
    void*      buffer,
    const int  buffer_size);

OS_Error_t
network_stack_pico_socket_close(
    const int handle,
    const int clientId);

OS_Error_t
network_stack_pico_socket_connect(
    const int handle,
    const OS_NetworkSocket_Addr_t* const dstAddr);

OS_Error_t
network_stack_pico_socket_bind(
    const int handle,
    const OS_NetworkSocket_Addr_t* const localAddr);

OS_Error_t
network_stack_pico_socket_listen(
    const int handle,
    const int backlog);

OS_Error_t
network_stack_pico_socket_accept(
    const int handle,
    int* const pClient_handle,
    OS_NetworkSocket_Addr_t* const srcAddr);

OS_Error_t
network_stack_pico_socket_write(
    const int handle,
    size_t* const pLen);

OS_Error_t
network_stack_pico_socket_read(
    const int handle,
    size_t* const pLen);

OS_Error_t
network_stack_pico_socket_sendto(
    const int handle,
    size_t* const pLen,
    const OS_NetworkSocket_Addr_t* const dstAddr);

OS_Error_t
network_stack_pico_socket_recvfrom(
    const int handle,
    size_t* const pLen,
    OS_NetworkSocket_Addr_t* const srcAddr);

#define PICO_TCP_NAGLE_DISABLE 1
#define PICO_TCP_NAGLE_ENABLE  0

#define PICO_TCP_KEEPALIVE_COUNT         5
#define PICO_TCP_KEEPALIVE_PROBE_TIMEOUT 30000
#define PICO_TCP_KEEPALIVE_RETRY_TIMEOUT 5000
