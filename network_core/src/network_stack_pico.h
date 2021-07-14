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
    int domain,
    int socket_type,
    int* pHandle);

OS_Error_t
network_stack_pico_socket_close(
    int handle);

OS_Error_t
network_stack_pico_socket_connect(
    int handle,
    const OS_NetworkSocket_Addr_t* dstAddr);

OS_Error_t
network_stack_pico_socket_bind(
    int handle,
    const OS_NetworkSocket_Addr_t* localAddr);

OS_Error_t
network_stack_pico_socket_listen(
    int handle,
    int backlog);

OS_Error_t
network_stack_pico_socket_accept(
    int handle,
    int* pClient_handle,
    OS_NetworkSocket_Addr_t* srcAddr);

OS_Error_t
network_stack_pico_socket_write(
    int handle,
    size_t* pLen);

OS_Error_t
network_stack_pico_socket_read(
    int handle,
    size_t* pLen);

OS_Error_t
network_stack_pico_socket_sendto(
    int handle,
    size_t* pLen,
    const OS_NetworkSocket_Addr_t* dstAddr);

OS_Error_t
network_stack_pico_socket_recvfrom(
    int handle,
    size_t* pLen,
    OS_NetworkSocket_Addr_t* srcAddr);
