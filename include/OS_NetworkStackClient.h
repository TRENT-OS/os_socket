#pragma once

#include "OS_Dataport.h"

typedef struct
{
    OS_Dataport_t* dataport;
    int number_of_sockets;
} OS_NetworkStackClient_SocketDataports_t;

OS_Error_t
OS_NetworkStackClient_init(
    OS_NetworkStackClient_SocketDataports_t* config);

//------------------------------------------------------------------------------
// RPC API, prefix "network_stack_rpc" comes from CAmkES RPC, the rest from the
// interface method list.
//------------------------------------------------------------------------------
OS_Error_t
network_stack_rpc_socket_create(
    unsigned int domain,
    unsigned int type,
    unsigned int* pHandle);

OS_Error_t
network_stack_rpc_socket_accept(
    unsigned int handle,
    unsigned int* pHandleClient,
    uint16_t port);

OS_Error_t
network_stack_rpc_socket_bind(
    unsigned int handle,
    uint16_t port);

OS_Error_t
network_stack_rpc_socket_listen(
    unsigned int handle,
    unsigned int backlog);

OS_Error_t
network_stack_rpc_socket_connect(
    unsigned int handle,
    const char* name,
    uint16_t port);

OS_Error_t
network_stack_rpc_socket_close(
    unsigned int handle);

OS_Error_t
network_stack_rpc_socket_write(
    unsigned int handle,
    size_t* pLen);

OS_Error_t
network_stack_rpc_socket_read(
    unsigned int handle,
    size_t* pLen);

OS_Error_t
network_stack_rpc_socket_recvfrom(
    unsigned int handle,
    size_t* plen,
    OS_Network_Socket_t* src_socket);

OS_Error_t
network_stack_rpc_socket_sendto(
    unsigned int handle,
    size_t* pLen,
    OS_Network_Socket_t dst_socket);

// TODO: Remove init_done_event
extern void event_network_stack_init_done_wait(void);
