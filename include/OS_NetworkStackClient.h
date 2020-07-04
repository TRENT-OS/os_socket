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
    int                        domain,
    int                        type,
    OS_NetworkSocket_Handle_t* pHandle);

OS_Error_t
network_stack_rpc_socket_accept(
    OS_NetworkSocket_Handle_t  handle,
    OS_NetworkSocket_Handle_t* pHandleClient,
    uint16_t                   port);

OS_Error_t
network_stack_rpc_socket_bind(
    OS_NetworkSocket_Handle_t handle,
    uint16_t                  port);

OS_Error_t
network_stack_rpc_socket_listen(
    OS_NetworkSocket_Handle_t handle,
    int                       backlog);

OS_Error_t
network_stack_rpc_socket_connect(
    OS_NetworkSocket_Handle_t handle,
    const char*               name,
    uint16_t                  port);

OS_Error_t
network_stack_rpc_socket_close(
    OS_NetworkSocket_Handle_t handle);

OS_Error_t
network_stack_rpc_socket_write(
    OS_NetworkSocket_Handle_t handle,
    size_t* pLen);

OS_Error_t
network_stack_rpc_socket_read(
    OS_NetworkSocket_Handle_t handle,
    size_t* pLen);

OS_Error_t
network_stack_rpc_socket_recvfrom(
    OS_NetworkSocket_Handle_t handle,
    size_t*                   plen,
    OS_Network_Socket_t*      src_socket);

OS_Error_t
network_stack_rpc_socket_sendto(
    OS_NetworkSocket_Handle_t handle,
    size_t*                   pLen,
    OS_Network_Socket_t       dst_socket);

// TODO: Remove init_done_event
extern void event_network_stack_init_done_wait(void);
