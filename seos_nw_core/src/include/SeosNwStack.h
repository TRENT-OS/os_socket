/*
 *  SeosNwStack.h
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
*/


/**
 * @defgroup SeosNWStack SEOS Core Nwstack
 * @file SeosNwStack.h
 *
 * @brief Core Network stack.This layer mostly interacts with PicoTCP. \n
 *        PicoTCP being the network protocol stack.
 *        This layer mostly supports all the socket related operations.
 *
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
    struct pico_socket* socket;     /**< represents an opened socket in the stack */
    const    seos_nw_api_vtable*
    vtable; /**< pointer to nw_api_vtable to call pico functions*/
    struct   pico_ip4 ip_addr;      /**< IP addr assigned to tap devices  */
    struct   pico_ip4 bind_ip_addr; /**<  bind ip addr */
    struct   pico_socket*
        client_socket; /**< represents a connected socket when the Nw Stack is configured as server*/
    int      listen_port; /**< listen port for server to listen */
    int      event;       /**< Pico Internal event representing current state of connected socket */
    int      read;        /**< Has read len */
    int      socket_fd;   /**< defined but not used */
    uint8_t  in_use;      /**< defined but not used */
} SeosNwstack;


/**
 * @brief   seos_nw_camkes_signal_glue contains emitter and consumer signals inside the stack

 * @ingroup SeosNWStack
*/


typedef struct
{
    void (*e_write_emit)(); /**< emit and unblock write  */
    void (*c_write_wait)(); /**< block on write  */
    void (*e_read_emit)();  /**< emit and unblock read  */
    void (*c_read_wait)();  /**< block on read  */
    void (*e_conn_emit)();  /**< emit and unblock connect */
    void (*c_conn_wait)();  /**< block on connect */
    void (*e_write_nwstacktick)(); /**< emit and unblock pico tick */
    void (*c_nwstacktick_wait)();  /**< block for pico tick */
    void (*e_initdone)();         /**< unblock nw stack init  */
    void (*c_initdone)();         /**< block nw stack init */
} seos_nw_camkes_signal_glue;


/**
 * @brief   seos_nw_ports_glue contains data ports used for data TX and RX

 * @ingroup SeosNWStack
*/
typedef struct
{
    void* nwdriverDataPort;   /**< ChanMux Data port uses Data channel */
    void* Appdataport;       /**< App data port */
} seos_nw_ports_glue;



/**
* @brief   Seos_nw_camkes_info contains reference to the structures
           seos_nw_ports_glue and seos_nw_camkes_signal_glue.

* @ingroup SeosNWStack
*/
typedef struct
{
    seos_nw_camkes_signal_glue*
    pCamkesglue; /**< pointer to seos_nw_camkes_signal_glue */
    seos_nw_ports_glue* pportsglu; /**< pointer to seos_nw_ports_glue */
} Seos_nw_camkes_info;


/**
* @brief   seos_nw_config contains network config info
           Seos system must configure the network stack after driver init

* @ingroup SeosNWStack
*/
typedef struct
{
    char* dev_addr; /**< pointer to device address e.g. tap0, tap1 */
    char* gateway_addr; /**< pointer to gateway addr */
    char* subnet_mask; /**< pointer to subnet mask */
    void (*driver_create_device)(void* dev, size_t size_of_dev, uint8_t* _mac); /**< pointer to driver
                                                Callback e.g tap create device */
} seos_nw_config;

/**
* @details %Seos_NwStack_init, instanciates a Network Stack. This is called before any app starts using
            using Network stack. As of now two instances are created. One for Client and other for
            Server. This sets up all the initial environment with necessary CamkES signals, dataport
            used etc. Once this is completed, it enters an infinite loop to process Pico ticks.

* @ingroup SeosNWStack
*
* @param Seos_nw_camkes_info:  Structure containing Camkes signals used, ports used and instance ID

* @return Success or Failure.
* @retval SEOS_SUCCESS or SEOS_ERROR_GENERIC
*
*/

extern int
Seos_NwStack_init(Seos_nw_camkes_info* p, seos_nw_config* nwConfig);
