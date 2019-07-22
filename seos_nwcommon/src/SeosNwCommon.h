#pragma once
//#include "uart_socket_guest_rpc_conventions.h"

#include "ChanMux_config.h"
#include "seos_err.h"


#include <stdint.h>
#include <stddef.h>
#include <limits.h>
/* Map cmds with uart as this is used by proxy */

typedef enum
{
    NW_CTRL_CMD_OPEN       =  0,   //UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_OPEN,
    NW_CTRL_CMD_OPEN_CNF   =  1,   // UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_OPEN_CNF,
    NW_CTRL_CMD_CLOSE      =  2,   //UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_CLOSE,
    NW_CTRL_CMD_CLOSE_CNF  =  3,   // UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_CLOSE_CNF,
    NW_CTRL_CMD_GETMAC     =  4,  //UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_GETMAC,
    NW_CTRL_CMD_GETMAC_CNF =  5  //UART_SOCKET_GUEST_CONTROL_SOCKET_COMMAND_GETMAC_CNF
} NwCtrlCommand;


/* MACRO's */
#define VALIDATE_NULL(param) \
    if(!param) \
    { \
        return -1; \
    }

#define VALIDATE_ONE(param,value) \
    if(param != value) { \
        pico_err = PICO_ERR_EINVAL; \
        return -1; \
    }

#define VALIDATE_TWO(param,value1,value2) \
    if(param != value1 && param != value2) { \
        pico_err = PICO_ERR_EINVAL; \
        return -1; \
    }

/* Camkes external components */
extern void* NwAppDataPort;
extern void* chanMuxDataPort;
extern void* chanMuxCtrlDataPort;

extern int e_write_emit();
extern int c_write_wait();
extern int e_read_emit();
extern int c_read_wait();

extern int e_write_nwstacktick_emit();
extern int e_initdone_emit();
extern int c_nwstacktick_wait();

extern int ChanMux_write();
extern int ChanMux_read();

