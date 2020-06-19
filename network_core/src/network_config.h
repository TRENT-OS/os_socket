/*
 *  OS Network Stack Config Wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Types.h"
#include "OS_Dataport.h"
#include "OS_NetworkStackConf.h"
#include <stddef.h>


const os_camkes_network_stack_config_t* config_get_handlers(void);


//------------------------------------------------------------------------------
// System interface
//------------------------------------------------------------------------------

void wait_network_event(void);

void internal_notify_main_loop(void);
void internal_notify_read(void);
void internal_wait_read(void);
void internal_notify_write(void);
void internal_wait_write(void);
void internal_notify_connection(void);
void internal_wait_connection(void);

void wait_nic_init_done(void);
const OS_Dataport_t* get_nic_port_from(void);
const OS_Dataport_t* get_nic_port_to(void);

OS_Error_t nic_rpc_dev_write(size_t* pLen);
OS_Error_t nic_rpc_get_mac(void);

void notify_app_init_done(void);
const OS_Dataport_t* get_app_port(void);
