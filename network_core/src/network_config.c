/*
 * OS Network Stack Config Wrapper
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "OS_Types.h"
#include "OS_Dataport.h"
#include "lib_debug/Debug.h"
#include "OS_NetworkStack.h"
#include "network_config.h"
#include "network_stack_core.h"
#include <stddef.h>

//------------------------------------------------------------------------------
void
wait_network_event(void)
{
    Debug_LOG_TRACE("wait_network_event for handle");

    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    event_wait_func_t do_wait = handlers->wait_loop_event;
    if (!do_wait)
    {
        Debug_LOG_WARNING("wait_loop_event not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
void
internal_notify_main_loop(void)
{
    Debug_LOG_TRACE("internal_notify_main_loop for handle");

    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    event_notify_func_t do_notify = handlers->internal.notify_loop;
    if (!do_notify)
    {
        Debug_LOG_WARNING("internal.notify_main_loop not set");
        return;
    }

    do_notify();
}


//------------------------------------------------------------------------------
const OS_Dataport_t*
get_nic_port_from(void)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    // network stack -> driver (aka output)
    const OS_Dataport_t* port = &(handlers->drv_nic.from);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->io );
    Debug_ASSERT( 0 != port->size );

    return port;
}


//------------------------------------------------------------------------------
const OS_Dataport_t*
get_nic_port_to(void)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    // driver -> network stack (aka input)
    const OS_Dataport_t* port = &(handlers->drv_nic.to);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->io );
    Debug_ASSERT( 0 != port->size );

    return port;
}

//------------------------------------------------------------------------------
OS_Error_t
nic_dev_read(
    size_t* pLen,
    size_t* frameRemaining)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    Debug_ASSERT( NULL != handlers->drv_nic.rpc.dev_read );

    return handlers->drv_nic.rpc.dev_read(pLen, frameRemaining);
}


//------------------------------------------------------------------------------
OS_Error_t
nic_dev_write(
    size_t* pLen)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    Debug_ASSERT( NULL != handlers->drv_nic.rpc.dev_write );

    return handlers->drv_nic.rpc.dev_write(pLen);
}


//------------------------------------------------------------------------------
OS_Error_t
nic_dev_get_mac_address(void)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    Debug_ASSERT( NULL != handlers->drv_nic.rpc.get_mac );

    return handlers->drv_nic.rpc.get_mac();
}


//------------------------------------------------------------------------------
void
internal_socket_control_block_mutex_lock(void)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    mutex_lock_func_t lock_mutex = handlers->internal.socketCB_lock;
    if (!lock_mutex)
    {
        Debug_LOG_WARNING("socket_control_block_mutex_lock not set");
        return;
    }

    Debug_LOG_TRACE("%s", __func__);
    lock_mutex();
}

//------------------------------------------------------------------------------
void internal_socket_control_block_mutex_unlock(void)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    mutex_unlock_func_t unlock_mutex = handlers->internal.socketCB_unlock;
    if (!unlock_mutex)
    {
        Debug_LOG_WARNING("socket_control_block_mutex_unlock not set");
        return;
    }

    Debug_LOG_TRACE("%s", __func__);
    unlock_mutex();
}

//------------------------------------------------------------------------------
void internal_network_stack_thread_safety_mutex_lock(void)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    mutex_lock_func_t lock_mutex = handlers->internal.stackTS_lock;
    if (!lock_mutex)
    {
        Debug_LOG_WARNING("socket_thread_safety_mutex_lock not set");
        return;
    }

    Debug_LOG_TRACE("%s", __func__);
    lock_mutex();
}

//------------------------------------------------------------------------------
void internal_network_stack_thread_safety_mutex_unlock(void)
{
    const OS_NetworkStack_CamkesConfig_t* handlers = config_get_handlers();

    mutex_unlock_func_t unlock_mutex = handlers->internal.stackTS_unlock;
    if (!unlock_mutex)
    {
        Debug_LOG_WARNING("socket_thread_safety_mutex_unlock not set");
        return;
    }

    Debug_LOG_TRACE("%s", __func__);
    unlock_mutex();
}
