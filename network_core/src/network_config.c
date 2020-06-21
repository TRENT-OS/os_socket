/*
 *  OS Network Stack Config Wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */


#include "OS_Types.h"
#include "OS_Dataport.h"
#include "LibDebug/Debug.h"
#include "OS_NetworkStackConf.h"
#include "network_config.h"
#include <stddef.h>



//------------------------------------------------------------------------------
void
wait_network_event(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

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
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    event_notify_func_t do_notify = handlers->internal.notify_loop;
    if (!do_notify)
    {
        Debug_LOG_WARNING("internal.notify_main_loop not set");
        return;
    }

    do_notify();
}


//------------------------------------------------------------------------------
void
internal_notify_read(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    event_notify_func_t do_notify = handlers->internal.notify_read;
    if (!do_notify)
    {
        Debug_LOG_WARNING("notify_read not set");
        return;
    }

    do_notify();
}

//------------------------------------------------------------------------------
void
internal_wait_read(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    event_wait_func_t do_wait = handlers->internal.wait_read;
    if (!do_wait)
    {
        Debug_LOG_WARNING("internal.wait_read not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
void
internal_notify_write(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    event_notify_func_t do_notify = handlers->internal.notify_write;
    if (!do_notify)
    {
        Debug_LOG_WARNING("notify_write not set");
        return;
    }

    do_notify();
}


//------------------------------------------------------------------------------
void
internal_wait_write(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    event_wait_func_t do_wait = handlers->internal.wait_write;
    if (!do_wait)
    {
        Debug_LOG_WARNING("internal.wait_write not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
void
internal_notify_connection(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    event_notify_func_t do_notify = handlers->internal.notify_connection;
    if (!do_notify)
    {
        Debug_LOG_WARNING("internal.notify_connection not set");
        return;
    }

    do_notify();
}


//------------------------------------------------------------------------------
void
internal_wait_connection(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    event_wait_func_t do_wait = handlers->internal.wait_connection;
    if (!do_wait)
    {
        Debug_LOG_WARNING("internal.wait_connection not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
const OS_Dataport_t*
get_nic_port_from(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

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
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    // driver -> network stack (aka input)
    const OS_Dataport_t* port = &(handlers->drv_nic.to);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->io );
    Debug_ASSERT( 0 != port->size );

    return port;
}


//------------------------------------------------------------------------------
OS_Error_t
nic_rpc_dev_write(
    size_t* pLen)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    Debug_ASSERT( NULL != handlers->drv_nic.rpc.dev_write );

    return handlers->drv_nic.rpc.dev_write(pLen);
}


//------------------------------------------------------------------------------
OS_Error_t
nic_rpc_get_mac(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    Debug_ASSERT( NULL != handlers->drv_nic.rpc.get_mac );

    return handlers->drv_nic.rpc.get_mac();
}


//------------------------------------------------------------------------------
void
notify_app_init_done(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    event_notify_func_t do_notify = handlers->app.notify_init_done;
    if (!do_notify)
    {
        Debug_LOG_WARNING("app.notify_init_done not set");
        return;
    }

    Debug_LOG_INFO("%s", __func__);
    do_notify();
}


//------------------------------------------------------------------------------
const OS_Dataport_t*
get_app_port(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    // network stack -> driver (aka output)
    const OS_Dataport_t* port = &(handlers->app.port);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->io );
    Debug_ASSERT( 0 != port->size );

    return port;
}


//------------------------------------------------------------------------------
void
internal_socket_control_block_mutex_lock(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    mutex_lock_func_t lock_mutex = handlers->internal.socketCB_lock;
    if (!lock_mutex)
    {
        Debug_LOG_WARNING("socket_control_block_mutex_lock not set");
        return;
    }

    Debug_LOG_INFO("%s", __func__);
    lock_mutex();
}


//------------------------------------------------------------------------------
void internal_socket_control_block_mutex_unlock(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    mutex_unlock_func_t unlock_mutex = handlers->internal.socketCB_unlock;
    if (!unlock_mutex)
    {
        Debug_LOG_WARNING("socket_control_block_mutex_unlock not set");
        return;
    }

    Debug_LOG_INFO("%s", __func__);
    unlock_mutex();
}

//------------------------------------------------------------------------------
void internal_network_stack_thread_safety_mutex_lock(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    mutex_lock_func_t lock_mutex = handlers->internal.stackTS_lock;
    if (!lock_mutex)
    {
        Debug_LOG_WARNING("socket_thread_safety_mutex_lock not set");
        return;
    }

    Debug_LOG_INFO("%s", __func__);
    lock_mutex();
}

//------------------------------------------------------------------------------
void internal_network_stack_thread_safety_mutex_unlock(void)
{
    const os_camkes_network_stack_config_t* handlers = config_get_handlers();

    mutex_unlock_func_t unlock_mutex = handlers->internal.stackTS_unlock;
    if (!unlock_mutex)
    {
        Debug_LOG_WARNING("socket_thread_safety_mutex_unlock not set");
        return;
    }

    Debug_LOG_INFO("%s", __func__);
    unlock_mutex();
}