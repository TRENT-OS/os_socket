/*
 *  SEOS Network Stack Config Wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */


#include "seos_types.h"
#include "LibDebug/Debug.h"
#include "seos_api_network_stack.h"
#include "nw_config.h"
#include <stddef.h>



//------------------------------------------------------------------------------
void
wait_network_event(void)
{
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

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
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

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
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

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
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

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
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

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
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

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
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

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
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

    event_wait_func_t do_wait = handlers->internal.wait_connection;
    if (!do_wait)
    {
        Debug_LOG_WARNING("internal.wait_connection not set");
        return;
    }

    do_wait();
}


//------------------------------------------------------------------------------
const seos_shared_buffer_t*
get_nic_port_from(void)
{
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

    // network stack -> driver (aka output)
    const seos_shared_buffer_t* port = &(handlers->drv_nic.from);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->buffer );
    Debug_ASSERT( 0 != port->len );

    return port;
}


//------------------------------------------------------------------------------
const seos_shared_buffer_t*
get_nic_port_to(void)
{
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

    // driver -> network stack (aka input)
    const seos_shared_buffer_t* port = &(handlers->drv_nic.to);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->buffer );
    Debug_ASSERT( 0 != port->len );

    return port;
}


//------------------------------------------------------------------------------
seos_err_t
nic_rpc_dev_write(
    size_t* pLen)
{
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

    Debug_ASSERT( NULL != handlers->drv_nic.rpc.dev_write );

    return handlers->drv_nic.rpc.dev_write(pLen);
}


//------------------------------------------------------------------------------
seos_err_t
nic_rpc_get_mac(void)
{
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

    Debug_ASSERT( NULL != handlers->drv_nic.rpc.get_mac );

    return handlers->drv_nic.rpc.get_mac();
}


//------------------------------------------------------------------------------
void
notify_app_init_done(void)
{
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

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
const seos_shared_buffer_t*
get_app_port(void)
{
    const seos_camkes_network_stack_config_t* handlers = config_get_handlers();

    // network stack -> driver (aka output)
    const seos_shared_buffer_t* port = &(handlers->app.port);

    Debug_ASSERT( NULL != port );
    Debug_ASSERT( NULL != port->buffer );
    Debug_ASSERT( 0 != port->len );

    return port;
}
