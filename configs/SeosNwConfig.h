/*
 *  SeosNwConfig.h
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *  A basic configuration file for Network Stack.
*/
#pragma once

#define SEOS_TAP0_ADDR          "192.168.82.91"
#define SEOS_TAP1_ADDR          "192.168.82.92"
#define SEOS_SUBNET_MASK        "255.255.255.0"
#define SEOS_GATEWAY_ADDR       "192.168.82.1"
#define SEOS_CLOUD_ADDR         "51.144.118.31"

/* Temporarily include this file from driver due to driver tap create API call.
 * Need to remove it when we move out the SeosNwConfig to SEOS-system
 */
#include "Seos_pico_dev_chan_mux.h"

//------------------------------------------------------------------------------
static seos_err_t
network_config_init(
    Seos_nw_camkes_info*        nw_camkes,
    SeosNwstack*                seos_nw,
    const seos_nw_api_vtable*   nw_api_if)
{

    struct pico_ip4 ipaddr;
    struct pico_device* dev;

    if (nw_camkes->instanceID == SEOS_NWSTACK_AS_CLIENT)
    {
        dev = pico_chan_mux_tap_create("tap0"); //create tap0 device
        pico_string_to_ipv4(SEOS_TAP0_ADDR, &ipaddr.addr);
    }
    else
    {
        dev = pico_chan_mux_tap_create("tap1"); //create tap1 device
        pico_string_to_ipv4(SEOS_TAP1_ADDR, &ipaddr.addr);
    }

    if (!dev)
    {
        Debug_LOG_INFO("Error creating tap device");
        return SEOS_ERROR_GENERIC;
    }

    // create IPv4 interface wih address and netmask
    struct pico_ip4 netmask;
    pico_string_to_ipv4(SEOS_SUBNET_MASK, &netmask.addr);
    pico_ipv4_link_add(dev, ipaddr, netmask);

    const struct pico_ip4 ZERO_IP4 = { 0 };

    // add default route via gateway
    struct pico_ip4 gateway;
    pico_string_to_ipv4(SEOS_GATEWAY_ADDR, &gateway.addr);
    (void)pico_ipv4_route_add(ZERO_IP4, ZERO_IP4, gateway, 1, NULL);

    // add route to cloud server - do we really need this given there is a
    // default gateway?
    struct pico_ip4 dst;
    pico_string_to_ipv4(SEOS_CLOUD_ADDR, &dst.addr);
    int route = pico_ipv4_route_add(dst, ZERO_IP4, gateway, 1, NULL);
    // check route to cloud server
    struct pico_ip4 check_gateway = pico_ipv4_route_get_gateway(&dst);
    Debug_LOG_INFO("gateway address dst=%x and route=%d",
                   check_gateway.addr, route);


    // setup network stack
    seos_nw->ip_addr = ipaddr;
    seos_nw->vtable = nw_api_if;
    seos_nw->in_use = 1; // Required for multi threading

    // notify app after that network stack is initialized
    nw_camkes->pCamkesglue->e_initdone();

    // enter endles loop processing events
    for (;;)
    {
        // wait for event (write, read or 1 sec timeout)
        nw_camkes->pCamkesglue->c_nwstacktick_wait();
        // let PicoTCP process the event
        pico_stack_tick();
    }

    Debug_LOG_FATAL("tick loop terminated");
    return SEOS_ERROR_GENERIC;
}
