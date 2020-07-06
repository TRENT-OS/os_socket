/*
 *  OS Network Stack
 *
 *  NIC level functions for the PicoTCP implementation of the network stack.
 *
 *  Copyright (C) 2020, Hensoldt Cyber GmbH
 */
#include <stddef.h>
#include <stdlib.h>

#include "OS_Network.h"
#include "OS_Types.h"
#include "network_config.h"
#include "network/OS_NetworkStack.h"
#include "pico_device.h"
#include "pico_stack.h"


// currently we support only one NIC
static struct pico_device os_nic;

//------------------------------------------------------------------------------
// Called by PicoTCP to send one frame
static int
nic_send_frame(
    struct pico_device*  dev,
    void*                buf,
    int                  len)
{
    // currently we support only one NIC
    Debug_ASSERT( &os_nic == dev );

    const OS_Dataport_t* nic_in = get_nic_port_to();
    void* wrbuf = OS_Dataport_getBuf(*nic_in);

    if (OS_Dataport_getSize(*nic_in) < len )
    {
        Debug_LOG_ERROR("Buffer doesn't fit in dataport");
        return -1;
    }

    // copy data it into shared buffer
    size_t wr_len = len;
    memcpy(wrbuf, buf, wr_len);
    // call driver
    OS_Error_t err = nic_rpc_dev_write(&wr_len);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("nic_rpc_dev_write() failed, error %d", err);
        return -1;
    }

    Debug_ASSERT( wr_len == len );

    return len;
}


//------------------------------------------------------------------------------
// Called after notification from driver and regularly from PicoTCP stack tick
static int
nic_poll_data(
    struct pico_device*  dev,
    int                  loop_score)
{
    // currently we support only one NIC
    Debug_ASSERT( &os_nic == dev );

    // loop_score indicates max number of frames that can be processed during
    // the invocation of this poll. Since we still lack the concept of frames
    // in the shared memory, we can't do much here. Pretend there is one
    // frame in the buffer and give it to PicoTCP
    if (loop_score > 0)
    {
        const OS_Dataport_t* nw_in = get_nic_port_from();
        OS_NetworkStack_RxBuffer_t* nw_rx = (OS_NetworkStack_RxBuffer_t*)
                                            OS_Dataport_getBuf(*nw_in);

        size_t len = nw_rx->len;
        if (len > 0)
        {
            Debug_LOG_DEBUG("incoming frame len %zu", len);
            loop_score--;
            pico_stack_recv(dev, nw_rx->data, (uint32_t)len);

            // set flag in shared memory that data has been read
            nw_rx->len = 0;
        }
    }
    return loop_score;
}


//------------------------------------------------------------------------------
static void
nic_destroy(
    struct pico_device* dev)
{
    // currently we support only one NIC
    Debug_ASSERT( &os_nic == dev );

    memset(dev, 0, sizeof(*dev));
}


//------------------------------------------------------------------------------
OS_Error_t
pico_nic_initialize(const OS_NetworkStack_AddressConfig_t* config)
{
    // currently we support only one NIC
    struct pico_device* dev = &os_nic;

    memset(dev, 0, sizeof(*dev));

    dev->send    = nic_send_frame;
    dev->poll    = nic_poll_data;
    dev->destroy = nic_destroy;

    //---------------------------------------------------------------
    // get MAC from NIC driver
    OS_Error_t err = nic_rpc_get_mac();
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("nic_rpc_get_mac() failed, error %d", err);
        nic_destroy(dev);
        return OS_ERROR_GENERIC;
    }

    const OS_Dataport_t* nw_in = get_nic_port_from();
    OS_NetworkStack_RxBuffer_t* nw_rx = (OS_NetworkStack_RxBuffer_t*)
                                        OS_Dataport_getBuf(*nw_in);
    uint8_t* mac = nw_rx->data;

    Debug_LOG_INFO("MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );

    static const char* drv_name  = "tapdriver";
    int ret = pico_device_init(dev, drv_name, mac);
    if (ret != 0)
    {
        Debug_LOG_ERROR("pico_device_init() failed, error %d", ret);
        nic_destroy(dev);
        return OS_ERROR_GENERIC;
    }

    Debug_LOG_INFO("PicoTCP Device created: %s", drv_name);

    //---------------------------------------------------------------
    // assign IPv4 configuration

    struct pico_ip4 ipaddr;
    pico_string_to_ipv4(config->dev_addr, &ipaddr.addr);

    struct pico_ip4 netmask;
    pico_string_to_ipv4(config->subnet_mask, &netmask.addr);

    // assign IP address and netmask
    pico_ipv4_link_add(dev, ipaddr, netmask);


    struct pico_ip4 gateway;
    pico_string_to_ipv4(config->gateway_addr, &gateway.addr);

    // add default route via gateway
    const struct pico_ip4 ZERO_IP4 = { 0 };
    (void)pico_ipv4_route_add(ZERO_IP4, ZERO_IP4, gateway, 1, NULL);

    return OS_SUCCESS;
}