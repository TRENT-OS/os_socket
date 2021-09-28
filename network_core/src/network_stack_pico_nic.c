/*
 * OS Network Stack
 *
 * NIC level functions for the PicoTCP implementation of the network stack.
 *
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
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
    if (OS_Dataport_getSize(*nic_in) < len)
    {
        Debug_LOG_ERROR("Buffer doesn't fit in dataport");
        return -1;
    }

    // copy data into shared buffer and call driver
    memcpy(wrbuf, buf, len);
    size_t wr_len = len;
    OS_Error_t err = nic_dev_write(&wr_len);

    if (OS_SUCCESS != err)
    {
        switch (err)
        {
        case OS_ERROR_TRY_AGAIN:
            Debug_LOG_WARNING("Send frame couldn't complete. Retrying");
            // returning 0 tells picoTCP to retry sending the current frame
            return 0;

        case OS_ERROR_INVALID_PARAMETER:
            Debug_LOG_ERROR("Invalid frame size");
            return -1;

        case OS_ERROR_NOT_INITIALIZED:
            Debug_LOG_ERROR("NIC not initialized");
            return -1;

        default:
            break;
        }

        Debug_LOG_ERROR("nic_dev_write() failed, wr_len %zu, error %d",
                        wr_len, err);
        return -1;
    }

    // sending was successful, do a sanity check that the whole frame was sent.
    if (wr_len != len)
    {
        // this should not happen, maybe the frame is corrupt?
        Debug_LOG_ERROR("unexpected mismatch: len %d, wr_len %zu", len, wr_len);
        Debug_DUMP_ERROR(buf, len);
        Debug_ASSERT(0); // halt in debug builds
    }

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
    Debug_ASSERT(&os_nic == dev);

    static bool isLegacyInterface = false;
    static bool isDetectionDone   = false;

    const OS_Dataport_t*        nw_in = get_nic_port_from();
    OS_NetworkStack_RxBuffer_t* buf_ptr =
        (OS_NetworkStack_RxBuffer_t*)OS_Dataport_getBuf(*nw_in);

    if (isLegacyInterface == false)
    {
        size_t len;
        size_t framesRemaining = 1;

        while (loop_score > 0 && framesRemaining)
        {
            OS_Error_t status = nic_dev_read(&len, &framesRemaining);
            // if the return code is NOT_IMPLEMENTED it means the driver implements
            // the event based interface
            if (status != OS_SUCCESS)
            {
                if (status == OS_ERROR_NOT_IMPLEMENTED)
                {
                    if (isDetectionDone == true)
                    {
                        // There is no return value we can give here which signals to the
                        // picotcp stack that an error ocurred. The loop value we return
                        // here is fed to a LSFR to generate randomness.
                        // Since this error should never happen we consider it fatal and stop
                        // execution here.
                        Debug_LOG_ERROR("Fatal error: RPC call returned not implemented.");
                        exit(0);
                    }
                    isLegacyInterface = true;
                    isDetectionDone   = true;
                    Debug_LOG_INFO("Falling back to legacy interface.");
                    break;
                }
                if (status == OS_ERROR_NOT_INITIALIZED)
                {
                    // Driver didn't finish initialization. Try again later.
                    Debug_LOG_DEBUG("Nic not initialized. Retrying");
                    break;
                }
                if (status == OS_ERROR_NO_DATA)
                {
                    Debug_LOG_DEBUG("No data to be read");
                    break;
                }
            }

            Debug_LOG_TRACE("incoming frame len %zu", len);
            pico_stack_recv(dev, (void*)buf_ptr, len);
            loop_score--;
            isDetectionDone = true;
        }

        if (loop_score == 0 && framesRemaining)
        {
            internal_notify_main_loop();
            Debug_LOG_TRACE("Loop score is 0 but there is still data in the NIC");
        }

    }
    if (isLegacyInterface == true)
    {
        static unsigned int pos = 0;
        // loop_score indicates max number of frames that can be processed during
        // the invocation of this poll.
        if (loop_score > 0)
        {
            unsigned int ring_buffer_size = nw_in->size;
            // As long as the loop score permits, take the next frame stored in the
            // ring buffer.
            while (buf_ptr[pos].len != 0 && loop_score > 0)
            {
                Debug_LOG_TRACE("incoming frame len %zu", buf_ptr[pos].len);
                pico_stack_recv(dev, buf_ptr[pos].data, buf_ptr[pos].len);
                loop_score--;
                // set flag in shared memory that data has been read
                buf_ptr[pos].len = 0;

                pos = (pos + 1) % ring_buffer_size;
            }
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
    OS_Error_t err = nic_dev_get_mac_address();
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("nic_dev_get_mac_address() failed, error %d", err);
        nic_destroy(dev);
        return OS_ERROR_GENERIC;
    }

    const OS_Dataport_t* nw_in = get_nic_port_from();
    OS_NetworkStack_RxBuffer_t* nw_rx = (OS_NetworkStack_RxBuffer_t*)
                                        OS_Dataport_getBuf(*nw_in);
    uint8_t* mac = nw_rx->data;

    Debug_LOG_INFO("MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );

    static const char* drv_name  = "trentos_nic_driver";
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
