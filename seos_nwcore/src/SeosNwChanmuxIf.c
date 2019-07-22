/*
 *  SEOS Netwrok Stack CAmkES wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosNwStack.h"
#include "SeosNwCommon.h"
#include <string.h>
#include "LibDebug/Debug.h"
#include <stdint.h>
#include <stddef.h>


// run() when you instantiate SeosNwStack component  must call this
int Seos_NwStack_init()
{
    Debug_LOG_INFO("starting network stack...\n");
    int ret;

    ret = NwStack_seos_init();  // should never return as this starts pico_stack_tick().

    if(ret<0)  // is possible when proxy does not run with use_tap =1 param. Just print and exit
    {
        Debug_LOG_INFO("Network Stack Init() Failed...Exiting NwStack\n");
    }
    return 0;
}

/* Function to send ctrl cmds.
 *
 * Ctrl cmds will always fit within PAGE_SIZE.
 *
 */
size_t
NwCamkes_chanWriteSyncCtrl(
        const void*   buf,
        size_t        len)
{
    size_t written = 0;

    len = len < PAGE_SIZE ? len : PAGE_SIZE;
    // copy in the ctrl dataport
    memcpy(chanMuxCtrlDataPort, buf,len);
    // tell the other side how much data we want to send and in which channel
    seos_err_t err = ChanMux_write(CHANNEL_NW_STACK_CTRL, len, &written);
    Debug_ASSERT_PRINTFLN(!err, "seos err %d", err);

    return written;
}

/* Function to send NW data.
 *
 * Data may not fit within PAGE_SIZE. Hence loop if required until all data is sent
 * w_size finally contains how many actually bytes were written.
 */
size_t
NwCamkes_chanWriteSyncData(
    const void*   buf,
    size_t        len)
{
    size_t written = 0;
    size_t remain_len = len;
    size_t w_size=0;

    while(len > 0)    // loop to send all data if > PAGE_SIZE = 4096
    {
        len = len < PAGE_SIZE ? len : PAGE_SIZE;
        // copy in the normal dataport
        memcpy(chanMuxDataPort, buf+w_size, len);
        // tell the other side how much data we want to send and in which channel
        seos_err_t err = ChanMux_write(CHANNEL_NW_STACK_DATA, len, &written);
        Debug_ASSERT_PRINTFLN(!err, "seos err %d", err);
        w_size=+written;
        len=remain_len-w_size;
        if(err <0)
        {
            Debug_LOG_INFO("error in writing, err= %d\n", err);
            break;
        }
    }
    return w_size;
}

size_t
NwCamkes_chanRead(
    unsigned int  chan,
    void*         buf,
    size_t        len)
{
    size_t read = 0;
    seos_err_t err = ChanMux_read(chan, len, &read);
    Debug_ASSERT_PRINTFLN(!err, "seos err %d", err);

    if (read)
    {
       // Debug_ASSERT(read <= len);
        if(chan ==CHANNEL_NW_STACK_DATA)
        {
            memcpy(buf, chanMuxDataPort, read);
        }
        else   // it is control data
        {
            memcpy(buf, chanMuxCtrlDataPort, read);
        }
    }
    return read;
}


size_t
NwCamkes_chanReadBlocking (
    unsigned int  chan,
    char*         buf,
    size_t        len)
{
    size_t lenRead = 0;

    while (lenRead < len)
    {
        // Non-blocking read.
        size_t read = NwCamkes_chanRead(chan,
                               &buf[lenRead],
                               len - lenRead);
        if (0 == read)
        {
            c_nwstacktick_wait();
        }
        else
        {
            lenRead += read;
        }
    }
    return lenRead;

}
