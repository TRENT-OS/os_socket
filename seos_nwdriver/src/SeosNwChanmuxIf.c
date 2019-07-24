/*
 *  SEOS Network Stack ChanMux wrapper driver Interface. This interacts with Chanmux for write/read
 *
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


/* Function to send ctrl cmds.
 *
 * Ctrl cmds will always fit within PAGE_SIZE.
 *
 */
size_t
NwChanmux_chanWriteSyncCtrl(
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
NwChanmux_chanWriteSyncData(
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
NwChanmux_chanRead(
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
NwChanmux_chanReadBlocking (
    unsigned int  chan,
    char*         buf,
    size_t        len)
{
    size_t lenRead = 0;

    while (lenRead < len)
    {
        // Non-blocking read.
        size_t read = NwChanmux_chanRead(chan,
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


//------------------------------------------------------------------------------
// called by PicoTCP

/*
 *   Function: NwStack_write_data()
 *
 *   Return values:
 *   written bytes = success
 *   0 = failure
 */
int
NwChanmux_write_data(
    void*   buffer,
    size_t  len)
{
    int written= NwChanmux_chanWriteSyncData(
                                        buffer,
                                        len);
    return written;
}

//------------------------------------------------------------------------------
/*
 *   Function: NwStack_read_data()
 *
 *   Return values:
 *   read bytes = success
 *   0 = nothing to read
 */
// called by PicoTCP
int
NwChanmux_read_data(
    void*   buffer,
    size_t  len)
{
    int chan = CHANNEL_NW_STACK_DATA;
    return (NwChanmux_chanRead(chan, buffer,len));
}


/*
 *   Function: NwChanmux_get_mac()
 *
 *   Return values:
 *   0 and gets the mac address filled
 */
//------------------------------------------------------------------------------
// called by PicoTCP
int
NwChanmux_get_mac(
    char*     name,
    uint8_t*  mac)
{

    char command[2];
    char response[8];

    Debug_LOG_INFO("%s\n",__FUNCTION__);

   /* First we send the OPEN and then the GETMAC cmd. This is for proxy which first needs to Open/activate the socket */
    command[0] = NW_CTRL_CMD_OPEN;
    command[1] = CHANNEL_NW_STACK_DATA;

    unsigned result = NwChanmux_chanWriteSyncCtrl(
                              command,
                              sizeof(command));

   if(result != sizeof(command))
   {
     Debug_LOG_INFO("%s could not write OPEN cmd , result = %d\n",__FUNCTION__,result);
     return -1;
   }

   /* Read back 2 bytes for OPEN CNF response, is a blocking call */

   size_t read = NwChanmux_chanReadBlocking(CHANNEL_NW_STACK_CTRL,response,2);

   if(read != 2)
   {
       Debug_LOG_INFO("%s could not read OPEN CNF response, result = %d\n",__FUNCTION__,result);
       return -1;
   }
   if(response[0] == NW_CTRL_CMD_OPEN_CNF)
   {
       // now start reading the mac

        command[0] = NW_CTRL_CMD_GETMAC;
        command[1] = CHANNEL_NW_STACK_DATA;   // this is required due to proxy

        Debug_LOG_INFO("Sending Get mac cmd: \n");

        unsigned result = NwChanmux_chanWriteSyncCtrl(
                                   command,
                                   sizeof(command));
        if(result != sizeof(command))
        {
           Debug_LOG_INFO("%s result = %d\n",__FUNCTION__,result);
           return -1;
        }
       size_t read = NwChanmux_chanReadBlocking(CHANNEL_NW_STACK_CTRL,response,sizeof(response));

        if(read != sizeof(response))
        {
           Debug_LOG_INFO("%s read = %d\n",__FUNCTION__,result);
           return -1;
        }
        /* response[1] must contain 0 as this is set by proxy when success */
        if((NW_CTRL_CMD_GETMAC_CNF == response[0]) && (response[1] == 0))
        {
           memcpy(mac,&response[2],6);
           Debug_LOG_INFO ( "exit %s mac received =%x %x %x %x %x %x \n", __FUNCTION__, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
           const  uint8_t empty[6] = { 0, };
           if(memcmp(mac,empty,6) ==0)
           {
               return -1;    // recvd six 0's from proxy tap for mac. This is not good. Check for tap on proxy !!
           }
        }

   }
  return 0;
}


