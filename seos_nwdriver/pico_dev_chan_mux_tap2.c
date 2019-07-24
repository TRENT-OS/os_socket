/*
 *   Pico TCP MUX CHAN TAP driver
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "pico_device.h"
#include "pico_dev_chan_mux_tap2.h"
#include "pico_stack.h"
#include "NwStack_2.h"
#include "uart_socket_guest_rpc_conventions.h"

struct pico_device_chan_mux_tap2
{
    struct pico_device dev;
};

#define TUN_MTU  2048   // Revisit later


static int pico_chan_mux_tap2_send(struct pico_device *dev, void *buf, int len)
{
	 //TBD
    struct pico_device_chan_mux_tap2 *tap = ( struct pico_device_chan_mux_tap2 * ) dev;
    return (NwStack_2_write_data(buf,len));

}


static int pico_chan_mux_tap2_poll( struct pico_device *dev, int loop_score )
{
	//TBD
     struct pico_device_chan_mux_tap2 *tap = ( struct pico_device_chan_mux_tap2 * ) dev;
     unsigned char buf[TUN_MTU];
     int len;
     int result;

     while(loop_score > 0)
     {
           len = NwStack_2_read_data(buf,TUN_MTU);
           if(len >0)
           {
               loop_score--;
               pico_stack_recv(dev, buf, (uint32_t)len);
           }
           else
           {
        	   return loop_score;
           }

     }
     return 0;

}

void pico_chan_mux_tap2_destroy ( struct pico_device *dev )
{
    //  struct pico_device_uart_bridge_tap *tap = (struct pico_device_uart_bridge_tap *) dev;
    // TBD ?? what needs to be destroyed

}


static int pico_chan_mux_tap2_open (char *name )
{
    //TBD
}


static int pico_chan_mux_tap2_get_mac(char *name, uint8_t *mac)
{
    return (NwStack_2_get_mac(name,mac));
}

struct pico_device *pico_chan_mux_tap2_create (char *name)
{
    struct pico_device_chan_mux_tap2 *chan_mux_tap = PICO_ZALLOC(sizeof (struct pico_device_chan_mux_tap2));
    uint8_t mac[6] = {};

    if ( !chan_mux_tap )
    {
        return NULL;
    }

    pico_chan_mux_tap2_open(name);

    printf("%s\n",__FUNCTION__);


    /* Host's mac address is generated * by the host kernel and is
     * retrieved via tap_get_mac().
     */
    if (pico_chan_mux_tap2_get_mac(name, mac) < 0 )
    {
        dbg ( "Pico MUX CHAN Tap2 mac query failed.\n" );
        pico_chan_mux_tap2_destroy ((struct pico_device * ) chan_mux_tap );
        return NULL;
    }

    /* To act as a second endpoint in the same subnet, the picoTCP
     * app using the tap device must have a different mac address.
     * For simplicity, we just add 1 to the last byte of the linux
     * endpoint so the two addresses are consecutive.
     */
    mac[5]++;

    if ( 0 != pico_device_init ( ( struct pico_device * ) chan_mux_tap, name, mac ) )
    {
        dbg ( "Chan Mux Tap2 init failed.\n" );
        pico_chan_mux_tap2_destroy ( ( struct pico_device * ) chan_mux_tap );
        return NULL;
    }

    chan_mux_tap->dev.send = pico_chan_mux_tap2_send;
    chan_mux_tap->dev.poll = pico_chan_mux_tap2_poll;
    chan_mux_tap->dev.destroy = pico_chan_mux_tap2_destroy;
    dbg ( "Device %s created.\n", chan_mux_tap->dev.name );
    return ( struct pico_device * ) chan_mux_tap;
}

