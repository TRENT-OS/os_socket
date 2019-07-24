/*
 *  SEOS Network Stack ChanMux wrapper driver Interface.
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include <stdlib.h>
#include <stdint.h>


size_t
NwChanmux_chanWriteSyncData(
    const void*   buf,
    size_t        len);

size_t
NwChanmux_chanWriteSyncCtrl(
        const void*   buf,
        size_t        len);
size_t
NwChanmux_chanRead(
    unsigned int  chan,
    void*         buf,
    size_t        len);

size_t
NwChanmux_chanReadBlocking(
    unsigned int  chan,
    void*         buf,
    size_t        len);



int
NwChanmux_write_data(
    void*   buffer,
    size_t  len);

int
NwChanmux_read_data(
    void*   buffer,
    size_t  len);

int
NwChanmux_get_mac(
    char*     name,
    uint8_t*  mac);
