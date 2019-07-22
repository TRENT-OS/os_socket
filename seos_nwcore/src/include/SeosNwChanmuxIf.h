/*
 *  SEOS Network Stack CAmkES wrapper
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include <stdlib.h>



size_t
NwCamkes_chanWriteSyncData(
    const void*   buf,
    size_t        len);

size_t
NwCamkes_chanWriteSyncCtrl(
        const void*   buf,
        size_t        len);
size_t
NwCamkes_chanRead(
    unsigned int  chan,
    void*         buf,
    size_t        len);

size_t
NwCamkes_chanReadBlocking(
    unsigned int  chan,
    void*         buf,
    size_t        len);
