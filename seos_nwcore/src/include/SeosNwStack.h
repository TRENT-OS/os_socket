/*
 *  SEOS Network Stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include <stdlib.h>
#include <stdint.h>

int
NwStack_seos_init(void);

int
NwStack_write_data(
    void*   buffer,
    size_t  len);

int
NwStack_read_data(
    void*   buffer,
    size_t  len);

int
NwStack_get_mac(
    char*     name,
    uint8_t*  mac);

