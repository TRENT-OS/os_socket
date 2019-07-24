/*
 *   Pico TCP MUX CHAN TAP driver
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#ifndef INCLUDE_PICO_CHAN_MUX_TAP2
#define INCLUDE_PICO_CHAN_MUX_TAP2
#include "pico_config.h"
#include "pico_device.h"

void pico_chan_mux_tap2_destroy ( struct pico_device *tap );

struct pico_device *pico_chan_mux_tap2_create (char *name);

#endif
