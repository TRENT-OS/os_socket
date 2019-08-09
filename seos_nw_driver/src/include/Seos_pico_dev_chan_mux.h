/*
 *  SEOS Network Stack PicoTCP driver for Chanmux .
 *
 * @addtogroup SEOS
 * @{
 *
 * @file Seos_pico_dev_chan_mux.h
 *
 * @brief Picotcp Driver for Chanmux driver.

 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#ifndef INCLUDE_PICO_CHAN_MUX_TAP
#define INCLUDE_PICO_CHAN_MUX_TAP
#include "pico_config.h"
#include "pico_device.h"


/**
 * @brief Destroy tap interface created. Since we do not have any physical tap interface, this is dummy at the moment
 *
 * @param pico_device, the tap device which was created and needs to be destroyed.

 * @return none
 * @retval none
 *
 */

void pico_chan_mux_tap_destroy ( struct pico_device* tap );

/**
 * @brief Create tap interface. Since we do not have any physical tap interface it actually triggers proxy
 *        to get the necessary info such as mac, informs picotcp about this device and assigns picotcp call back functions
 *        for polling and writing data.
 *        This is called when Network stack is initialized.
 *
 * @param *name, the tap device which needs to be created (such as "tap0", "tap1" etc)

 * @return pico_device *, pointer to device created.
 * @retval pico_device*
 *
 */

struct pico_device* pico_chan_mux_tap_create (char* name);

#endif
