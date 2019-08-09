/*
 *  SEOS Network Stack ChanMux wrapper driver Interface.
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosNwChanmuxIf.h
 *
 * @brief Chanmux Interface driver

 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#pragma once

#include <stdlib.h>
#include <stdint.h>
#include "seos_err.h"

/**
 * @brief Write data through Chan mux. Data is written to DataPort shared between Chanmux and Network Stack.
 *
 * @param chan, Can take values CHANNEL_NW_STACK_DATA, CHANNEL_NW_STACK_DATA_2, CHANNEL_NW_STACK_CTRL or CHANNEL_NW_STACK_CTRL_2.

 * @param len, is the length of data to write

 * @param *written is pointer to written which will contain how much of data was actually written by Chanmux

 * @return Success or Failure.
 * @retval SEOS_SUCCESS or SEOS_ERROR_GENERIC
 *
 */

extern seos_err_t ChanMux_write(unsigned int chan, size_t len, size_t *written);

/**
 * @brief Read data through Chan mux, Data must be read from DataPort shared between Chanmux and Network Stack.

 * @param chan, Can take values CHANNEL_NW_STACK_DATA, CHANNEL_NW_STACK_DATA_2, CHANNEL_NW_STACK_CTRL or CHANNEL_NW_STACK_CTRL_2.

 * @param len, is the length of data to read

 * @param *read is pointer to read which will contain how much of data was actually read by Chanmux

 * @return Success or Failure.
 * @retval SEOS_SUCCESS or SEOS_ERROR_GENERIC
 *
 */

extern seos_err_t ChanMux_read(unsigned int chan, size_t len, size_t *read);


/**
 * @brief This is a wrapper for Chanmux_write for data channel

 * @param *buf, Pointer of the data buffer containing data to be written

 * @param len, is the length of data to write

 * @return Total number of bytes written
 * @retval length
 *
 */

size_t
NwChanmux_chanWriteSyncData(
    const void*   buf,
    size_t        len);

/**
 * @brief This is a wrapper for Chanmux_write for ctrl channel

 * @param *buf, Pointer of the data buffer containing data to be written

 * @param len, is the length of data to write

 * @return Total number of bytes written
 * @retval length
 *
 */

size_t
NwChanmux_chanWriteSyncCtrl(
        const void*   buf,
        size_t        len);

/**
 * @brief This is a wrapper for Chanmux_read. It is a non blocking read.

 * @param *buf, Pointer of the data buffer to be read into

 * @param len, is the length of data to read

 * @return Total number of bytes read
 * @retval length of bytes read
 *
 */

size_t
NwChanmux_chanRead(
    unsigned int  chan,
    void*         buf,
    size_t        len);


/**
 * @brief This is a wrapper for Chanmux_read. It is a blocking read.

 * @param *buf, Pointer of the data buffer to be read into

 * @param len, is the length of data to read

 * @return Total number of bytes read
 * @retval length of bytes read
 *
 */

size_t
NwChanmux_chanReadBlocking(
    unsigned int  chan,
    char*         buf,
    size_t        len);


/**
 * @brief This is a Interface for picotcp to use Chanmux, Chanmux_write. It acts as a wrapper for NwChanmux_chanWriteSyncData().

 * @param *buf, Pointer of the data buffer containing data to be written

 * @param len, is the length of data to write

 * @return Total number of bytes written
 * @retval length written
 *
 */
int
NwChanmux_write_data(
    void*   buffer,
    size_t  len);

/**
 * @brief This is a Interface for picotcp to use Chanmux, Chanmux_read. It acts as a wrapper for NwChanmux_chanRead().

 * @param *buf, Pointer of the data buffer containing data to be read into

 * @param len, is the length of data to read

 * @return Total number of bytes read
 * @retval length read
 *
 */
int
NwChanmux_read_data(
    void*   buffer,
    size_t  len);

/**
 * @brief This is a Interface for picotcp to use Chanmux to get the tap mac address.

 * @param *name, name of the tap of which mac addr is requested (e.g. "tap0" or "tap1" etc)

 * @param *mac , will contain the mac addr filled

 * @return Mac addr filled for tap
 * @retval mac addr
 *
 */

int
NwChanmux_get_mac(
    char*     name,
    uint8_t*  mac);
