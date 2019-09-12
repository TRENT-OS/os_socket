/*
 *  SeosNwConfig.h
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *  A basic configuration file for Network Stack.
*/
#pragma once

/* enable or disable tap interface */
#define SEOS_USE_TAP_INTERFACE       1


#if (SEOS_USE_TAP_INTERFACE == 1)

#define SEOS_TAP0_ADDR          "192.168.82.91"
#define SEOS_TAP1_ADDR          "192.168.82.92"
#define SEOS_SUBNET_MASK        "255.255.255.0"
#define SEOS_GATEWAY_ADDR       "192.168.82.1"
#define SEOS_CLOUD_ADDR         "51.144.118.31"

#endif
