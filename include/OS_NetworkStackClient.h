/*
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Dataport.h"
#include "OS_Error.h"
#include "OS_Network.h"

typedef struct
{
    OS_Dataport_t* dataport;
    int number_of_sockets;
} OS_NetworkStackClient_SocketDataports_t;

OS_Error_t
OS_NetworkStackClient_init(
    OS_NetworkStackClient_SocketDataports_t* config);

