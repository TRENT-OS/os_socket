/*
 * Nw_error.c
 *
 *  Created on: Jun 14, 2019
 *  Author: Hensoldt cyber GmbH (@Yogesh kulkarni)
 */

#include "pico_protocol.h"

char* nw_errlist[] =
{
    "no error",
    "Operation not permitted",
    "No such file or dir",
    "Interrupted system call",
    "I/O error",
    "no such dev or addr",
    "Try again",
    "Out of memory",
    "permission denied",
    "bad address",
    "Device or Resource busy",
    "File exists",
    "Invalid argument",
    "Machine is not on the network",
    "Protocol error",
    "Protocol not available",
    "Protocol not supported",
    "Operation not supported on transport endpoint",
    "Address already in use",
    "Cannot assign requested address",
    "Network is down",
    "Network is unreachable",
    "Connection reset by peer",
    "Transport endpoint is already connected",
    "Transport endpoint is not connected",
    "Cannot send after transport endpoint shutdown",
    "Connection timed out",
    "Connection refused",
    "Host is down",
    "No route to host",
    "Operation now in progress"
};


const char* nw_strerror(int e)
{
    return (nw_errlist[e]);
}
