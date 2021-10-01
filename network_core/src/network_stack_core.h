/*
 * OS Network Stack
 *
 * Core functions of the TRENTOS-M Network stack, independent of any
 * actual implementation
 *
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Types.h"
#include "stdint.h"
#include "OS_Dataport.h"

void*
get_implementation_socket_from_handle(
    const int handle);

void*
get_socket_from_handle(
    const int handle);

int
get_handle_from_implementation_socket(
    void* impl_sock);

int
get_client_index_from_clientId(
    const int clientId);

void*
get_client_from_clientId(
    const int clientId);

int
reserve_handle(
    void* impl_sock,
    const int clientId);

void
free_handle(
    const int handle,
    const int clientId);

void
set_parent_handle(
    const int handle,
    const int accepted_handle);

const OS_Dataport_t*
get_dataport_for_handle(
    const int handle);

int
get_client_id(void);

uint8_t*
get_client_id_buf(void);

int
get_client_id_buf_size(void);

#define CHECK_SOCKET(_socket_, _handle_)                                       \
    do                                                                         \
    {                                                                          \
        if (NULL == _socket_)                                                  \
        {                                                                      \
            Debug_LOG_ERROR("%s: invalid handle %d", __func__, _handle_);      \
            return OS_ERROR_INVALID_HANDLE;                                    \
        }                                                                      \
    } while (0)

#define CHECK_CLIENT_ID(_socket_)                                              \
    do                                                                         \
    {                                                                          \
        if (_socket_->clientId != get_client_id())                             \
        {                                                                      \
            Debug_LOG_ERROR(                                                   \
                "%s: invalid clientId number. Called by %d on a socket "       \
                "belonging to %d",                                             \
                __func__,                                                      \
                get_client_id(),                                               \
                _socket_->clientId);                                           \
            return OS_ERROR_INVALID_HANDLE;                                    \
        }                                                                      \
    } while (0)

#define CHECK_IS_RUNNING(_currentState_)                                       \
    do                                                                         \
    {                                                                          \
        if (_currentState_ != RUNNING)                                         \
        {                                                                      \
            if (_currentState_ == FATAL_ERROR)                                 \
            {                                                                  \
                Debug_LOG_ERROR("%s: FATAL_ERROR occurred in the NetworkStack" \
                                , __func__);                                   \
                return OS_ERROR_ABORTED;                                       \
            }                                                                  \
            else                                                               \
            {                                                                  \
                Debug_LOG_TRACE("%s: NetworkStack currently not running",      \
                __func__);                                                     \
               return OS_ERROR_NOT_INITIALIZED;                                \
            }                                                                  \
        }                                                                      \
    } while (0)
