/*
 *  OS Network Stack
 *
 *  Core functions of the TRENTOS-M Network stack, independent of any
 *  actual implementation
 *
 *  Copyright (C) 2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Types.h"

void*
get_implementation_socket_from_handle(
    int handle);

void*
get_socket_from_handle(
    int handle);

int get_handle_from_implementation_socket(
    void* impl_sock);

int reserve_handle(
    void* impl_sock);

void free_handle(
    int handle);

void set_accepted_handle(
    int handle,
    int accept_handle);

int get_accepted_handle(
    int handle);

event_notify_func_t
get_notify_conn_func_for_handle(
    int handle);

event_wait_func_t
get_wait_conn_func_for_handle(
    int handle);

event_notify_func_t
get_notify_write_func_for_handle(
    int handle);

event_wait_func_t
get_wait_write_func_for_handle(
    int handle);

event_notify_func_t
get_notify_read_func_for_handle(
    int handle);

event_wait_func_t
get_wait_read_func_for_handle(
    int handle);

OS_Dataport_t*
get_dataport_for_handle(
    int handle);
