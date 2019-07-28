/*
 *  SEOS Network Stack
 *
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#pragma once
#include <stdlib.h>
#include <stdint.h>

int
NwStack_seos_init(void);

/* Camkes structure to be filled during component instantiation */
typedef struct _nw_camkes_glue_t
{
    void (*e_write_emit)();
    void (*e_read_emit)();
    void (*e_conn_emit)();
    void (*e_write_nwstacktick)();
    void (*e_initdone)();
    void (*c_write_wait)();
    void (*c_read_wait)();
    void (*c_conn_wait)();
    void (*c_nwstacktick_wait)();

}nw_camkes_glue;


typedef struct _nw_chanmux_ports_glue_t
{
    void *ChanMuxDataPort;
    void *ChanMuxCtrlPort;
    void *Appdataport;
 }nw_chanmux_ports_glue;




extern int
Seos_NwStack_init(int instance, nw_camkes_glue *pNwCamkes,nw_chanmux_ports_glue *dataportglu);

extern void Seos_NwStack_App_init(void * nwAppDataPort);


extern int NwStackIf_socket(int domain, int type);
extern int NwStackIf_close();
extern int NwStackIf_connect(const char* name, int port);
extern int NwStackIf_write(int len);
extern int NwStackIf_bind(uint16_t port);
extern int NwStackIf_listen(int backlog);
extern int NwStackIf_accept(uint16_t port);
extern int NwStackIf_read(int len);






