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


enum
{
    SEOS_NWSTACK_AS_CLIENT ,   //0
    SEOS_NWSTACK_AS_SERVER ,   // 1
    SEOS_NONE
};


/* Camkes structure to be filled during component instantiation */
typedef struct _nw_camkes_glue_t
{
    void (*e_write_emit)();  // emit and wait when there is pico event to write
    void (*c_write_wait)();
    void (*e_read_emit)();   // emit and wait when there is event to read
    void (*c_read_wait)();
    void (*e_conn_emit)();   // emit and wait when connected in case of server
    void (*c_conn_wait)();
    void (*e_write_nwstacktick)(); // tick nw stack when there is write event
    void (*c_nwstacktick_wait)();
    void (*e_initdone)();          // inform app after nw stack is initialised
}nw_camkes_signal_glue;


typedef struct _nw_ports_glue_t
{
    void *ChanMuxDataPort;
    void *ChanMuxCtrlPort;
    void *Appdataport;
 }nw_ports_glue;



 typedef struct _Seos_nw_instance_info_t    /* So that it can be used across other files */
 {
    nw_camkes_signal_glue* pCamkesglue;
    nw_ports_glue* pportsglu;
    uint8_t instanceID;
 }Seos_nw_camkes_info;




extern int
Seos_NwStack_init(Seos_nw_camkes_info *p);

extern void Seos_NwStack_App_init(void * nwAppDataPort);

/*
extern int NwStackIf_socket(int domain, int type);
extern int NwStackIf_close();
extern int NwStackIf_connect(const char* name, int port);
extern int NwStackIf_write(int len);
extern int NwStackIf_bind(uint16_t port);
extern int NwStackIf_listen(int backlog);
extern int NwStackIf_accept(uint16_t port);
extern int NwStackIf_read(int len);
*/





