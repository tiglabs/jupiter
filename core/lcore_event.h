/* Copyright (c) 2017. TIG developer. */

#ifndef __LCORE_EVENT_H__
#define __LCORE_EVENT_H__

void lcore_event_init(void);
int lcore_event_notify(unsigned rcv_cid, void (*handle)(unsigned, void *),
                       void *param);
void lcore_event_poll(unsigned lcore_id);
int lcore_event_show_stats(char *buf, int len);

#endif

