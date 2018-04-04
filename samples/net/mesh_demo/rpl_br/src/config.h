/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <net/coap.h>

/* The startup time needs to be longish if DHCP is enabled as setting
 * DHCP up takes some time.
 */
#define APP_STARTUP_TIME K_SECONDS(20)

bool setup_rpl(struct net_if *iface, const char *addr_prefix);

enum coap_request_type {
	COAP_REQ_NONE = 0,
	COAP_REQ_LED_TOGGLE = 1,	/* Toggle the LED */
};


typedef void (*coap_reply_cb_t)(struct coap_packet *response, void *user_data);

int coap_init(void);
void coap_send_request(struct in6_addr *peer_addr,
		       enum coap_request_type type,
		       coap_reply_cb_t cb,
		       void *user_data);
#endif
