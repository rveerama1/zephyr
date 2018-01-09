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

#ifdef CONFIG_NET_APP_SETTINGS
#ifdef CONFIG_NET_IPV6
#define ZEPHYR_ADDR            CONFIG_NET_APP_MY_IPV6_ADDR
#else
#define ZEPHYR_ADDR            CONFIG_NET_APP_MY_IPV4_ADDR
#endif
#else
#ifdef CONFIG_NET_IPV6
#define ZEPHYR_ADDR            "2001:db8::1"
#else
#define ZEPHYR_ADDR            "192.0.2.1"
#endif
#endif

#ifndef ZEPHYR_PORT
#define ZEPHYR_PORT		8080
#endif

#define HTTP_TITLE		"Zephyr Border Router"

#define HTTP_AUTH_URL		"/auth"
#define HTTP_AUTH_TYPE		"Basic"

/* HTTP Basic Auth, see https://tools.ietf.org/html/rfc7617 */
#define HTTP_AUTH_REALM		"Zephyr"
#define HTTP_AUTH_USERNAME	"zephyr"
#define HTTP_AUTH_PASSWORD	"zephyr"

/* If you do not need HTTP support, then it is possible to disable it */
#if defined(CONFIG_WEBSOCKET)
void start_http_server(struct net_if *iface);
#else
#define start_http_server(...)
#endif

bool setup_rpl(struct net_if *iface, const char *addr_prefix);

enum coap_request_type {
	COAP_REQ_NONE = 0,
	COAP_REQ_LED_ON = 1,	/* Turn On LED */
	COAP_REQ_LED_OFF = 2,	/* Turn Off LED */
	COAP_REQ_RPL_INFO = 3,	/* Get RPL Info */
	COAP_REQ_RPL_OBS = 4,	/* Register OBS */
};

typedef void (*coap_reply_cb_t)(struct coap_packet *response, void *user_data);

int coap_init(void);
void coap_send_request(struct in6_addr *peer_addr,
		       enum coap_request_type type,
		       coap_reply_cb_t cb,
		       void *user_data);

int coap_append_topology_info(struct net_pkt *pkt);

void coap_remove_node_from_topology(struct in6_addr *peer);
#endif
