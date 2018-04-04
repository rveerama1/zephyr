/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if 1
#define SYS_LOG_DOMAIN "rpl-br/coap"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <zephyr.h>
#include <stdio.h>
#include <stdlib.h>

#include <net/net_app.h>
#include <net/coap.h>
#include <net/udp.h>

#include "rpl.h"
#include "net_private.h"

#include "config.h"

#define MY_COAP_PORT 0xC0AB
#define PEER_COAP_PORT htons(0x1633) /* 5683 */

#define PKT_WAIT_TIME K_SECONDS(1)

static struct net_context *coap;

static const char * const uri_path[] = { "led", NULL };

#define BR_RPL_PROXY	\
	        { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, \
		      0x9f, 0xb3, 0x2e, 0xc1, 0x54, 0x9d, 0x8c, 0x3f } } }

#define RPL_NODE_1	\
	        { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, \
		      0x02, 0x12, 0x4b, 0, 0, 0, 0, 0x01 } } }

#define RPL_NODE_2	\
	        { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, \
		      0x02, 0x12, 0x4b, 0, 0, 0, 0, 0x02 } } }

#define RPL_NODE_3	\
	        { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, \
		      0x02, 0x12, 0x4b, 0, 0, 0, 0, 0x03 } } }

#define RPL_NODE_4	\
	        { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, \
		      0x02, 0x12, 0x4b, 0, 0, 0, 0, 0x04 } } }

static struct sockaddr_in6 proxy_peer = {
			.sin6_family = AF_INET6,
			.sin6_addr = BR_RPL_PROXY,
			.sin6_port = PEER_COAP_PORT
			};

static struct sockaddr_in6 rpl_peer1 = {
			.sin6_family = AF_INET6,
			.sin6_addr = RPL_NODE_1,
			.sin6_port = PEER_COAP_PORT
			};

static struct sockaddr_in6 rpl_peer2 = {
			.sin6_family = AF_INET6,
			.sin6_addr = RPL_NODE_2,
			.sin6_port = PEER_COAP_PORT
			};

static struct sockaddr_in6 rpl_peer3 = {
			.sin6_family = AF_INET6,
			.sin6_addr = RPL_NODE_3,
			.sin6_port = PEER_COAP_PORT
			};

static struct sockaddr_in6 rpl_peer4 = {
			.sin6_family = AF_INET6,
			.sin6_addr = RPL_NODE_4,
			.sin6_port = PEER_COAP_PORT
			};

static bool toggle_led(const struct sockaddr_in6 *peer, u16_t id,
		       u8_t src, u8_t dst)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct coap_packet request;
	const char * const *p;
	int r;

	pkt = net_pkt_get_tx(coap, PKT_WAIT_TIME);
	if (!pkt) {
		NET_ERR("Ran out of network packets");
		return false;
	}

	frag = net_pkt_get_data(coap, PKT_WAIT_TIME);
	if (!frag) {
		NET_ERR("Ran out of network buffers");
		goto end;
	}

	net_pkt_frag_add(pkt, frag);

	r = coap_packet_init(&request, pkt, 1, COAP_TYPE_NON_CON,
			     0, NULL, COAP_METHOD_POST, id);
	if (r < 0) {
		NET_ERR("Failed to initialize CoAP packet");
		goto end;
	}

	for (p = uri_path; p && *p; p++) {
		r = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
					      *p, strlen(*p));
		if (r < 0) {
			NET_ERR("Unable add option to request.\n");
			goto end;
		}
	}

	if (src && dst) {
		r = coap_packet_append_payload_marker(&request);
		if (r < 0) {
			goto end;
		}

		r = coap_packet_append_payload(&request, &src, 1);
		if (r < 0) {
			net_pkt_unref(pkt);
			return false;
		}

		r = coap_packet_append_payload(&request, &dst, 1);
		if (r < 0) {
			net_pkt_unref(pkt);
			return false;
		}

	}

	r = net_context_sendto(pkt, (const struct sockaddr *)peer,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		NET_ERR("Cannot send data to peer (%d)", r);
		goto end;
	}

	return true;

end:
	net_pkt_unref(pkt);
	return false;
}

static void bt_rpl_proxy_send_request(u8_t src, u8_t dst)
{
	toggle_led(&proxy_peer, coap_next_id(), src, dst);
}

static void rpl_send_request(u8_t src, u8_t dst)
{
	switch (dst) {
	case 1:
		toggle_led(&rpl_peer1, coap_next_id(), src, dst);
		break;
	case 2:
		toggle_led(&rpl_peer2, coap_next_id(), src, dst);
		break;
	case 3:
		toggle_led(&rpl_peer3, coap_next_id(), src, dst);
		break;
	case 4:
		toggle_led(&rpl_peer4, coap_next_id(), src, dst);
		break;
	}
}

static void pkt_receive(struct net_context *context,
			struct net_pkt *pkt,
			int status,
			void *user_data)
{
	struct coap_option options[4] = { 0 };
	struct coap_packet response;
	struct net_buf *frag;
	u16_t offset;
	u16_t len;
	u8_t opt_num = 4;
	u8_t src;
	u8_t dst;
	int r;

	r = coap_packet_parse(&response, pkt, options, opt_num);
	if (r < 0) {
		NET_ERR("Invalid data received (%d)\n", r);
		goto end;
	}

	frag = coap_packet_get_payload(&response, &offset, &len);
	if (!frag && offset == 0xffff) {
		NET_ERR("Invalid data received (%d)\n", r);
		goto end;
	}

	frag = net_frag_read_u8(frag, offset, &offset, &src);
	if (!frag && offset == 0xffff) {
		NET_ERR("Invalid data received");
		goto end;
	}

	frag = net_frag_read_u8(frag, offset, &offset, &dst);
	if (!frag && offset == 0xffff) {
		NET_ERR("Invalid data received");
		goto end;
	}

	if (src == 1 || src == 2 || src == 3 || src == 4) {
		bt_rpl_proxy_send_request(src, dst);
	}

	if (dst == 1 || dst == 2 || dst == 3 || dst == 4) {
		rpl_send_request(src, dst);
	}

end:
	net_pkt_unref(pkt);
}

void coap_send_request(struct in6_addr *peer_addr,
		       enum coap_request_type type,
		       coap_reply_cb_t cb,
		       void *user_data)
{
	struct sockaddr_in6 peer;

	peer.sin6_family = AF_INET6;
	peer.sin6_port = PEER_COAP_PORT;
	net_ipaddr_copy(&peer.sin6_addr, peer_addr);

	switch (type) {
	case COAP_REQ_NONE:
		return;
	case COAP_REQ_LED_TOGGLE:
		/* FIXME: Extend shell commands to provide src and dst.
		 * Can toggle RPL leds only, BT leds toggling does not
		 * work through shell command.
		 */
		toggle_led(&peer, coap_next_id(), 0, 0);
		break;
	}
}

int coap_init(void)
{
	struct net_if *iface = NULL;

	static struct sockaddr_in6 my_addr = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(MY_COAP_PORT)
			};
	u8_t i;
	int r;

	iface = net_if_get_ieee802154();
	if (!iface) {
		NET_ERR("No IEEE 802.15.4 network interface found.");
		return -EINVAL;
	}

	for (i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
		if (iface->config.ip.ipv6->unicast[i].is_used) {
			break;
		}
	}

	if (i >= NET_IF_MAX_IPV6_ADDR) {
		return -EINVAL;
	}

	net_ipaddr_copy(&my_addr.sin6_addr,
			&iface->config.ip.ipv6->unicast[i].address.in6_addr);

	r = net_context_get(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &coap);
	if (r < 0) {
		NET_ERR("Could not get UDP context");
		return r;
	}

	r = net_context_bind(coap, (struct sockaddr *) &my_addr,
			     sizeof(my_addr));
	if (r < 0) {
		NET_ERR("Could not bind to the context");
		return r;
	}

	r = net_context_recv(coap, pkt_receive, 0, NULL);
	if (r < 0) {
		NET_ERR("Could not set recv callback in the context");
		return r;
	}

	return 0;
}
