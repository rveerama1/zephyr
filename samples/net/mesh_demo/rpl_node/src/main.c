/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if 1
#define SYS_LOG_DOMAIN "rpl-node"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <zephyr.h>
#include <errno.h>
#include <board.h>

#include <misc/byteorder.h>
#include <net/net_core.h>
#include <net/net_ip.h>
#include <net/net_pkt.h>
#include <net/net_context.h>
#include <net/udp.h>

#include <net_private.h>
#include <rpl.h>
#include <ipv6.h>

#include <gpio.h>

#include <net/coap.h>

#define MY_COAP_PORT 5683
#define PEER_COAP_PORT 0xABC0

#define ALL_NODES_LOCAL_COAP_MCAST					\
	{ { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd } } }

#define LED_GPIO_NAME LED0_GPIO_PORT
#define LED_PIN LED0_GPIO_PIN

#define LED1_PIN 27 /* AH - J15 - 12 */

#define RPL_MAX_REPLY 75

#define PKT_WAIT_TIME K_SECONDS(1)

static struct net_context *context;
static struct device *led0;
static struct device *led1;
static struct device *sw0;

static const char * const uri_path[] = { "led", NULL };

static void toggle_led(void)
{
	u32_t led = 0;
	int r;

	r = gpio_pin_read(led0, LED_PIN, &led);
	if (r < 0) {
		NET_ERR("Failed to read GPIO pin");
		return;
	}

	gpio_pin_write(led0, LED_PIN, !led);
}

static void toggle_led1(void)
{
	u32_t led = 0;
	int r;

	r = gpio_pin_read(led1, 27, &led);
	if (r < 0) {
		NET_ERR("Failed to read GPIO pin");
		return;
	}

	gpio_pin_write(led1, 27, !led);
}

static int led_post(struct coap_resource *resource,
		    struct coap_packet *request)
{
	NET_DBG("");

	toggle_led();
	toggle_led1();

	return 0;
}

static const char * const led_default_path[] = { "led", NULL };

static struct coap_resource resources[] = {
	{ .get = NULL,
	  .put = NULL,
	  .post = led_post,
	  .path = led_default_path,
	  .user_data = NULL,
	},
	{ },
};

static void udp_receive(struct net_context *context,
			struct net_pkt *pkt,
			int status,
			void *user_data)
{
	struct coap_packet request;
	struct coap_option options[16] = { 0 };
	u8_t opt_num = 16;
	int r;

	r = coap_packet_parse(&request, pkt, options, opt_num);
	if (r < 0) {
		NET_ERR("Invalid data received (%d)\n", r);
		goto end;
	}

	r = coap_handle_request(&request, resources, options, opt_num);
	if (r < 0) {
		NET_ERR("No handler for such request (%d)\n", r);
	}

end:
	net_pkt_unref(pkt);
}

static bool join_coap_multicast_group(void)
{
	static struct sockaddr_in6 mcast_addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = ALL_NODES_LOCAL_COAP_MCAST,
		.sin6_port = htons(MY_COAP_PORT) };
	struct net_if_mcast_addr *mcast;
	struct net_if *iface;

	iface = net_if_get_default();
	if (!iface) {
		NET_ERR("Could not get te default interface\n");
		return false;
	}

	mcast = net_if_ipv6_maddr_add(iface, &mcast_addr.sin6_addr);
	if (!mcast) {
		NET_ERR("Could not add multicast address to interface\n");
		return false;
	}

	return true;
}

static u8_t get_dst(void)
{
	switch (CONFIG_IEEE802154_CC2520_MAC7) {
	case 0x01:
		return 5;
	case 0x02:
		return 6;
	case 0x03:
		return 7;
	case 0x04:
		return 8;
	}

	return 0;
}

static u8_t get_src(void)
{
	return CONFIG_IEEE802154_CC2520_MAC7;
}

static bool send_coap_request(const struct sockaddr_in6 *peer, u16_t id)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct coap_packet request;
	const char * const *p;
	u8_t val;
	int r;

	pkt = net_pkt_get_tx(context, PKT_WAIT_TIME);
	if (!pkt) {
		NET_ERR("Ran out of network packets");
		return false;
	}

	frag = net_pkt_get_data(context, PKT_WAIT_TIME);
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

	r = coap_packet_append_payload_marker(&request);
	if (r < 0) {
		net_pkt_unref(pkt);
		return false;
	}

	/* Append SRC id */
	val = get_src();
	r = coap_packet_append_payload(&request, &val, 1);
	if (r < 0) {
		net_pkt_unref(pkt);
		return false;
	}

	/* Append DST id */
	val = get_dst();
	r = coap_packet_append_payload(&request, &val, 1);
	if (r < 0) {
		net_pkt_unref(pkt);
		return false;
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


static void button_pressed(struct device *gpiob, struct gpio_callback *cb,
			   u32_t pins)
{
	struct net_rpl_instance *rpl;
	struct sockaddr_in6 peer;
	struct in6_addr *parent = NULL;

	rpl = net_rpl_get_default_instance();
	if (rpl && rpl->current_dag && rpl->current_dag->preferred_parent) {
		parent = net_rpl_get_parent_addr(net_if_get_default(),
					 rpl->current_dag->preferred_parent);
		if (!parent) {
			NET_DBG("Can not send CoAP req to RPL BR");
			return;
		}
	} else {
		return;
	}

	peer.sin6_family = AF_INET6;
	peer.sin6_port = PEER_COAP_PORT;
	net_ipaddr_copy(&peer.sin6_addr, parent);

	send_coap_request(&peer, coap_next_id());
}

static struct gpio_callback gpio_cb;

static void init_app(void)
{
	static struct sockaddr_in6 any_addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
		.sin6_port = htons(MY_COAP_PORT) };
	int r;

	led0 = device_get_binding(LED_GPIO_NAME);
	if (led0) {
		gpio_pin_configure(led0, LED_PIN, GPIO_DIR_OUT);
	} else {
		NET_ERR("Failed to bind '%s'",
			 LED_GPIO_NAME);
		return;
	}

	led1 = device_get_binding(LED_GPIO_NAME);
	if (led1) {
		gpio_pin_configure(led1, 27, GPIO_DIR_IN | GPIO_DIR_OUT);
	} else {
		NET_ERR("Failed to bind '%s'",
			 LED_GPIO_NAME);
		return;
	}

	sw0 = device_get_binding(SW0_GPIO_NAME);
	if (sw0) {
		gpio_pin_configure(sw0, SW0_GPIO_PIN,
				   GPIO_DIR_IN | GPIO_INT |
				   GPIO_INT_EDGE | GPIO_INT_ACTIVE_LOW |
				   GPIO_PUD_PULL_UP);
		gpio_init_callback(&gpio_cb, button_pressed,
				   BIT(SW0_GPIO_PIN));
		gpio_add_callback(sw0, &gpio_cb);
		gpio_pin_enable_callback(sw0, SW0_GPIO_PIN);
	} else {
		NET_ERR("Failed to bind '%s'",
			 SW0_GPIO_NAME);
		return;
	}

	if (!join_coap_multicast_group()) {
		NET_ERR("Could not join CoAP multicast group");
		return;
	}

	r = net_context_get(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &context);
	if (r) {
		NET_ERR("Could not get an UDP context");
		return;
	}

	r = net_context_bind(context, (struct sockaddr *) &any_addr,
			     sizeof(any_addr));
	if (r) {
		NET_ERR("Could not bind the context");
		return;
	}

	r = net_context_recv(context, udp_receive, 0, NULL);
	if (r) {
		NET_ERR("Could not receive in the context");
	}
}

void main(void)
{
	NET_DBG("Start RPL node");

	init_app();
}
