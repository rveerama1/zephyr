/*
 * Copyright (c) 2017 Linaro Limited
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <misc/printk.h>

#include <net/socket.h>
#include <net/net_ip.h>
#include <net/sntp.h>

#define SNTP_PORT 123

void resp_callback(struct sntp_ctx *ctx, int status,
		   u64_t epoch_time)
{
	printk("time: %lld\n", epoch_time);
	printk("status: %d\n", status);
}

void main(void)
{
	struct sntp_ctx ctx;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	int rv;

	/* ipv4 */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(SNTP_PORT);
	inet_pton(AF_INET, CONFIG_NET_CONFIG_PEER_IPV4_ADDR,
		  &addr.sin_addr);

	rv = sntp_init(&ctx, (struct sockaddr *) &addr,
		       sizeof(struct sockaddr_in));
	if (rv < 0) {
		printk("Failed to init sntp ctx: %d\n", rv);
		return;
	}

	rv = sntp_request(&ctx, K_FOREVER, resp_callback);
	if (rv < 0) {
		printk("Failed to send sntp request: %d\n", rv);
		goto end;
	}

	sntp_close(&ctx);

	/* ipv6 */
	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(SNTP_PORT);
	inet_pton(AF_INET6, CONFIG_NET_CONFIG_PEER_IPV6_ADDR,
		  &addr6.sin6_addr);

	rv = sntp_init(&ctx, (struct sockaddr *) &addr6,
		       sizeof(struct sockaddr_in6));
	if (rv < 0) {
		printk("Failed to initi sntp ctx: %d\n", rv);
		goto end;
	}

	rv = sntp_request(&ctx, K_NO_WAIT, resp_callback);
	if (rv < 0) {
		printk("Failed to send sntp request: %d\n", rv);
		goto end;
	}

end:
	sntp_close(&ctx);
}
