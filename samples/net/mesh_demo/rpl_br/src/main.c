/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if 1
#define SYS_LOG_DOMAIN "rpl-br/main"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <zephyr.h>
#include <stdio.h>

#include <net/net_context.h>

#include "ipv6.h"
#include "route.h"
#include "rpl.h"
#include "net_private.h"
#include "config.h"

void main(void)
{
	struct net_if *iface;

	NET_DBG("Start RPL Border Router");

	iface = net_if_get_default();
	if (!iface) {
		NET_INFO("Cannot continue, no interface exists");
		return;
	}

	setup_rpl(iface, CONFIG_NET_RPL_PREFIX);

	coap_init();
}
