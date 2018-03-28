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
#include <net/net_mgmt.h>
#include <net/net_event.h>

#include "ipv6.h"
#include "route.h"
#include "rpl.h"
#include "net_private.h"
#include "config.h"

/*
static void calculate_edges(void)
{
	u8_t i, j, k;

	k = 0;

	for (i = 1; i < CONFIG_NET_IPV6_MAX_NEIGHBORS; i++) {
		if (!topology.nodes[i].used) {
			continue;
		}

		for (j = 0; j < CONFIG_NET_IPV6_MAX_NEIGHBORS; j++) {
			if (!topology.nodes[j].used) {
				continue;
			}

			if (!net_ipv6_addr_cmp(&topology.nodes[i].parent,
					       &topology.nodes[j].addr)) {
				continue;
			}

			topology.edges[k].from = topology.nodes[i].id;
			topology.edges[k].to = topology.nodes[j].id;
			topology.edges[k].used = true;

			k++;
			break;

		}
	}
}
*/

static void coap_obs_cb(struct coap_packet *response, void *user_data)
{
	ARG_UNUSED(response);
	ARG_UNUSED(user_data);
}

static struct net_mgmt_event_callback br_mgmt_cb;
static void mgmt_cb(struct net_mgmt_event_callback *cb,
		    u32_t mgmt_event, struct net_if *iface)
{
	struct net_if *iface_802154 = net_if_get_ieee802154();
	struct net_event_ipv6_route *route_info;
	struct net_event_ipv6_nbr *nbr_info;
	struct net_route_entry *route;
	struct net_nbr *nbr;

	if (iface_802154 != iface) {
		return;
	}

	if (!cb->info) {
		return;
	}

	if (mgmt_event == NET_EVENT_IPV6_NBR_ADD) {
		nbr_info = (struct net_event_ipv6_nbr *)cb->info;
		if (!nbr_info) {
			NET_ERR("Invalid info received on event");
			return;
		}

		nbr = net_ipv6_nbr_lookup(iface, &nbr_info->addr);
		if (!nbr || !net_ipv6_nbr_data(nbr)) {
			NET_ERR("Invalid neighbor data received");
			return;
		}

		NET_DBG("NBR add %s", net_sprint_ipv6_addr(&nbr_info->addr));

	} else if (mgmt_event == NET_EVENT_IPV6_NBR_DEL) {
		nbr_info = (struct net_event_ipv6_nbr *)cb->info;
		if (!nbr_info) {
			NET_ERR("Invalid info received on event");
			return;
		}

		NET_DBG("NBR del %s", net_sprint_ipv6_addr(&nbr_info->addr));

	} else if (mgmt_event == NET_EVENT_IPV6_ROUTE_ADD) {
		route_info = (struct net_event_ipv6_route *)cb->info;
		if (!route_info) {
			NET_ERR("Invalid info received on event");
			return;
		}

		route = net_route_lookup(iface, &route_info->addr);
		if (!route) {
			NET_ERR("Invalid route entry received");
			return;
		}

		NET_DBG("ROUTE add addr %s/%d",
			net_sprint_ipv6_addr(&route_info->addr),
			route_info->prefix_len);
		{
			NET_DBG("ROUTE add nexthop %s",
				net_sprint_ipv6_addr(&route_info->nexthop));

		}

		coap_send_request(&route_info->nexthop,
				  COAP_REQ_RPL_OBS, coap_obs_cb, NULL);

	} else if (mgmt_event == NET_EVENT_IPV6_ROUTE_DEL) {
		route_info = (struct net_event_ipv6_route *)cb->info;
		if (!route_info) {
			NET_ERR("Invalid info received on event");
			return;
		}

		NET_DBG("ROUTE del addr %s/%d",
			net_sprint_ipv6_addr(&route_info->addr),
			route_info->prefix_len);
		{
			NET_DBG("ROUTE del nexthop %s",
				net_sprint_ipv6_addr(&route_info->nexthop));

		}

		coap_remove_node_from_topology(&route_info->nexthop);
	}
}

void main(void)
{
	struct net_if *iface;

	NET_DBG("RPL border router starting");

	iface = net_if_get_default();
	if (!iface) {
		NET_INFO("Cannot continue, no interface exists");
		return;
	}

	setup_rpl(iface, CONFIG_NET_RPL_PREFIX);

	coap_init();

	net_mgmt_init_event_callback(&br_mgmt_cb, mgmt_cb,
				     NET_EVENT_IPV6_NBR_ADD |
				     NET_EVENT_IPV6_NBR_DEL |
				     NET_EVENT_IPV6_ROUTE_ADD |
				     NET_EVENT_IPV6_ROUTE_DEL);
	net_mgmt_add_event_callback(&br_mgmt_cb);
}
