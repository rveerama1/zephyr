#if 1
#define SYS_LOG_DOMAIN "rpl-node"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <zephyr.h>
#include <errno.h>
#include <board.h>
#include <gpio.h>

#include <net/net_core.h>
#include <net/net_ip.h>
#include <net/net_pkt.h>
#include <net/net_context.h>
#include <net/udp.h>
#include <net/coap.h>

#include <net_private.h>
#include <rpl.h>

#include "rpl.h"

#define MY_COAP_PORT 5683
#define PEER_COAP_PORT 0xABC0

#define ALL_NODES_LOCAL_COAP_MCAST					\
	{ { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd } } }

#define RPL_MAX_REPLY 75

#define PKT_WAIT_TIME K_SECONDS(1)

static struct net_context *context;

static const char * const uri_path[] = { "led", NULL };

static bool send_coap_request(const struct sockaddr_in6 *peer, u16_t id,
			      u8_t src, u8_t dst)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct coap_packet request;
	const char * const *p;
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
	r = coap_packet_append_payload(&request, &src, 1);
	if (r < 0) {
		net_pkt_unref(pkt);
		return false;
	}

	/* Append DST id */
	r = coap_packet_append_payload(&request, &dst, 1);
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

/* HACK: Send LED Toggle messages only One per Second.
 * BT node button sending multiple callbacks on single press.
 * Actual fix should be on BT node to generate only one message
 * per one press.
 */

static bool send_coap = true;
static struct k_delayed_work flow_ctrl_timer;

static void flow_control_timeout(struct k_work *work)
{
	send_coap = true;
}

int ble_to_rpl(u16_t src, u16_t dst)
{
	struct net_rpl_instance *rpl;
	struct sockaddr_in6 peer;
	struct in6_addr *parent = NULL;

	if (!send_coap) {
		NET_DBG("Message 0x%04x -> 0x%04x sent already", src, dst);
		return 0;
	}

	send_coap = false;
	k_delayed_work_submit(&flow_ctrl_timer, K_SECONDS(1));
#if 0
	/* Send message in below combinations only
	 * src -> dst
	 *  5  ->  1
	 *  6  ->  2
	 *  7  ->  3
	 *  8  ->  4
	 */

	if (!((src == 5 && dst == 1) ||
	      (src == 6 && dst == 2) ||
	      (src == 7 && dst == 3) ||
	      (src == 8 && dst == 4))) {
		return 0;
	}
#endif
	NET_DBG("Message 0x%04x -> 0x%04x", src, dst);

	rpl = net_rpl_get_default_instance();
	if (rpl && rpl->current_dag && rpl->current_dag->preferred_parent) {
		parent = net_rpl_get_parent_addr(net_if_get_default(),
					 rpl->current_dag->preferred_parent);
		if (!parent) {
			NET_DBG("Can not send CoAP req to RPL BR");
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}

	peer.sin6_family = AF_INET6;
	peer.sin6_port = PEER_COAP_PORT;
	net_ipaddr_copy(&peer.sin6_addr, parent);

	return send_coap_request(&peer, coap_next_id(), src, dst);
}

static int led_post(struct coap_resource *resource,
		    struct coap_packet *request)
{
	struct net_buf *frag;
	u16_t offset;
	u8_t src;
	u8_t dst;

	NET_DBG("");

	frag = net_frag_skip(request->frag, request->offset, &offset,
			     request->hdr_len + request->opt_len);
	if (!frag && offset == 0xffff) {
		return -EINVAL;
	}

	frag = net_frag_read_u8(frag, offset, &offset, &src);
	if (!frag && offset == 0xffff) {
		NET_ERR("packet without payload");
	}

	frag = net_frag_read_u8(frag, offset, &offset, &dst);
	if (!frag && offset == 0xffff) {
		NET_ERR("packet without payload");
	}

	NET_DBG("Message from %d -> %d", src, dst);

	rpl_to_ble(src, dst);

	return 0;
}

static const char * const led_default_path[] = { "led", NULL };

static struct coap_resource resources[] = {
	{ .get = NULL,
	  .post = led_post,
	  .put = NULL,
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

void init_rpl_node(void)
{
	static struct sockaddr_in6 any_addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
		.sin6_port = htons(MY_COAP_PORT) };
	int r;

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

	k_delayed_work_init(&flow_ctrl_timer, flow_control_timeout);
}
