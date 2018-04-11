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
static const char led_toggle[] = "LED Toggle";

#define NUM_OBSERVERS 3
#define NUM_PENDINGS 3

static struct coap_observer observers[NUM_OBSERVERS];
static struct coap_pending pendings[NUM_PENDINGS];

static struct k_delayed_work retransmit_work;

static void get_from_ip_addr(struct coap_packet *cpkt,
			     struct sockaddr_in6 *from)
{
	struct net_udp_hdr hdr, *udp_hdr;

	udp_hdr = net_udp_get_hdr(cpkt->pkt, &hdr);
	if (!udp_hdr) {
		return;
	}

	net_ipaddr_copy(&from->sin6_addr, &NET_IPV6_HDR(cpkt->pkt)->src);
	from->sin6_port = udp_hdr->src_port;
	from->sin6_family = AF_INET6;
}

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
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct coap_packet response;
	const char *str;
	u16_t len;
	u16_t id;
	u16_t offset;
	u8_t src;
	u8_t dst;

	int r;

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

	id = coap_header_get_id(request);

	pkt = net_pkt_get_tx(context, K_FOREVER);
	if (!pkt) {
		return -ENOMEM;
	}

	frag = net_pkt_get_data(context, K_FOREVER);
	if (!frag) {
		net_pkt_unref(pkt);
		return -ENOMEM;
	}

	net_pkt_frag_add(pkt, frag);

	r = coap_packet_init(&response, pkt, 1, COAP_TYPE_ACK,
			     0, NULL, COAP_RESPONSE_CODE_CHANGED, id);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	str = led_toggle;
	len = sizeof(led_toggle);

	r = coap_packet_append_payload_marker(&response);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	r = coap_packet_append_payload(&response, (u8_t *)str, len);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	get_from_ip_addr(request, &from);
	r = net_context_sendto(pkt, (const struct sockaddr *)&from,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		net_pkt_unref(pkt);
	}

	return r;
}

static void retransmit_request(struct k_work *work)
{
	struct coap_pending *pending;
	int r;

	pending = coap_pending_next_to_expire(pendings, NUM_PENDINGS);
	if (!pending) {
		return;
	}

	r = net_context_sendto(pending->pkt, &pending->addr,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		return;
	}

	if (!coap_pending_cycle(pending)) {
		coap_pending_clear(pending);
		return;
	}

	k_delayed_work_submit(&retransmit_work, pending->timeout);
}

static int append_rpl_parent(struct coap_packet *response)
{
	struct net_rpl_instance *rpl;
	struct in6_addr *parent;
	char out[RPL_MAX_REPLY];
	u16_t out_len;
	u8_t pos;

	rpl = net_rpl_get_default_instance();

	pos = snprintk(out, sizeof(out), "parent-");
	out_len = pos;

	if (!rpl || !rpl->current_dag || !rpl->current_dag->preferred_parent) {
		pos = snprintk(&out[out_len], sizeof(out), "None");
		out_len += pos;

	} else {
		parent = net_rpl_get_parent_addr(net_pkt_iface(response->pkt),
					rpl->current_dag->preferred_parent);
		pos = snprintk(&out[out_len], sizeof(out), "%s",
			       net_sprint_ipv6_addr(parent));
		out_len += pos;
	}

	pos = snprintk(&out[out_len], sizeof(out), "\nrank-");
	out_len += pos;

	if (!rpl || !rpl->current_dag) {
		pos = snprintk(&out[out_len], sizeof(out), "None");
		out_len += pos;
	} else {
		pos = snprintk(&out[out_len], sizeof(out), "%u",
			       rpl->current_dag->rank);
		out_len += pos;
	}

	return  coap_packet_append_payload(response, (u8_t *)out, out_len);
}

static int send_notification_packet(const struct sockaddr *addr,
				    u16_t age,
				    socklen_t addrlen,
				    u16_t id,
				    const u8_t *token,
				    u8_t tkl,
				    bool is_response)
{
	struct coap_packet response;
	struct coap_pending *pending;
	struct net_pkt *pkt;
	struct net_buf *frag;
	u8_t type = COAP_TYPE_CON;
	int r;

	if (is_response) {
		type = COAP_TYPE_ACK;
	}

	if (!is_response) {
		id = coap_next_id();
	}

	pkt = net_pkt_get_tx(context, K_FOREVER);
	frag = net_pkt_get_data(context, K_FOREVER);

	net_pkt_frag_add(pkt, frag);

	r = coap_packet_init(&response, pkt, 1, type,
			     tkl, (u8_t *)token,
			     COAP_RESPONSE_CODE_CONTENT, id);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	if (age >= 2) {
		coap_append_option_int(&response, COAP_OPTION_OBSERVE, age);
	}

	r = coap_packet_append_payload_marker(&response);
	if (r) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	r = append_rpl_parent(&response);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	if (type == COAP_TYPE_CON) {
		pending = coap_pending_next_unused(pendings, NUM_PENDINGS);
		if (!pending) {
			return -EINVAL;
		}

		r = coap_pending_init(pending, &response, addr);
		if (r) {
			return -EINVAL;
		}

		coap_pending_cycle(pending);
		pending = coap_pending_next_to_expire(pendings, NUM_PENDINGS);

		k_delayed_work_submit(&retransmit_work, pending->timeout);
	}

	return net_context_sendto(pkt, addr, addrlen, NULL, 0, NULL, NULL);
}

/* RPL Observe Server */
static int rpl_obs_get(struct coap_resource *resource,
		       struct coap_packet *request)
{
	struct coap_observer *observer;
	struct sockaddr_in6 from;
	u8_t token[8];
	u16_t id;
	u8_t tkl;
	bool observe = true;

	get_from_ip_addr(request, &from);

	if (!coap_request_is_observe(request)) {
		observe = false;
		goto done;
	}

	observer = coap_find_observer_by_addr(observers, NUM_OBSERVERS,
					      (const struct sockaddr *)&from);
	if (observer) {
		goto done;
	}

	observer = coap_observer_next_unused(observers, NUM_OBSERVERS);
	if (!observer) {
		return -ENOMEM;
	}

	coap_observer_init(observer, request, (const struct sockaddr *)&from);
	coap_register_observer(resource, observer);

done:
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	return send_notification_packet((const struct sockaddr *)&from,
					observe ? resource->age : 0,
					sizeof(struct sockaddr_in6), id,
					token, tkl, true);
}

static const char * const led_default_path[] = { "led", NULL };
static const char * const rpl_obs_default_path[] = { "rpl-obs", NULL };

static struct coap_resource resources[] = {
	{ .get = NULL,
	  .post = led_post,
	  .put = NULL,
	  .path = led_default_path,
	  .user_data = NULL,
	},
	{ .get = rpl_obs_get,
	  .post = NULL,
	  .put = NULL,
	  .path = rpl_obs_default_path,
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
