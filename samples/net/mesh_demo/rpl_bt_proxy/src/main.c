/* main.c - Application main entry point */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <misc/printk.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/mesh.h>

#include "rpl.h"

#define COMP_ID BT_COMP_ID_LF

#define MOD_LF 0x0000

#define NODE_ADDR 0x0001
#define GROUP_ADDR 0xc000

#define OP_VENDOR_BUTTON BT_MESH_MODEL_OP_3(0x00, COMP_ID)

static const u8_t net_key[16] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};
static const u8_t dev_key[16] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};
static const u8_t app_key[16] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};
static const u16_t net_idx;
static const u16_t app_idx;
static const u32_t iv_index;
static u8_t flags;

static struct bt_mesh_cfg_srv cfg_srv = {
	.relay = BT_MESH_RELAY_ENABLED,
	.beacon = BT_MESH_BEACON_ENABLED,
	.frnd = BT_MESH_FRIEND_NOT_SUPPORTED,
	.default_ttl = 7,

	/* 3 transmissions with 20ms interval */
	.net_transmit = BT_MESH_TRANSMIT(2, 20),
	.relay_retransmit = BT_MESH_TRANSMIT(3, 20),
};

static struct bt_mesh_cfg_cli cfg_cli = {
};

static void attention_on(struct bt_mesh_model *model)
{
	printk("attention_on()\n");
}

static void attention_off(struct bt_mesh_model *model)
{
	printk("attention_off()\n");
}

static const struct bt_mesh_health_srv_cb health_srv_cb = {
	.attn_on = attention_on,
	.attn_off = attention_off,
};

static struct bt_mesh_health_srv health_srv = {
	.cb = &health_srv_cb,
};

BT_MESH_HEALTH_PUB_DEFINE(health_pub, 0);

static struct bt_mesh_model sig_models[] = {
	BT_MESH_MODEL_CFG_SRV(&cfg_srv),
	BT_MESH_MODEL_CFG_CLI(&cfg_cli),
	BT_MESH_MODEL_HEALTH_SRV(&health_srv, &health_pub),
};

static void vnd_button_pressed(struct bt_mesh_model *model,
			       struct bt_mesh_msg_ctx *ctx,
			       struct net_buf_simple *buf)
{
	//printk("Message 0x%04x -> 0x%04x\n", ctx->addr, model->elem->addr);

	ble_to_rpl(ctx->addr, model->elem->addr);
}

static const struct bt_mesh_model_op vnd_ops[] = {
	{ OP_VENDOR_BUTTON, 0, vnd_button_pressed },
	BT_MESH_MODEL_OP_END,
};

static struct bt_mesh_model vnd1_models[] = {
	BT_MESH_MODEL_VND(COMP_ID, MOD_LF, vnd_ops, NULL, NULL),
};

static struct bt_mesh_model vnd2_models[] = {
	BT_MESH_MODEL_VND(COMP_ID, MOD_LF, vnd_ops, NULL, NULL),
};

static struct bt_mesh_model vnd3_models[] = {
	BT_MESH_MODEL_VND(COMP_ID, MOD_LF, vnd_ops, NULL, NULL),
};

static struct bt_mesh_model vnd4_models[] = {
	BT_MESH_MODEL_VND(COMP_ID, MOD_LF, vnd_ops, NULL, NULL),
};

static struct bt_mesh_elem elements[] = {
	BT_MESH_ELEM(0, sig_models, vnd1_models),
	BT_MESH_ELEM(0, BT_MESH_MODEL_NONE, vnd2_models),
	BT_MESH_ELEM(0, BT_MESH_MODEL_NONE, vnd3_models),
	BT_MESH_ELEM(0, BT_MESH_MODEL_NONE, vnd4_models),
};

static const struct bt_mesh_comp comp = {
	.cid = COMP_ID,
	.elem = elements,
	.elem_count = ARRAY_SIZE(elements),
};

int rpl_to_ble(u16_t src, u16_t dst)
{
	struct bt_mesh_model *model;
	NET_BUF_SIMPLE_DEFINE(msg, 3 + 4);
	struct bt_mesh_msg_ctx ctx = {
		.net_idx = net_idx,
		.app_idx = app_idx,
		.addr = dst,
		.send_ttl = BT_MESH_TTL_DEFAULT,
	};

	printk("src 0x%04x dst 0x%04x\n", src, dst);

	if (!src || src >= ARRAY_SIZE(elements)) {
		return -EINVAL;
	}

	model = &elements[src - 1].vnd_models[0];

	/* Bind to Health model */
	bt_mesh_model_msg_init(&msg, OP_VENDOR_BUTTON);

	if (bt_mesh_model_send(model, &ctx, &msg, NULL, NULL)) {
		printk("Unable to send Vendor Button message\n");
		return -EIO;
	}

	printk("Button message sent with OpCode 0x%08x\n", OP_VENDOR_BUTTON);

	return 0;
}

static void configure(u16_t addr)
{
	u8_t status;

	/* Add Application Key */
	bt_mesh_cfg_app_key_add(net_idx, addr, net_idx, app_idx, app_key,
				&status);

	/* Bind to vendor model */
	bt_mesh_cfg_mod_app_bind_vnd(net_idx, addr, addr, app_idx,
				     MOD_LF, COMP_ID, &status);
	bt_mesh_cfg_mod_app_bind_vnd(net_idx, addr, addr + 1, app_idx,
				     MOD_LF, COMP_ID, &status);
	bt_mesh_cfg_mod_app_bind_vnd(net_idx, addr, addr + 2, app_idx,
				     MOD_LF, COMP_ID, &status);
	bt_mesh_cfg_mod_app_bind_vnd(net_idx, addr, addr + 3, app_idx,
				     MOD_LF, COMP_ID, &status);

	/* Bind to Health model */
	bt_mesh_cfg_mod_app_bind(net_idx, addr, addr, app_idx,
				 BT_MESH_MODEL_ID_HEALTH_SRV, &status);

	/* Add model subscription */
	/* Do not listen for group address, some of 802.15.4 frames are lost. */
#if 0
	bt_mesh_cfg_mod_sub_add_vnd(net_idx, addr, addr, GROUP_ADDR,
				    MOD_LF, COMP_ID, &status);
	bt_mesh_cfg_mod_sub_add_vnd(net_idx, addr, addr + 1, GROUP_ADDR,
				    MOD_LF, COMP_ID, &status);
	bt_mesh_cfg_mod_sub_add_vnd(net_idx, addr, addr + 2, GROUP_ADDR,
				    MOD_LF, COMP_ID, &status);
	bt_mesh_cfg_mod_sub_add_vnd(net_idx, addr, addr + 3, GROUP_ADDR,
				    MOD_LF, COMP_ID, &status);
#endif
}

static const u8_t dev_uuid[16] = { 0xdd, 0xdd };

static const struct bt_mesh_prov prov = {
	.uuid = dev_uuid,
};

void main(void)
{
	int err;

	/* Set up 802.15.4 RPL proxy */
	printk("Initializing RPL proxy...\n");

	init_rpl_node();

	printk("Initializing Bluetooth...\n");

	/* Initialize the Bluetooth Subsystem */
	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return;
	}

	printk("Bluetooth initialized\n");

	err = bt_mesh_init(&prov, &comp);
	if (err) {
		printk("Initializing mesh failed (err %d)\n", err);
		return;
	}

	printk("Mesh initialized\n");

	err = bt_mesh_provision(net_key, net_idx, flags, iv_index, 0,
				NODE_ADDR, dev_key);
	if (err) {
		printk("Provisioning failed (err %d)\n", err);
		return;
	}

	printk("Provisioning completed, configuring...\n");

	configure(NODE_ADDR);

	printk("Configuring complete\n");
}
