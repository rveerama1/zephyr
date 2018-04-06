/* main.c - Application main entry point */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <misc/printk.h>

#include "rpl.h"

void main(void)
{
	/* Set up 802.15.4 RPL proxy */
	printk("Initializing RPL proxy...\n");

	init_rpl_node();
}
