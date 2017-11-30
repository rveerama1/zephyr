/* cc2520_frdm_k64f.c - FRDK K64F setup for cc2520 */

/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <kernel.h>
#include <device.h>
#include <init.h>
#include <pinmux.h>
#include <pinmux/pinmux.h>
#include <fsl_port.h>

#include <ieee802154/cc2520.h>
#include <gpio.h>

#define TEST_1

#if defined(TEST_1)

#define CC2520_GPIO_PORTA CONFIG_GPIO_MCUX_PORTA_NAME
#define CC2520_GPIO_PORTB CONFIG_GPIO_MCUX_PORTB_NAME
#define CC2520_GPIO_PORTC CONFIG_GPIO_MCUX_PORTC_NAME

#define CC2520_GPIO_VREG_EN	12  /* PTC12 */
#define CC2520_GPIO_RESET	3   /* PTC3 */
#define CC2520_GPIO_FIFO	2   /* PTC2 */
#define CC2520_GPIO_CCA		1   /* PTA1 */
#define CC2520_GPIO_SFD		9   /* PTB9 */
#define CC2520_GPIO_FIFOP	4   /* PTC4 */

static struct cc2520_gpio_configuration cc2520_gpios[CC2520_GPIO_IDX_MAX] = {
	{ .dev = NULL, .pin = CC2520_GPIO_VREG_EN, },
	{ .dev = NULL, .pin = CC2520_GPIO_RESET, },
	{ .dev = NULL, .pin = CC2520_GPIO_FIFO, },
	{ .dev = NULL, .pin = CC2520_GPIO_CCA, },
	{ .dev = NULL, .pin = CC2520_GPIO_SFD, },
	{ .dev = NULL, .pin = CC2520_GPIO_FIFOP, },
};

/* CONFIG_PINMUX_INIT_PRIORITY + 1 ! */
#define CC2520_PINMUX_PRIORITY 46

struct cc2520_gpio_configuration *cc2520_configure_gpios(void)
{
	struct device *gpioa;
	struct device *gpiob;
	struct device *gpioc;
	int i;

	gpioa = device_get_binding(CC2520_GPIO_PORTA);
	if (!gpioa) {
		return NULL;
	}

	gpiob = device_get_binding(CC2520_GPIO_PORTB);
	if (!gpiob) {
		return NULL;
	}

	gpioc = device_get_binding(CC2520_GPIO_PORTC);
	if (!gpioc) {
		return NULL;
	}


	for (i = 0; i < CC2520_GPIO_IDX_MAX; i++) {
		struct device *gpio;
		int flags;

		if (i == CC2520_GPIO_IDX_SFD) {
			gpio = gpiob;
		} else if (i == CC2520_GPIO_IDX_CCA) {
			gpio = gpioa;
		} else {
			gpio = gpioc;
		}

		if (i >= 0 && i < CC2520_GPIO_IDX_FIFO) {
			flags = GPIO_DIR_OUT;
		} else if (i < CC2520_GPIO_IDX_SFD) {
			flags = GPIO_DIR_IN;
		} else {
			flags = (GPIO_DIR_IN | GPIO_INT | GPIO_INT_EDGE |
				 GPIO_INT_ACTIVE_HIGH | GPIO_INT_DEBOUNCE);
		}

		gpio_pin_configure(gpio, cc2520_gpios[i].pin, flags);
		cc2520_gpios[i].dev = gpio;
	}

	return cc2520_gpios;
}

static int fdrm_k64f_cc2520_pinmux_setup(struct device *dev)
{
	ARG_UNUSED(dev);

	struct device *porta =
		device_get_binding(CONFIG_PINMUX_MCUX_PORTA_NAME);

	struct device *portb =
		device_get_binding(CONFIG_PINMUX_MCUX_PORTB_NAME);

	struct device *portc =
		device_get_binding(CONFIG_PINMUX_MCUX_PORTC_NAME);

	pinmux_pin_set(portc,  2, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(portc,  3, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(portc,  4, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(portc, 12, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(portb,  9, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(porta,  1, PORT_PCR_MUX(kPORT_MuxAsGpio));

	return 0;
}

#elif defined(TEST_2)
#define CC2520_GPIO_PORTC CONFIG_GPIO_MCUX_PORTC_NAME

#define CC2520_GPIO_VREG_EN	12  /* PTC12 */
#define CC2520_GPIO_RESET	3   /* PTC3 */
#define CC2520_GPIO_FIFO	2   /* PTC2 */
#define CC2520_GPIO_CCA		17  /* PTC17 */
#define CC2520_GPIO_SFD		16  /* PTC16 */
#define CC2520_GPIO_FIFOP	4   /* PTC4 */

static struct cc2520_gpio_configuration cc2520_gpios[CC2520_GPIO_IDX_MAX] = {
	{ .dev = NULL, .pin = CC2520_GPIO_VREG_EN, },
	{ .dev = NULL, .pin = CC2520_GPIO_RESET, },
	{ .dev = NULL, .pin = CC2520_GPIO_FIFO, },
	{ .dev = NULL, .pin = CC2520_GPIO_CCA, },
	{ .dev = NULL, .pin = CC2520_GPIO_SFD, },
	{ .dev = NULL, .pin = CC2520_GPIO_FIFOP, },
};

/* CONFIG_PINMUX_INIT_PRIORITY + 1 ! */
#define CC2520_PINMUX_PRIORITY 46

struct cc2520_gpio_configuration *cc2520_configure_gpios(void)
{
	struct device *gpioc;
	int i;

	gpioc = device_get_binding(CC2520_GPIO_PORTC);
	if (!gpioc) {
		return NULL;
	}

	for (i = 0; i < CC2520_GPIO_IDX_MAX; i++) {
		int flags;

		if (i >= 0 && i < CC2520_GPIO_IDX_FIFO) {
			flags = GPIO_DIR_OUT;
		} else if (i < CC2520_GPIO_IDX_SFD) {
			flags = GPIO_DIR_IN;
		} else {
			flags = (GPIO_DIR_IN | GPIO_INT | GPIO_INT_EDGE |
				 GPIO_INT_ACTIVE_HIGH | GPIO_INT_DEBOUNCE);
		}

		gpio_pin_configure(gpioc, cc2520_gpios[i].pin, flags);
		cc2520_gpios[i].dev = gpioc;
	}

	return cc2520_gpios;
}

static int fdrm_k64f_cc2520_pinmux_setup(struct device *dev)
{
	ARG_UNUSED(dev);

	struct device *portc =
		device_get_binding(CONFIG_PINMUX_MCUX_PORTC_NAME);

	pinmux_pin_set(portc,  2, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(portc,  3, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(portc,  4, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(portc, 12, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(portc, 16, PORT_PCR_MUX(kPORT_MuxAsGpio));
	pinmux_pin_set(portc, 17, PORT_PCR_MUX(kPORT_MuxAsGpio));

	return 0;
}


#endif

SYS_INIT(fdrm_k64f_cc2520_pinmux_setup, POST_KERNEL, CC2520_PINMUX_PRIORITY);
