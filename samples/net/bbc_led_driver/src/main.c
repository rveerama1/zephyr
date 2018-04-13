/*
 * Copyright (c) 2017 Linaro Limited
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#define SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#include <logging/sys_log.h>

#include <zephyr.h>
#include <led_strip.h>
#include <device.h>
#include <spi.h>
#include <misc/util.h>
#include <gpio.h>
#include <board.h>

/*
 * Number of RGB LEDs in the LED strip, adjust as needed.
 */
#if defined(CONFIG_WS2812_STRIP)
#define STRIP_NUM_LEDS 12
#define STRIP_DEV_NAME CONFIG_WS2812_STRIP_NAME
#else
#define STRIP_NUM_LEDS 24
#define STRIP_DEV_NAME CONFIG_WS2812B_SW_NAME
#endif

#define SPI_DEV_NAME "ws2812_spi"
#define DELAY_TIME K_MSEC(40)

static const struct led_rgb colors[] = {
	{ .r = 0xff, .g = 0x00, .b = 0x00, }, /* red */
	{ .r = 0x00, .g = 0xff, .b = 0x00, }, /* green */
	{ .r = 0x00, .g = 0x00, .b = 0xff, }, /* blue */
};

static const struct led_rgb black = {
	.r = 0x00,
	.g = 0x00,
	.b = 0x00,
};

/*static const struct led_rgb white = {
	.r = 0xff,
	.g = 0xff,
	.b = 0xff,
};*/

static const struct led_rgb gray = {
	.r = 0x0f,
	.g = 0x0f,
	.b = 0x0f,
};

static const struct led_rgb red = {
	.r = 0x3f,
	.g = 0x00,
	.b = 0x00,
};
static const struct led_rgb green = {
	.r = 0x3f,
	.g = 0x3f,
	.b = 0x3f,
};

static const struct led_rgb blue = {
	.r = 0x00,
	.g = 0x00,
	.b = 0x0f,
};

static struct device *gpio;

struct led_rgb black_strip[STRIP_NUM_LEDS];
struct led_rgb colored_strip0[STRIP_NUM_LEDS];
struct led_rgb colored_strip1[STRIP_NUM_LEDS];
struct led_rgb colored_strip2[STRIP_NUM_LEDS];

struct led_rgb *strips[] = {
        black_strip,
	colored_strip0,
	colored_strip1,
	colored_strip2,
};

#define USE_GPIO_PIN_1	    /*SW0_GPIO_PIN */ EXT_P1_GPIO_PIN
#define USE_GPIO_PIN_2	    /*SW1_GPIO_PIN */ EXT_P2_GPIO_PIN
#define USE_GPIO_PIN_NAME   SW0_GPIO_NAME


#define CHECK_GPIO_CLICKS   10


void main(void)
{
	struct device *strip;
	size_t i, time;
	u32_t value, last_value;

#if defined(CONFIG_SPI)
	struct device *spi;

	/* Double-check the configuration. */
	spi = device_get_binding(SPI_DEV_NAME);
	if (spi) {
		SYS_LOG_INF("Found SPI device %s", SPI_DEV_NAME);
	} else {
		SYS_LOG_ERR("SPI device not found; you must choose a SPI "
			    "device and configure its name to %s",
			    SPI_DEV_NAME);
		return;
	}
#endif

	strip = device_get_binding(STRIP_DEV_NAME);
	if (strip) {
		SYS_LOG_INF("Found LED strip device %s", STRIP_DEV_NAME);
	} else {
		SYS_LOG_ERR("LED strip device %s not found", STRIP_DEV_NAME);
		return;
	}

	/*Configuring GPIO pins*/
	gpio = device_get_binding(USE_GPIO_PIN_NAME);

        gpio_pin_configure(gpio, USE_GPIO_PIN_1,
                           (GPIO_DIR_IN | GPIO_INT| GPIO_INT_EDGE |  GPIO_PUD_PULL_DOWN | 
                            GPIO_INT_ACTIVE_HIGH/*LOW*/));
#if 0
        gpio_pin_configure(gpio, USE_GPIO_PIN_2,
                           (GPIO_DIR_IN | GPIO_INT | GPIO_INT_EDGE |  
                            GPIO_INT_ACTIVE_HIGH/*LOW*/));
#endif

#define SET_PIXEL(pixel, color) memcpy(&pixel, &color, sizeof(pixel))

	/* Fill the strips with solid color */
	for (i = 0; i < STRIP_NUM_LEDS; i++) {
		SET_PIXEL(black_strip[i], black);
		SET_PIXEL(colored_strip0[i], red);
		SET_PIXEL(colored_strip1[i], green);
		//SET_PIXEL(colored_strip2[i], blue);
		/*memcpy(&black_strip[i],  &black, sizeof(black_strip[i]));*/
	}

	SYS_LOG_INF("Displaying pattern on strip");
	time = 0;

	last_value = 1;  /*to force strip update */
	value = 0;

	while (1) {
		if (last_value != value ) {

			if(value > ARRAY_SIZE(strips)) {
				value = 0;
			}

			SYS_LOG_INF("Updating strip color to index  %u",
				    value);
			led_strip_update_rgb(strip, strips[value],
					     STRIP_NUM_LEDS);

			last_value = value;
		}

		k_sleep(DELAY_TIME);

		if( (time % CHECK_GPIO_CLICKS) == 0 ) {
			if (!gpio_pin_read(gpio, USE_GPIO_PIN_1, &value)) {
				//SYS_LOG_INF("Read %u from the port", v);
			} else {
				SYS_LOG_ERR("Cannot read GPIO 1 %s",
					    USE_GPIO_PIN_NAME);
			}
		}

		time++;
	}
}
