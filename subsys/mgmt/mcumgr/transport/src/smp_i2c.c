/*
 * Copyright (c) 2026 CrossControl AB
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief I2C transport for the mcumgr SMP protocol.
 *
 * Binary framing: [LEN_H][LEN_L][RAW SMP PACKET...]
 * LEN is the payload length in bytes (big-endian), not counting the 2 length
 * bytes themselves.  The host always issues a single read of (2 + MTU) bytes
 * and slices the response by LEN.  LEN == 0x0000 means "not ready".
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/net_buf.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/logging/log.h>
#include <zephyr/mgmt/mcumgr/mgmt/mgmt.h>
#include <zephyr/mgmt/mcumgr/smp/smp.h>
#include <zephyr/mgmt/mcumgr/transport/smp.h>

#include <mgmt/mcumgr/transport/smp_internal.h>

LOG_MODULE_REGISTER(smp_i2c, CONFIG_MCUMGR_TRANSPORT_I2C_LOG_LEVEL);

BUILD_ASSERT(CONFIG_MCUMGR_TRANSPORT_I2C_MTU != 0, "CONFIG_MCUMGR_TRANSPORT_I2C_MTU must be > 0");

/* Get the I2C device from devicetree */
#define SMP_I2C_NODE DT_ALIAS(smp_i2c)

#if !DT_NODE_EXISTS(SMP_I2C_NODE)
#error "No smp-i2c alias found in devicetree. Please add it to your board overlay."
#endif

static const struct device *const smp_i2c_dev = DEVICE_DT_GET(SMP_I2C_NODE);

/* I2C target address from Kconfig */
#define SMP_I2C_TARGET_ADDRESS CONFIG_MCUMGR_TRANSPORT_I2C_TARGET_ADDRESS

/* Buffer sizes — both RX and TX hold the 2-byte length prefix + MTU payload */
#define SMP_I2C_RX_BUF_SIZE (2 + CONFIG_MCUMGR_TRANSPORT_I2C_MTU)
/* 2-byte length prefix + raw SMP payload */
#define SMP_I2C_TX_BUF_SIZE (2 + CONFIG_MCUMGR_TRANSPORT_I2C_MTU)

/* RX/TX state structures */
struct smp_i2c_rx_state {
	uint8_t buf[SMP_I2C_RX_BUF_SIZE];
	size_t len;
	bool receiving;
};

struct smp_i2c_tx_state {
	uint8_t buf[SMP_I2C_TX_BUF_SIZE];
	size_t len;
	size_t offset;
	bool has_data;
};

static struct smp_i2c_rx_state rx_state;
static struct smp_i2c_tx_state tx_state;

/* Flag to indicate transport is fully initialized */
static bool smp_i2c_initialized;

static void smp_i2c_process_rx_queue(struct k_work *work);

static struct k_work smp_i2c_work;

static struct smp_transport smp_i2c_transport;

#ifdef CONFIG_SMP_CLIENT
static struct smp_client_transport_entry smp_client_transport;
#endif

/**
 * @brief Process received I2C data and dispatch an SMP packet.
 *
 * Wire format: buf[0..1] = big-endian payload length, buf[2..] = raw SMP.
 */
static void smp_i2c_process_rx_queue(struct k_work *work)
{
	struct net_buf *nb;
	uint16_t pkt_len;

	if (rx_state.len < 2) {
		LOG_ERR("I2C RX too short: %zu bytes", rx_state.len);
		rx_state.len = 0;
		return;
	}

	pkt_len = ((uint16_t)rx_state.buf[0] << 8) | rx_state.buf[1];

	/* Valid SMP packets are always >= 8 bytes (struct smp_hdr minimum) */
	if (pkt_len < 8 || pkt_len > CONFIG_MCUMGR_TRANSPORT_I2C_MTU) {
		LOG_ERR("I2C RX invalid LEN: %u (must be 8..%u)", pkt_len,
			CONFIG_MCUMGR_TRANSPORT_I2C_MTU);
		rx_state.len = 0;
		return;
	}

	if (rx_state.len != (size_t)(2 + pkt_len)) {
		LOG_ERR("I2C RX length mismatch: got %zu, expected %u", rx_state.len, 2 + pkt_len);
		rx_state.len = 0;
		return;
	}

	nb = smp_packet_alloc();
	if (nb == NULL) {
		LOG_ERR("Failed to allocate SMP packet");
		rx_state.len = 0;
		return;
	}

	if (net_buf_tailroom(nb) < pkt_len) {
		LOG_ERR("net_buf too small");
		smp_packet_free(nb);
		rx_state.len = 0;
		return;
	}

	net_buf_add_mem(nb, &rx_state.buf[2], pkt_len);
	rx_state.len = 0;
	rx_state.receiving = false;

	LOG_DBG("SMP binary request: %u bytes", pkt_len);
	smp_rx_req(&smp_i2c_transport, nb);
}

/**
 * @brief I2C target write requested callback.
 *
 * Called when the I2C controller initiates a write transaction.
 * Resets both RX and TX state so stale responses are not returned.
 */
static int smp_i2c_target_write_requested_cb(struct i2c_target_config *config)
{
	ARG_UNUSED(config);
	unsigned int key = irq_lock();

	rx_state.len = 0;
	rx_state.receiving = true;
	/* Invalidate any stale response */
	tx_state.has_data = false;
	tx_state.len = 0;
	tx_state.offset = 0;

	irq_unlock(key);
	return 0;
}

/**
 * @brief I2C target write received callback.
 *
 * Called for each byte received from the I2C controller during a write transaction.
 */
static int smp_i2c_target_write_received_cb(struct i2c_target_config *config, uint8_t val)
{
	ARG_UNUSED(config);

	/* Check for buffer overflow */
	if (rx_state.len >= SMP_I2C_RX_BUF_SIZE) {
		LOG_ERR("I2C RX buffer overflow");
		rx_state.len = 0;
		rx_state.receiving = false;
		return -ENOMEM;
	}

	rx_state.buf[rx_state.len++] = val;

	return 0;
}

/**
 * @brief I2C target read requested callback.
 *
 * Called when the I2C controller initiates a read transaction.
 * Returns the first byte of the TX buffer, or 0x00 when not ready.
 * LEN == 0x0000 is the "not ready" sentinel.
 */
static int smp_i2c_target_read_requested_cb(struct i2c_target_config *config, uint8_t *val)
{
	ARG_UNUSED(config);
	/* Never advance offset when not ready; host detects LEN==0 and retries */
	if (tx_state.has_data && tx_state.offset < tx_state.len) {
		*val = tx_state.buf[tx_state.offset++];
	} else {
		*val = 0x00;
	}
	return 0;
}

/**
 * @brief I2C target read processed callback.
 *
 * Called after each byte is successfully transmitted to the I2C controller.
 */
static int smp_i2c_target_read_processed_cb(struct i2c_target_config *config, uint8_t *val)
{
	ARG_UNUSED(config);
	if (tx_state.has_data && tx_state.offset < tx_state.len) {
		*val = tx_state.buf[tx_state.offset++];
	} else {
		if (tx_state.len > 0 && tx_state.offset >= tx_state.len) {
			/* All bytes delivered; reset for next response */
			tx_state.has_data = false;
			tx_state.len = 0;
			tx_state.offset = 0;
		}
		*val = 0x00;
	}
	return 0;
}

/**
 * @brief I2C target stop callback.
 *
 * Called when the I2C controller sends a stop condition.
 */
static int smp_i2c_target_stop_cb(struct i2c_target_config *config)
{
	ARG_UNUSED(config);

	/* If we were receiving data, schedule processing */
	if (smp_i2c_initialized && rx_state.receiving && rx_state.len > 0) {
		k_work_submit(&smp_i2c_work);
	}

	return 0;
}

/* I2C target callbacks - must be static to persist after init */
static struct i2c_target_callbacks smp_i2c_target_callbacks;

/* I2C target configuration - must be static to persist after init */
static struct i2c_target_config smp_i2c_target_cfg;

/**
 * @brief Get MTU for I2C transport.
 */
static uint16_t smp_i2c_get_mtu(const struct net_buf *nb)
{
	ARG_UNUSED(nb);
	return CONFIG_MCUMGR_TRANSPORT_I2C_MTU;
}

/**
 * @brief Transmit an SMP packet over I2C.
 *
 * Stores the binary-framed response in the TX buffer for the I2C
 * controller to read with a single (2 + MTU)-byte transaction.
 */
static int smp_i2c_tx_pkt(struct net_buf *nb)
{
	unsigned int key;
	uint16_t pkt_len = nb->len;

	if (pkt_len > CONFIG_MCUMGR_TRANSPORT_I2C_MTU) {
		LOG_ERR("SMP packet too large: %u > %u", pkt_len, CONFIG_MCUMGR_TRANSPORT_I2C_MTU);
		smp_packet_free(nb);
		return -ENOMEM;
	}

	key = irq_lock();
	tx_state.buf[0] = (pkt_len >> 8) & 0xFF;
	tx_state.buf[1] = pkt_len & 0xFF;
	memcpy(&tx_state.buf[2], nb->data, pkt_len);
	tx_state.len = 2 + pkt_len;
	tx_state.offset = 0;
	tx_state.has_data = true;
	/* Bytes buf[2+pkt_len .. SMP_I2C_TX_BUF_SIZE) are implicitly 0x00 (padding).
	 * The host always reads 2+MTU bytes in one transaction and slices by LEN.
	 */
	irq_unlock(key);

	smp_packet_free(nb);
	LOG_INF("SMP binary response ready: %u bytes", pkt_len);
	return 0;
}

/**
 * @brief Initialize the I2C SMP transport.
 */
static int smp_i2c_init(void)
{
	int rc;

	/* Check if I2C device pointer is valid */
	if (smp_i2c_dev == NULL) {
		LOG_ERR("I2C device pointer is NULL - check devicetree smp-i2c alias");
		return -ENODEV;
	}

	/* Check if I2C device is ready */
	if (!device_is_ready(smp_i2c_dev)) {
		LOG_ERR("I2C device %s is not ready", smp_i2c_dev->name);
		return -ENODEV;
	}

	/* Initialize RX/TX state */
	memset(&rx_state, 0, sizeof(rx_state));
	memset(&tx_state, 0, sizeof(tx_state));

	/* Initialize work item */
	k_work_init(&smp_i2c_work, smp_i2c_process_rx_queue);

	/* Initialize callbacks structure */
	smp_i2c_target_callbacks.write_requested = smp_i2c_target_write_requested_cb;
	smp_i2c_target_callbacks.write_received = smp_i2c_target_write_received_cb;
	smp_i2c_target_callbacks.read_requested = smp_i2c_target_read_requested_cb;
	smp_i2c_target_callbacks.read_processed = smp_i2c_target_read_processed_cb;
	smp_i2c_target_callbacks.stop = smp_i2c_target_stop_cb;

	/* Initialize target configuration */
	smp_i2c_target_cfg.address = SMP_I2C_TARGET_ADDRESS;
	smp_i2c_target_cfg.callbacks = &smp_i2c_target_callbacks;
	smp_i2c_target_cfg.flags = 0;

	/* Configure SMP transport functions */
	smp_i2c_transport.functions.output = smp_i2c_tx_pkt;
	smp_i2c_transport.functions.get_mtu = smp_i2c_get_mtu;

	/* Register SMP transport */
	rc = smp_transport_init(&smp_i2c_transport);
	if (rc != 0) {
		LOG_ERR("Failed to initialize SMP transport: %d", rc);
		return rc;
	}

	/* Mark as initialized BEFORE registering I2C target
	 * (i2c_target_register enables interrupts immediately)
	 */
	smp_i2c_initialized = true;

	/* Register as I2C target - this enables interrupts immediately */
	rc = i2c_target_register(smp_i2c_dev, &smp_i2c_target_cfg);
	if (rc != 0) {
		LOG_ERR("Failed to register I2C target: %d", rc);
		smp_i2c_initialized = false;
		return rc;
	}

	LOG_INF("I2C SMP transport initialized at address 0x%02x", SMP_I2C_TARGET_ADDRESS);

#ifdef CONFIG_SMP_CLIENT
	smp_client_transport.smpt = &smp_i2c_transport;
	smp_client_transport.smpt_type = SMP_I2C_TRANSPORT;
	smp_client_transport_register(&smp_client_transport);
	LOG_DBG("I2C SMP client transport registered");
#endif

	return 0;
}

SYS_INIT(smp_i2c_init, APPLICATION, CONFIG_MCUMGR_TRANSPORT_I2C_INIT_PRIORITY);
