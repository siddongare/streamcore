'use strict';

const crypto = require('crypto');
const path = require('path');
const express = require('express');

const port = Number(process.env.PORT) || 3000;

function signaturesMatch(rawBody, signatureHeader, webhookSecret) {
  if (!webhookSecret || !signatureHeader) return false;

  const expected = `sha256=${crypto
    .createHmac('sha256', webhookSecret)
    .update(rawBody)
    .digest('hex')}`;
  const receivedBuffer = Buffer.from(signatureHeader, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');

  return receivedBuffer.length === expectedBuffer.length
    && crypto.timingSafeEqual(receivedBuffer, expectedBuffer);
}

async function markOrderPaidAndDeliver({ orderId, invoiceId, payload, orderStore }) {
  // Replace this in-memory placeholder with an atomic database transaction.
  orderStore.set(orderId, {
    orderId,
    invoiceId,
    paymentStatus: 'settled',
    paidAt: new Date().toISOString(),
    deliveryStatus: 'unlocked'
  });

  // Replace this log with the actual credential allocation/delivery service.
  console.log(`[delivery] Unlock Netflix credentials for order ${orderId}`, {
    invoiceId,
    storeId: payload.storeId
  });
}

function createApp(options = {}) {
  const app = express();
  const webhookSecret = options.webhookSecret ?? process.env.BTCPAY_WEBHOOK_SECRET ?? '';
  const fulfillOrder = options.fulfillOrder || markOrderPaidAndDeliver;
  const processedDeliveries = options.processedDeliveries || new Set();
  const paidOrders = options.paidOrders || new Map();
  const siteFile = path.join(__dirname, 'index.html');
  const checkoutFile = path.join(__dirname, 'gemini-code-1786288921890.html');

  app.post('/api/btcpay-webhook', express.raw({ type: 'application/json' }), async (request, response) => {
    const rawBody = request.body;
    const signature = request.get('BTCPay-Sig') || '';

    if (!webhookSecret) {
      return response.status(503).json({ error: 'BTCPAY_WEBHOOK_SECRET is not configured' });
    }

    if (!Buffer.isBuffer(rawBody) || !signaturesMatch(rawBody, signature, webhookSecret)) {
      return response.status(401).json({ error: 'Invalid webhook signature' });
    }

    let payload;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch (error) {
      return response.status(400).json({ error: 'Invalid JSON payload' });
    }

    if (payload.type !== 'InvoiceSettled') {
      return response.status(200).json({ received: true, ignored: true });
    }

    const metadata = payload.metadata && typeof payload.metadata === 'object'
      ? payload.metadata
      : {};
    const orderId = metadata.orderId || payload.orderId || metadata.order_id;
    const invoiceId = payload.invoiceId;

    if (!orderId || !invoiceId) {
      return response.status(400).json({
        error: 'InvoiceSettled payload must include invoiceId and orderId metadata'
      });
    }

    const deliveryKey = payload.originalDeliveryId
      || payload.deliveryId
      || String(invoiceId);
    if (processedDeliveries.has(deliveryKey) || paidOrders.has(String(orderId))) {
      return response.status(200).json({ received: true, duplicate: true });
    }

    try {
      await fulfillOrder({
        orderId: String(orderId),
        invoiceId: String(invoiceId),
        payload,
        orderStore: paidOrders
      });
      processedDeliveries.add(deliveryKey);
      return response.status(200).json({ received: true, orderId: String(orderId) });
    } catch (error) {
      console.error('[webhook] Failed to fulfill settled invoice', error);
      return response.status(500).json({ error: 'Unable to fulfill order' });
    }
  });

  app.get('/api/order-status', (request, response) => {
    const orderId = typeof request.query.orderId === 'string' ? request.query.orderId : '';
    const order = orderId ? paidOrders.get(orderId) : null;

    response.set('Cache-Control', 'no-store');
    return response.status(200).json({
      orderId: orderId || null,
      paid: Boolean(order && order.paymentStatus === 'settled'),
      deliveryStatus: order?.deliveryStatus || 'pending'
    });
  });

  app.get('/', (request, response) => {
    response.sendFile(siteFile);
  });

  app.get('/crypto-checkout', (request, response) => {
    response.sendFile(checkoutFile);
  });

  app.get('/success', (request, response) => {
    response.sendFile(checkoutFile);
  });

  return { app, paidOrders, processedDeliveries };
}

const { app } = createApp();

if (require.main === module) {
  app.listen(port, () => {
    console.log(`Checkout server listening on http://localhost:${port}`);
  });
}

module.exports = { app, createApp, signaturesMatch, markOrderPaidAndDeliver };
