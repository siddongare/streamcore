'use strict';

require('dotenv').config();

const axios = require('axios');
const crypto = require('crypto');
const express = require('express');
const path = require('path');

const port = Number(process.env.PORT) || 3000;

function signaturesMatch(rawBody, signatureHeader, webhookSecret) {
  if (!webhookSecret || !signatureHeader || !Buffer.isBuffer(rawBody)) return false;

  const expected = `sha256=${crypto
    .createHmac('sha256', webhookSecret)
    .update(rawBody)
    .digest('hex')}`;
  const receivedBuffer = Buffer.from(signatureHeader, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');

  return receivedBuffer.length === expectedBuffer.length
    && crypto.timingSafeEqual(receivedBuffer, expectedBuffer);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  })[character]);
}

function getOrigin(request) {
  const configuredOrigin = process.env.PUBLIC_URL;
  if (configuredOrigin) return configuredOrigin.replace(/\/$/, '');
  return `${request.protocol}://${request.get('host')}`;
}

async function markOrderPaidAndDeliver({ orderId, invoiceId, payload, orderStore }) {
  // Replace this in-memory placeholder with an atomic database transaction.
  orderStore.set(orderId, {
    orderId,
    invoiceId,
    paymentStatus: 'settled',
    paidAt: new Date().toISOString(),
    deliveryStatus: 'ready'
  });

  // Replace this with the secure product-allocation and delivery service.
  console.log(`[delivery] Payment settled for order ${orderId}`, {
    invoiceId,
    storeId: payload.storeId
  });
}

function createApp(options = {}) {
  const app = express();
  app.set('trust proxy', true);

  const ltcPayHost = (options.ltcPayHost || process.env.LTC_PAY_HOST || '').replace(/\/$/, '');
  const ltcPayStoreId = options.ltcPayStoreId || process.env.LTC_PAY_STORE_ID || '';
  const ltcPayApiKey = options.ltcPayApiKey || process.env.LTC_PAY_API_KEY || '';
  const webhookSecret = options.webhookSecret || process.env.LTC_PAY_WEBHOOK_SECRET || '';
  const fulfillOrder = options.fulfillOrder || markOrderPaidAndDeliver;
  const processedDeliveries = options.processedDeliveries || new Set();
  const paidOrders = options.paidOrders || new Map();
  const siteFile = path.join(__dirname, 'index.html');

  app.post('/api/create-ltc-invoice', express.json({ limit: '20kb' }), async (request, response) => {
    const body = request.body || {};
    const amount = Number(body.amount);
    const currency = String(body.currency || 'USD').trim().toUpperCase();
    const orderId = String(body.orderId || crypto.randomUUID()).trim();

    if (!ltcPayHost || !ltcPayStoreId || !ltcPayApiKey) {
      return response.status(503).json({ error: 'LTCpay invoice service is not configured' });
    }
    if (!Number.isFinite(amount) || amount <= 0) {
      return response.status(400).json({ error: 'amount must be a positive number' });
    }
    if (!['USD', 'LTC'].includes(currency)) {
      return response.status(400).json({ error: 'currency must be USD or LTC' });
    }
    if (!orderId || orderId.length > 120) {
      return response.status(400).json({ error: 'orderId is required and must be 120 characters or fewer' });
    }

    const redirectURL = `${getOrigin(request)}/success?orderId=${encodeURIComponent(orderId)}`;

    try {
      const invoiceResponse = await axios.post(
        `${ltcPayHost}/api/v1/stores/${encodeURIComponent(ltcPayStoreId)}/invoices`,
        {
          amount,
          currency,
          metadata: { orderId },
          checkout: { redirectURL }
        },
        {
          headers: {
            Authorization: `token ${ltcPayApiKey}`,
            'Content-Type': 'application/json'
          },
          timeout: 15000
        }
      );
      const invoiceId = invoiceResponse.data?.id || invoiceResponse.data?.invoiceId;

      if (!invoiceId) {
        return response.status(502).json({ error: 'LTCpay did not return an invoice ID' });
      }

      return response.status(201).json({ invoiceId, orderId });
    } catch (error) {
      const status = error.response?.status || 502;
      console.error('[ltcpay] Invoice creation failed', {
        status,
        message: error.response?.data?.message || error.message
      });
      return response.status(status >= 400 && status < 500 ? status : 502).json({
        error: 'Unable to create Litecoin invoice'
      });
    }
  });

  async function webhookHandler(request, response) {
    const rawBody = request.body;
    const signature = request.get('BTCPAY-SIG') || '';

    if (!webhookSecret || webhookSecret.startsWith('replace-with-')) {
      return response.status(503).json({ error: 'LTC_PAY_WEBHOOK_SECRET is not configured' });
    }
    if (!signaturesMatch(rawBody, signature, webhookSecret)) {
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

    const metadata = payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : {};
    const orderId = metadata.orderId || payload.orderId || metadata.order_id;
    const invoiceId = payload.invoiceId || payload.id;

    if (!orderId || !invoiceId) {
      return response.status(400).json({
        error: 'InvoiceSettled payload must include invoiceId and orderId metadata'
      });
    }

    const deliveryKey = payload.originalDeliveryId || payload.deliveryId || String(invoiceId);
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
  }

  app.post('/api/ltcpay-webhook', express.raw({ type: 'application/json' }), webhookHandler);
  // Keeps the previous webhook URL working while you update LTCpay's dashboard.
  app.post('/api/btcpay-webhook', express.raw({ type: 'application/json' }), webhookHandler);

  app.get('/success', (request, response) => {
    const orderId = escapeHtml(String(request.query.orderId || 'pending'));
    response.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Payment confirmed</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b090c;color:#fff;font-family:system-ui,sans-serif}.card{width:min(440px,calc(100% - 40px));padding:38px;border:1px solid #372536;border-radius:20px;background:#141016;text-align:center;box-shadow:0 24px 70px rgba(0,0,0,.45)}.mark{display:grid;place-items:center;width:58px;height:58px;margin:auto;border-radius:50%;background:#173d2a;color:#83e6af;font-size:25px}.id{margin-top:14px;color:#a99aaa;font-size:13px}a{display:inline-block;margin-top:25px;color:#ff5bea;text-decoration:none}</style></head><body><main class="card"><div class="mark">OK</div><h1>Payment confirmed</h1><p>Your order is in the delivery queue.</p><p class="id">Order ID: ${orderId}</p><a href="/">Return to store</a></main></body></html>`);
  });

  app.get('/', (request, response) => {
    response.sendFile(siteFile);
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
