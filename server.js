'use strict';

require('dotenv').config();

const axios = require('axios');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const express = require('express');
const path = require('path');

const port = Number(process.env.PORT) || 3000;
const CATALOG_PRODUCTS = ['netflix', 'prime', 'spotify', 'youtube', 'capcut', 'nordvpn', 'canva', 'minecraft', 'crunchyroll', 'combo'];

function isDeliverableSlot(slot) {
  return Boolean(String(slot.delivery_item || '').trim() || String(slot.delivery_link || '').trim() || String(slot.delivery_message || '').trim());
}

function createDeliveryToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashDeliveryToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function signaturesMatch(rawBody, signatureHeader, webhookSecret) {
  if (!webhookSecret || !signatureHeader || !Buffer.isBuffer(rawBody)) return false;
  const expected = `sha256=${crypto.createHmac('sha256', webhookSecret).update(rawBody).digest('hex')}`;
  const receivedBuffer = Buffer.from(signatureHeader, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  return receivedBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(receivedBuffer, expectedBuffer);
}

function getOrigin(request) {
  const configuredOrigin = process.env.PUBLIC_URL;
  return configuredOrigin ? configuredOrigin.replace(/\/$/, '') : `${request.protocol}://${request.get('host')}`;
}

function adminOnly(request, response, next) {
  const configuredPassword = process.env.ADMIN_PASSWORD;
  const suppliedPassword = request.get('x-admin-password') || '';
  if (!configuredPassword || !crypto.timingSafeEqual(Buffer.from(suppliedPassword), Buffer.from(configuredPassword))) {
    return response.status(401).json({ error: 'Admin authentication failed' });
  }
  return next();
}

function initializeDatabase(filename) {
  const db = new Database(filename);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS inventory_slots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id TEXT NOT NULL REFERENCES products(id),
      delivery_item TEXT NOT NULL DEFAULT '',
      delivery_link TEXT,
      delivery_message TEXT,
      status TEXT NOT NULL DEFAULT 'available' CHECK(status IN ('available', 'assigned')),
      order_id TEXT UNIQUE,
      assigned_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS orders (
      order_id TEXT PRIMARY KEY,
      invoice_id TEXT UNIQUE,
      product_id TEXT NOT NULL REFERENCES products(id),
      amount REAL NOT NULL,
      currency TEXT NOT NULL,
      payment_status TEXT NOT NULL DEFAULT 'pending',
      delivery_status TEXT NOT NULL DEFAULT 'pending',
      slot_id INTEGER UNIQUE REFERENCES inventory_slots(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      paid_at TEXT,
      delivered_at TEXT,
      delivery_token_hash TEXT
    );
    CREATE TABLE IF NOT EXISTS webhook_events (
      delivery_key TEXT PRIMARY KEY,
      invoice_id TEXT,
      received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
  const orderColumns = db.prepare('PRAGMA table_info(orders)').all();
  if (!orderColumns.some((column) => column.name === 'delivery_token_hash')) db.exec('ALTER TABLE orders ADD COLUMN delivery_token_hash TEXT');
  const insertProduct = db.prepare('INSERT OR IGNORE INTO products (id, name) VALUES (?, ?)');
  const countSlots = db.prepare('SELECT COUNT(*) AS count FROM inventory_slots WHERE product_id = ?');
  const insertSlot = db.prepare('INSERT INTO inventory_slots (product_id) VALUES (?)');
  const seed = db.transaction(() => {
    for (const productId of CATALOG_PRODUCTS) {
      insertProduct.run(productId, productId);
      const missing = Math.max(0, 100 - countSlots.get(productId).count);
      for (let index = 0; index < missing; index += 1) insertSlot.run(productId);
    }
  });
  seed();
  return db;
}

function createApp(options = {}) {
  const app = express();
  app.set('trust proxy', true);
  const db = options.db || initializeDatabase(options.databaseFile || process.env.SQLITE_PATH || path.join(__dirname, 'streamox.sqlite'));
  const ltcPayHost = (options.ltcPayHost || process.env.LTC_PAY_HOST || '').replace(/\/$/, '');
  const ltcPayStoreId = options.ltcPayStoreId || process.env.LTC_PAY_STORE_ID || '';
  const ltcPayApiKey = options.ltcPayApiKey || process.env.LTC_PAY_API_KEY || '';
  const webhookSecret = options.webhookSecret || process.env.LTC_PAY_WEBHOOK_SECRET || '';
  const siteFile = path.join(__dirname, 'index.html');

  const fulfillSettledOrder = db.transaction(({ orderId, invoiceId, deliveryKey }) => {
    if (db.prepare('SELECT 1 FROM webhook_events WHERE delivery_key = ?').get(deliveryKey)) return { duplicate: true };
    const order = db.prepare('SELECT * FROM orders WHERE order_id = ?').get(orderId);
    if (!order) throw new Error('Order not found');
    if (!order.invoice_id || order.invoice_id !== invoiceId) throw new Error('Invoice does not match order');
    if (order.delivery_status === 'delivered') {
      db.prepare('INSERT INTO webhook_events (delivery_key, invoice_id) VALUES (?, ?)').run(deliveryKey, invoiceId);
      return { duplicate: true };
    }
    const slot = db.prepare("SELECT * FROM inventory_slots WHERE product_id = ? AND status = 'available' AND (TRIM(delivery_item) <> '' OR TRIM(COALESCE(delivery_link, '')) <> '' OR TRIM(COALESCE(delivery_message, '')) <> '') ORDER BY id LIMIT 1").get(order.product_id);
    if (!slot || !isDeliverableSlot(slot)) throw new Error('No deliverable inventory is available for this product');
    const now = new Date().toISOString();
    const deliveryToken = createDeliveryToken();
    const assigned = db.prepare("UPDATE inventory_slots SET status = 'assigned', order_id = ?, assigned_at = ? WHERE id = ? AND status = 'available'").run(orderId, now, slot.id);
    if (assigned.changes !== 1) throw new Error('Inventory slot was unavailable');
    db.prepare("UPDATE orders SET payment_status = 'settled', delivery_status = 'delivered', slot_id = ?, paid_at = ?, delivered_at = ?, delivery_token_hash = ? WHERE order_id = ?").run(slot.id, now, now, hashDeliveryToken(deliveryToken), orderId);
    db.prepare('INSERT INTO webhook_events (delivery_key, invoice_id) VALUES (?, ?)').run(deliveryKey, invoiceId);
    return { duplicate: false, deliveryToken };
  });

  app.post('/api/create-ltc-invoice', express.json({ limit: '20kb' }), async (request, response) => {
    const body = request.body || {};
    const amount = Number(body.amount);
    const currency = String(body.currency || 'USD').trim().toUpperCase();
    const orderId = String(body.orderId || crypto.randomUUID()).trim();
    const productId = String(body.productId || '').trim().toLowerCase();
    if (!ltcPayHost || !ltcPayStoreId || !ltcPayApiKey) return response.status(503).json({ error: 'LTCpay invoice service is not configured' });
    if (!Number.isFinite(amount) || amount <= 0) return response.status(400).json({ error: 'amount must be a positive number' });
    if (!['USD', 'LTC'].includes(currency)) return response.status(400).json({ error: 'currency must be USD or LTC' });
    if (!orderId || orderId.length > 120) return response.status(400).json({ error: 'orderId is required and must be 120 characters or fewer' });
    if (!db.prepare('SELECT 1 FROM products WHERE id = ? AND active = 1').get(productId)) return response.status(400).json({ error: 'A valid productId is required' });
    const existing = db.prepare('SELECT * FROM orders WHERE order_id = ?').get(orderId);
    if (existing && (existing.product_id !== productId || existing.amount !== amount || existing.currency !== currency)) return response.status(409).json({ error: 'orderId is already associated with a different order' });
    if (!existing) db.prepare('INSERT INTO orders (order_id, product_id, amount, currency) VALUES (?, ?, ?, ?)').run(orderId, productId, amount, currency);
    const redirectURL = `${getOrigin(request)}/success?orderId=${encodeURIComponent(orderId)}`;
    try {
      const invoiceResponse = await axios.post(`${ltcPayHost}/api/v1/stores/${encodeURIComponent(ltcPayStoreId)}/invoices`, { amount, currency, metadata: { orderId, productId }, checkout: { redirectURL } }, { headers: { Authorization: `token ${ltcPayApiKey}`, 'Content-Type': 'application/json' }, timeout: 15000 });
      const invoiceId = invoiceResponse.data?.id || invoiceResponse.data?.invoiceId;
      if (!invoiceId) return response.status(502).json({ error: 'LTCpay did not return an invoice ID' });
      db.prepare('UPDATE orders SET invoice_id = ? WHERE order_id = ?').run(String(invoiceId), orderId);
      return response.status(201).json({ invoiceId, orderId });
    } catch (error) {
      const status = error.response?.status || 502;
      console.error('[ltcpay] Invoice creation failed', { status, message: error.response?.data?.message || error.message });
      return response.status(status >= 400 && status < 500 ? status : 502).json({ error: 'Unable to create Litecoin invoice' });
    }
  });

  app.get('/api/orders/:orderId', (request, response) => {
    const order = db.prepare(`SELECT o.order_id, o.product_id, o.amount, o.currency, o.payment_status, o.delivery_status, o.created_at, o.paid_at, o.delivered_at, o.delivery_token_hash, s.delivery_item, s.delivery_link, s.delivery_message FROM orders o LEFT JOIN inventory_slots s ON s.id = o.slot_id WHERE o.order_id = ?`).get(request.params.orderId);
    if (!order) return response.status(404).json({ error: 'Order not found' });
    const token = String(request.get('x-delivery-token') || request.query.deliveryToken || '');
    const authorizedForDelivery = Boolean(order.delivery_token_hash && token && crypto.timingSafeEqual(Buffer.from(hashDeliveryToken(token)), Buffer.from(order.delivery_token_hash)));
    return response.json({ orderId: order.order_id, productId: order.product_id, amount: order.amount, currency: order.currency, paymentStatus: order.payment_status, deliveryStatus: order.delivery_status, createdAt: order.created_at, paidAt: order.paid_at, deliveredAt: order.delivered_at, delivery: order.delivery_status === 'delivered' && authorizedForDelivery ? { item: order.delivery_item, link: order.delivery_link, message: order.delivery_message } : null });
  });

  app.get('/api/admin/products', adminOnly, (request, response) => {
    const products = db.prepare(`SELECT p.id, p.name, p.active, COUNT(s.id) AS totalSlots, SUM(CASE WHEN s.status = 'available' THEN 1 ELSE 0 END) AS availableSlots, SUM(CASE WHEN s.status = 'assigned' THEN 1 ELSE 0 END) AS assignedSlots FROM products p LEFT JOIN inventory_slots s ON s.product_id = p.id GROUP BY p.id ORDER BY p.id`).all();
    response.json({ products });
  });
  app.get('/api/admin/orders', adminOnly, (request, response) => response.json({ orders: db.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 200').all() }));
  app.get('/api/admin/slots/:productId', adminOnly, (request, response) => response.json({ slots: db.prepare('SELECT * FROM inventory_slots WHERE product_id = ? ORDER BY id').all(request.params.productId) }));
  app.post('/api/admin/slots', adminOnly, express.json({ limit: '20kb' }), (request, response) => {
    const { productId, deliveryItem = '', deliveryLink = null, deliveryMessage = null } = request.body || {};
    if (!db.prepare('SELECT 1 FROM products WHERE id = ?').get(productId)) return response.status(400).json({ error: 'Unknown productId' });
    const result = db.prepare('INSERT INTO inventory_slots (product_id, delivery_item, delivery_link, delivery_message) VALUES (?, ?, ?, ?)').run(productId, String(deliveryItem), deliveryLink ? String(deliveryLink) : null, deliveryMessage ? String(deliveryMessage) : null);
    return response.status(201).json({ id: result.lastInsertRowid });
  });
  app.patch('/api/admin/slots/:slotId', adminOnly, express.json({ limit: '20kb' }), (request, response) => {
    const slot = db.prepare('SELECT * FROM inventory_slots WHERE id = ?').get(request.params.slotId);
    if (!slot) return response.status(404).json({ error: 'Slot not found' });
    if (slot.status === 'assigned') return response.status(409).json({ error: 'Assigned slots are immutable and are never deleted' });
    const body = request.body || {};
    db.prepare('UPDATE inventory_slots SET delivery_item = ?, delivery_link = ?, delivery_message = ? WHERE id = ?').run(body.deliveryItem === undefined ? slot.delivery_item : String(body.deliveryItem), body.deliveryLink === undefined ? slot.delivery_link : (body.deliveryLink ? String(body.deliveryLink) : null), body.deliveryMessage === undefined ? slot.delivery_message : (body.deliveryMessage ? String(body.deliveryMessage) : null), slot.id);
    return response.json({ updated: true });
  });

  async function webhookHandler(request, response) {
    const rawBody = request.body;
    const signature = request.get('BTCPAY-SIG') || '';
    if (!webhookSecret || webhookSecret.startsWith('replace-with-')) return response.status(503).json({ error: 'LTC_PAY_WEBHOOK_SECRET is not configured' });
    if (!signaturesMatch(rawBody, signature, webhookSecret)) return response.status(401).json({ error: 'Invalid webhook signature' });
    let payload;
    try { payload = JSON.parse(rawBody.toString('utf8')); } catch { return response.status(400).json({ error: 'Invalid JSON payload' }); }
    if (payload.type !== 'InvoiceSettled') return response.status(200).json({ received: true, ignored: true });
    const metadata = payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : {};
    const orderId = metadata.orderId || payload.orderId || metadata.order_id;
    const invoiceId = payload.invoiceId || payload.id;
    if (!orderId || !invoiceId) return response.status(400).json({ error: 'InvoiceSettled payload must include invoiceId and orderId metadata' });
    try {
      const result = fulfillSettledOrder({ orderId: String(orderId), invoiceId: String(invoiceId), deliveryKey: String(payload.originalDeliveryId || payload.deliveryId || invoiceId) });
      return response.status(200).json({ received: true, orderId: String(orderId), duplicate: result.duplicate, deliveryToken: result.deliveryToken });
    } catch (error) {
      console.error('[webhook] Failed to fulfill settled invoice', error.message);
      return response.status(500).json({ error: 'Unable to fulfill order' });
    }
  }

  app.post('/api/ltcpay-webhook', express.raw({ type: 'application/json' }), webhookHandler);
  app.post('/api/btcpay-webhook', express.raw({ type: 'application/json' }), webhookHandler);
  app.get('/success', (request, response) => response.redirect(`/?orderId=${encodeURIComponent(String(request.query.orderId || ''))}#buyer-orders`));
  app.get('/', (request, response) => response.sendFile(siteFile));
  return { app, db };
}

const { app } = createApp();
if (require.main === module) app.listen(port, () => console.log(`Checkout server listening on http://localhost:${port}`));
module.exports = { app, createApp, signaturesMatch, initializeDatabase };
