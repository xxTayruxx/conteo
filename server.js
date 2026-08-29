require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || 'https://conteo-rt2c.onrender.com';
const REDIRECT_URI = process.env.ML_REDIRECT_URI || `${BASE_URL}/auth/callback`;
const CLIENT_ID = process.env.ML_CLIENT_ID;
const CLIENT_SECRET = process.env.ML_CLIENT_SECRET;
const AUTH_DOMAIN = process.env.ML_AUTH_DOMAIN || 'https://auth.mercadolibre.com.ar';
const API_BASE = process.env.ML_API_BASE || 'https://api.mercadolibre.com';

// Offset de Argentina (UTC-3, sin horario de verano actualmente)
const AR_OFFSET_MS = -3 * 60 * 60 * 1000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

let oauthState = null;
let pkceVerifier = null;
let tokenCache = null;

// Clientes conectados por Server-Sent Events (notificaciones en tiempo real)
const sseClients = new Set();

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS me_tokens (
        id INT PRIMARY KEY,
        tokens JSONB NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS product_costs (
        item_id VARCHAR(50) PRIMARY KEY,
        cost_price NUMERIC(12,2) NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        order_id VARCHAR(50),
        title TEXT,
        amount NUMERIC(12,2),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    tokenCache = await loadTokens();
  } catch (err) {
    console.error('Error DB:', err);
  }
}

async function loadTokens() {
  try {
    const res = await pool.query('SELECT tokens FROM me_tokens WHERE id = 1');
    return res.rows[0]?.tokens || null;
  } catch {
    return null;
  }
}

async function saveTokens(tokens) {
  try {
    tokenCache = tokens;
    await pool.query(`
      INSERT INTO me_tokens (id, tokens, updated_at)
      VALUES (1, $1, NOW())
      ON CONFLICT (id) DO UPDATE SET tokens = EXCLUDED.tokens, updated_at = NOW();
    `, [JSON.stringify(tokens)]);
  } catch (err) {
    console.error('Error guardando tokens:', err);
  }
}

function randomState() { return crypto.randomBytes(24).toString('hex'); }
function base64url(buf) { return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function makePkce() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

async function tokenRequest(body) {
  const response = await fetch(`${API_BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error_description || data.error);
  return data;
}

async function refreshAccessToken() {
  if (!tokenCache?.refresh_token) throw new Error('No hay refresh_token');
  const data = await tokenRequest({
    grant_type: 'refresh_token',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: tokenCache.refresh_token
  });
  await saveTokens({
    ...data,
    obtained_at: Date.now(),
    expires_at: Date.now() + ((data.expires_in || 21600) * 1000)
  });
  return data.access_token;
}

async function getAccessToken() {
  if (!tokenCache?.access_token) throw new Error('Mercado Libre no conectado.');
  if (tokenCache.expires_at && Date.now() < tokenCache.expires_at - 60000) {
    return tokenCache.access_token;
  }
  return refreshAccessToken();
}

async function mlFetch(endpoint) {
  const accessToken = await getAccessToken();
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' }
  });
  if (res.status === 401) {
    await refreshAccessToken();
    return mlFetch(endpoint);
  }
  return res.json();
}

// ---------- Utilidades de fechas (hora Argentina) ----------

function nowAR() {
  return new Date(Date.now() + AR_OFFSET_MS);
}

function startOfDayAR(dayShift = 0) {
  const d = nowAR();
  d.setUTCDate(d.getUTCDate() + dayShift);
  d.setUTCHours(0, 0, 0, 0);
  return new Date(d.getTime() - AR_OFFSET_MS);
}

function startOfMonthAR() {
  const d = nowAR();
  d.setUTCDate(1);
  d.setUTCHours(0, 0, 0, 0);
  return new Date(d.getTime() - AR_OFFSET_MS);
}

function getDateRange(period) {
  const now = new Date();
  switch (period) {
    case 'yesterday':
      return { from: startOfDayAR(-1), to: startOfDayAR(0) };
    case 'week':
      // últimos 7 días (rolling), incluye hoy
      return { from: startOfDayAR(-6), to: now };
    case 'month':
      return { from: startOfMonthAR(), to: now };
    case 'today':
    default:
      return { from: startOfDayAR(0), to: now };
  }
}

// ---------- Órdenes de Mercado Libre ----------

async function fetchOrdersByRange(sellerId, from, to, maxResults = 300) {
  const limit = 50;
  let offset = 0;
  const all = [];
  while (true) {
    const url = `/orders/search?seller=${sellerId}` +
      `&order.date_created.from=${encodeURIComponent(from.toISOString())}` +
      `&order.date_created.to=${encodeURIComponent(to.toISOString())}` +
      `&sort=date_desc&limit=${limit}&offset=${offset}`;
    const data = await mlFetch(url);
    const results = data.results || [];
    all.push(...results);
    const total = data.paging?.total ?? all.length;
    offset += limit;
    if (offset >= total || all.length >= maxResults || results.length === 0) break;
  }
  return all;
}

// Estados de ML que no representan una venta real y no deben sumar a la facturación
const EXCLUDED_STATUSES = new Set(['cancelled', 'invalid']);

function computeMetrics(orders, costsMap) {
  const validOrders = orders.filter(o => !EXCLUDED_STATUSES.has(o.status));
  const cancelledCount = orders.length - validOrders.length;

  let totalRevenue = 0;
  let totalFees = 0;
  let totalShipping = 0;
  let totalProductCost = 0;

  const parsedOrders = validOrders.map(order => {
    const item = order.order_items[0];
    const gross = order.total_amount || 0;
    const fee = order.order_items.reduce((acc, i) => acc + (i.sale_fee || 0), 0);
    const shipping = order.shipping?.cost || 0;
    const unitCost = costsMap[item.item.id] || 0;
    const productCost = unitCost * item.quantity;
    const netProfit = gross - fee - shipping - productCost;

    totalRevenue += gross;
    totalFees += fee;
    totalShipping += shipping;
    totalProductCost += productCost;

    return {
      id: order.id,
      date: order.date_created,
      title: item.item.title,
      sku: item.item.id,
      quantity: item.quantity,
      status: order.status,
      financials: {
        gross,
        fee,
        shipping,
        productCost,
        netProfit,
        margin: gross > 0 ? ((netProfit / gross) * 100).toFixed(1) : 0
      }
    };
  });

  const netProfitTotal = totalRevenue - totalFees - totalShipping - totalProductCost;

  return {
    parsedOrders,
    summary: {
      totalRevenue,
      totalFees,
      totalShipping,
      totalProductCost,
      netProfitTotal,
      overallMargin: totalRevenue > 0 ? ((netProfitTotal / totalRevenue) * 100).toFixed(1) : 0,
      totalOrders: validOrders.length,
      cancelledOrders: cancelledCount
    }
  };
}

// ---------- Stock / alertas de quiebre ----------

async function getStockAlerts() {
  if (!tokenCache?.user_id) throw new Error('Mercado Libre no conectado');

  // Velocidad de venta calculada sobre los últimos 30 días
  const to = new Date();
  const from = new Date(to.getTime() - 30 * 24 * 60 * 60 * 1000);
  const orders = await fetchOrdersByRange(tokenCache.user_id, from, to, 500);

  const unitsBySku = {};
  orders.filter(o => !EXCLUDED_STATUSES.has(o.status)).forEach(o => {
    (o.order_items || []).forEach(i => {
      const id = i.item.id;
      unitsBySku[id] = (unitsBySku[id] || 0) + i.quantity;
    });
  });

  const skuIds = Object.keys(unitsBySku);
  if (skuIds.length === 0) return [];

  // Traer stock real desde ML en tandas de 20 (límite de la API multiget)
  const stockMap = {};
  for (let i = 0; i < skuIds.length; i += 20) {
    const batch = skuIds.slice(i, i + 20);
    const data = await mlFetch(`/items?ids=${batch.join(',')}&attributes=id,title,available_quantity`);
    (Array.isArray(data) ? data : []).forEach(entry => {
      if (entry.code === 200 && entry.body) {
        stockMap[entry.body.id] = {
          title: entry.body.title,
          stock: entry.body.available_quantity ?? 0
        };
      }
    });
  }

  const alerts = skuIds.map(id => {
    const avgDaily = unitsBySku[id] / 30;
    const info = stockMap[id] || { title: id, stock: 0 };
    const daysRemaining = avgDaily > 0 ? info.stock / avgDaily : null;
    return {
      itemId: id,
      title: info.title,
      stock: info.stock,
      unitsSold30d: unitsBySku[id],
      avgDailySales: parseFloat(avgDaily.toFixed(2)),
      daysRemaining: daysRemaining !== null ? parseFloat(daysRemaining.toFixed(1)) : null
    };
  });

  alerts.sort((a, b) => {
    if (a.daysRemaining === null) return 1;
    if (b.daysRemaining === null) return -1;
    return a.daysRemaining - b.daysRemaining;
  });

  return alerts;
}

// ---------- Server-Sent Events (tiempo real) ----------

function broadcast(type, data) {
  const payload = `data: ${JSON.stringify({ type, data })}\n\n`;
  for (const res of sseClients) {
    res.write(payload);
  }
}

app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });
  res.write('retry: 5000\n\n');
  sseClients.add(res);

  const heartbeat = setInterval(() => res.write(':hb\n\n'), 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
});

// ---------- OAuth ----------

app.get('/auth/login', (req, res) => {
  oauthState = randomState();
  const pkce = makePkce();
  pkceVerifier = pkce.verifier;
  const url = new URL(`${AUTH_DOMAIN}/authorization`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('state', oauthState);
  url.searchParams.set('code_challenge', pkce.challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  res.redirect(url.toString());
});

app.get('/auth/callback', async (req, res) => {
  try {
    const data = await tokenRequest({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code: req.query.code,
      redirect_uri: REDIRECT_URI,
      code_verifier: pkceVerifier
    });
    await saveTokens({
      ...data,
      obtained_at: Date.now(),
      expires_at: Date.now() + ((data.expires_in || 21600) * 1000)
    });
    res.redirect('/?connected=1');
  } catch (e) {
    res.status(500).send(`Error de conexión: ${e.message}`);
  }
});

// ---------- API ----------

app.get('/api/status', async (req, res) => {
  res.json({
    ok: true,
    connected: !!tokenCache?.access_token,
    user_id: tokenCache?.user_id || null
  });
});

// Métricas con filtro de período: today | yesterday | week | month
app.get('/api/live-metrics', async (req, res) => {
  try {
    if (!tokenCache?.user_id) throw new Error('Mercado Libre no conectado');

    const period = ['today', 'yesterday', 'week', 'month'].includes(req.query.period)
      ? req.query.period
      : 'today';

    const { from, to } = getDateRange(period);
    const orders = await fetchOrdersByRange(tokenCache.user_id, from, to);

    const costsRes = await pool.query('SELECT * FROM product_costs');
    const costsMap = Object.fromEntries(costsRes.rows.map(r => [r.item_id, parseFloat(r.cost_price)]));

    const { parsedOrders, summary } = computeMetrics(orders, costsMap);

    res.json({ ok: true, period, summary, orders: parsedOrders });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Alertas de stock: días restantes según velocidad de venta real
app.get('/api/stock-alerts', async (req, res) => {
  try {
    const alerts = await getStockAlerts();
    res.json({ ok: true, alerts });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Historial de notificaciones (para carga inicial de pantalla)
app.get('/api/notifications', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 20');
    res.json({ ok: true, notifications: r.rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Guardar costos de producto
app.post('/api/costs', async (req, res) => {
  try {
    const { itemId, costPrice } = req.body;
    await pool.query(`
      INSERT INTO product_costs (item_id, cost_price, updated_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (item_id) DO UPDATE SET cost_price = EXCLUDED.cost_price, updated_at = NOW();
    `, [itemId, costPrice]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Webhook de Mercado Libre: guarda la notificación y la empuja en vivo por SSE
app.post('/api/webhooks/meli', async (req, res) => {
  res.status(200).send('OK'); // Responder a ML de inmediato, procesar después

  try {
    const { topic, resource } = req.body;
    if (topic === 'orders_v2' && resource) {
      const orderData = await mlFetch(resource);
      const item = orderData.order_items?.[0];
      const title = item?.item?.title || 'Venta nueva';
      const amount = orderData.total_amount || 0;

      await pool.query(
        `INSERT INTO notifications (order_id, title, amount) VALUES ($1, $2, $3)`,
        [String(orderData.id), title, amount]
      );

      broadcast('new_order', {
        orderId: orderData.id,
        title,
        amount,
        date: orderData.date_created
      });

      console.log('Nueva orden recibida vía Webhook:', orderData.id);
    }
  } catch (err) {
    console.error('Error procesando webhook:', err.message);
  }
});

app.listen(PORT, async () => {
  await initDB();
  console.log(`Servidor activo en puerto ${PORT}`);
});
