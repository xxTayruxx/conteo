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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

let oauthState = null;
let pkceVerifier = null;
let tokenCache = null;

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
      CREATE TABLE IF NOT EXISTS daily_ads_spend (
        spend_date DATE PRIMARY KEY DEFAULT CURRENT_DATE,
        amount NUMERIC(12,2) NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    tokenCache = await loadTokens();
  } catch (err) {
    console.error('Error inicializando DB:', err);
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
  const res = await fetch(`${API_BASE}${endpoint}`, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' }
  });
  if (res.status === 401) {
    await refreshAccessToken();
    return mlFetch(endpoint);
  }
  return res.json();
}

// OAuth
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

app.get('/api/status', async (req, res) => {
  res.json({
    ok: true,
    connected: !!tokenCache?.access_token,
    user_id: tokenCache?.user_id || null
  });
});

// Métricas en Vivo con Desglose Completo (Cargos ML + Mercado Ads)
app.get('/api/live-metrics', async (req, res) => {
  try {
    if (!tokenCache?.user_id) throw new Error('Mercado Libre no conectado');

    const ordersData = await mlFetch(`/orders/search?seller=${tokenCache.user_id}&sort=date_desc&limit=50`);
    
    // Obtener costos de productos
    const costsRes = await pool.query('SELECT * FROM product_costs');
    const costsMap = Object.fromEntries(costsRes.rows.map(r => [r.item_id, parseFloat(r.cost_price)]));

    // Obtener publicidad del día
    const adsRes = await pool.query('SELECT amount FROM daily_ads_spend WHERE spend_date = CURRENT_DATE');
    const adsSpendToday = adsRes.rows[0] ? parseFloat(adsRes.rows[0].amount) : 0;

    let totalRevenue = 0;
    let totalFees = 0;
    let totalShipping = 0;
    let totalProductCost = 0;

    const parsedOrders = (ordersData.results || []).map(order => {
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

    // Desglose de ganancia neta restando la publicidad diaria
    const netProfitTotal = totalRevenue - totalFees - totalShipping - totalProductCost - adsSpendToday;

    res.json({
      ok: true,
      summary: {
        totalRevenue,
        totalFees,
        totalShipping,
        totalProductCost,
        adsSpendToday,
        netProfitTotal,
        overallMargin: totalRevenue > 0 ? ((netProfitTotal / totalRevenue) * 100).toFixed(1) : '0.0',
        totalOrders: parsedOrders.length
      },
      orders: parsedOrders
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Endpoint para guardar costos por producto (SKU/MLA)
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

// Endpoint para registrar el gasto diario de Mercado Ads
app.post('/api/ads-spend', async (req, res) => {
  try {
    const { amount } = req.body;
    await pool.query(`
      INSERT INTO daily_ads_spend (spend_date, amount, updated_at)
      VALUES (CURRENT_DATE, $1, NOW())
      ON CONFLICT (spend_date) DO UPDATE SET amount = EXCLUDED.amount, updated_at = NOW();
    `, [amount]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Webhook en vivo de Mercado Libre
app.post('/api/webhooks/meli', async (req, res) => {
  res.status(200).send('OK');
});

app.listen(PORT, async () => {
  await initDB();
  console.log(`Servidor de Conteonix corriendo en puerto ${PORT}`);
});
