require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// IMPORTANTE: sirve public/index.html, manifest, sw.js, sonidos, iconos, etc.
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;

const BASE_URL =
  process.env.BASE_URL ||
  'https://conteo-rt2c.onrender.com';

const REDIRECT_URI =
  process.env.ML_REDIRECT_URI ||
  `${BASE_URL}/auth/callback`;

const CLIENT_ID = process.env.ML_CLIENT_ID;
const CLIENT_SECRET = process.env.ML_CLIENT_SECRET;

const AUTH_DOMAIN =
  process.env.ML_AUTH_DOMAIN ||
  'https://auth.mercadolibre.com.ar';

const API_BASE =
  process.env.ML_API_BASE ||
  'https://api.mercadolibre.com';

// ---------- PostgreSQL ----------

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false
});

let oauthState = null;
let pkceVerifier = null;
let tokenCache = null;

// Clientes conectados mediante SSE
const sseClients = new Set();

// ---------- Base de datos ----------

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS me_tokens (
        id INT PRIMARY KEY,
        tokens JSONB NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS product_costs (
        item_id VARCHAR(80) PRIMARY KEY,
        cost_price NUMERIC(12,2) NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        order_id VARCHAR(80),
        title TEXT,
        amount NUMERIC(12,2),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id SERIAL PRIMARY KEY,
        endpoint TEXT UNIQUE NOT NULL,
        subscription JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    tokenCache = await loadTokens();

    console.log(
      tokenCache?.access_token
        ? 'Token de Mercado Libre cargado desde PostgreSQL.'
        : 'No hay token de Mercado Libre guardado.'
    );
  } catch (err) {
    console.error('Error inicializando PostgreSQL:', err.message);
  }
}

async function loadTokens() {
  try {
    const result = await pool.query(
      'SELECT tokens FROM me_tokens WHERE id = 1'
    );

    return result.rows[0]?.tokens || null;
  } catch {
    return null;
  }
}

async function saveTokens(tokens) {
  tokenCache = tokens;

  await pool.query(
    `
      INSERT INTO me_tokens (id, tokens, updated_at)
      VALUES (1, $1, NOW())
      ON CONFLICT (id)
      DO UPDATE SET
        tokens = EXCLUDED.tokens,
        updated_at = NOW()
    `,
    [JSON.stringify(tokens)]
  );
}

// ---------- Utilidades ----------

function escapeHtml(value) {
  return String(value).replace(
    /[&<>'"]/g,
    char =>
      ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
      })[char]
  );
}

function randomState() {
  return crypto.randomBytes(24).toString('hex');
}

function base64url(buffer) {
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function makePkce() {
  const verifier = base64url(
    crypto.randomBytes(32)
  );

  const challenge = base64url(
    crypto
      .createHash('sha256')
      .update(verifier)
      .digest()
  );

  return {
    verifier,
    challenge
  };
}

// ---------- OAuth Mercado Libre ----------

async function tokenRequest(body) {
  const response = await fetch(
    `${API_BASE}/oauth/token`,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type':
          'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams(body)
    }
  );

  const text = await response.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    const error = new Error(
      data.error_description ||
        data.error ||
        `HTTP ${response.status}`
    );

    error.status = response.status;
    error.details = data;

    throw error;
  }

  return data;
}

async function exchangeCode(code) {
  const body = {
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code,
    redirect_uri: REDIRECT_URI
  };

  if (pkceVerifier) {
    body.code_verifier = pkceVerifier;
  }

  const data = await tokenRequest(body);

  await saveTokens({
    ...data,
    obtained_at: Date.now(),
    expires_at:
      Date.now() +
      ((data.expires_in || 21600) * 1000)
  });

  return data;
}

async function refreshAccessToken() {
  if (!tokenCache?.refresh_token) {
    throw new Error(
      'No hay refresh_token. Hay que conectar Mercado Libre nuevamente.'
    );
  }

  const data = await tokenRequest({
    grant_type: 'refresh_token',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: tokenCache.refresh_token
  });

  await saveTokens({
    ...data,
    obtained_at: Date.now(),
    expires_at:
      Date.now() +
      ((data.expires_in || 21600) * 1000)
  });

  return data.access_token;
}

async function getAccessToken() {
  if (!tokenCache?.access_token) {
    throw new Error(
      'Mercado Libre no está conectado.'
    );
  }

  const safetyWindow = 60 * 1000;

  if (
    tokenCache.expires_at &&
    Date.now() <
      tokenCache.expires_at - safetyWindow
  ) {
    return tokenCache.access_token;
  }

  return refreshAccessToken();
}

// ---------- Fetch Mercado Libre ----------

async function mlFetch(
  endpoint,
  options = {},
  retry = true
) {
  const accessToken = await getAccessToken();

  const url = endpoint.startsWith('http')
    ? endpoint
    : `${API_BASE}${endpoint}`;

  const headers = {
    ...(options.headers || {}),
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/json'
  };

  const response = await fetch(url, {
    ...options,
    headers
  });

  if (
    response.status === 401 &&
    retry &&
    tokenCache?.refresh_token
  ) {
    await refreshAccessToken();

    return mlFetch(
      endpoint,
      options,
      false
    );
  }

  const text = await response.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    const error = new Error(
      data.message ||
        data.error ||
        `Mercado Libre HTTP ${response.status}`
    );

    error.status = response.status;
    error.details = data;

    throw error;
  }

  return data;
}

// ---------- Fechas Argentina ----------

function todayAR() {
  const parts =
    new Intl.DateTimeFormat(
      'en-CA',
      {
        timeZone:
          'America/Argentina/Buenos_Aires',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      }
    ).formatToParts(new Date());

  const values = Object.fromEntries(
    parts.map(p => [
      p.type,
      p.value
    ])
  );

  return `${values.year}-${values.month}-${values.day}`;
}

function dateShiftAR(days) {
  const now = new Date();

  const parts =
    new Intl.DateTimeFormat(
      'en-CA',
      {
        timeZone:
          'America/Argentina/Buenos_Aires',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      }
    ).formatToParts(now);

  const values = Object.fromEntries(
    parts.map(p => [
      p.type,
      p.value
    ])
  );

  const d = new Date(
    `${values.year}-${values.month}-${values.day}T00:00:00-03:00`
  );

  d.setDate(d.getDate() + days);

  return d.toISOString().slice(0, 10);
}

function getAdsDateRange(period) {
  switch (period) {
    case 'yesterday':
      return {
        date_from: dateShiftAR(-1),
        date_to: dateShiftAR(-1)
      };

    case 'week':
      return {
        date_from: dateShiftAR(-6),
        date_to: dateShiftAR(0)
      };

    case 'month': {
      const today = todayAR();
      const first =
        `${today.slice(0, 7)}-01`;

      return {
        date_from: first,
        date_to: today
      };
    }

    case 'today':
    default:
      return {
        date_from: dateShiftAR(0),
        date_to: dateShiftAR(0)
      };
  }
}

// ---------- Órdenes ----------

function toMLDate(date) {
  return date
    .toISOString()
    .replace('Z', '-00:00');
}

async function fetchOrdersByRange(
  sellerId,
  from,
  to,
  maxResults = 300
) {
  const limit = 50;
  let offset = 0;
  const all = [];

  while (true) {
    const params =
      new URLSearchParams({
        seller: String(sellerId),
        'order.date_created.from':
          toMLDate(from),
        'order.date_created.to':
          toMLDate(to),
        sort: 'date_desc',
        limit: String(limit),
        offset: String(offset)
      });

    const data =
      await mlFetch(
        `/orders/search?${params.toString()}`
      );

    const results =
      data.results || [];

    all.push(...results);

    const total =
      data.paging?.total ??
      all.length;

    offset += limit;

    if (
      offset >= total ||
      all.length >= maxResults ||
      results.length === 0
    ) {
      break;
    }
  }

  return all;
}

const EXCLUDED_STATUSES =
  new Set([
    'cancelled',
    'invalid'
  ]);

function computeMetrics(
  orders,
  costsMap
) {
  const validOrders =
    orders.filter(
      order =>
        !EXCLUDED_STATUSES.has(
          order.status
        )
    );

  const cancelledCount =
    orders.length -
    validOrders.length;

  let totalRevenue = 0;
  let totalFees = 0;
  let totalShipping = 0;
  let totalProductCost = 0;

  const parsedOrders =
    validOrders.map(order => {
      const items =
        order.order_items || [];

      const firstItem =
        items[0];

      if (!firstItem) {
        return null;
      }

      const gross =
        Number(
          order.total_amount || 0
        );

      const fee =
        items.reduce(
          (sum, item) =>
            sum +
            Number(
              item.sale_fee || 0
            ),
          0
        );

      const shipping =
        Number(
          order.shipping?.cost || 0
        );

      const itemId =
        firstItem.item?.id;

      const unitCost =
        Number(
          costsMap[itemId] || 0
        );

      const quantity =
        Number(
          firstItem.quantity || 0
        );

      const productCost =
        unitCost * quantity;

      const netProfit =
        gross -
        fee -
        shipping -
        productCost;

      totalRevenue += gross;
      totalFees += fee;
      totalShipping += shipping;
      totalProductCost +=
        productCost;

      return {
        id: order.id,
        date:
          order.date_created,
        title:
          firstItem.item?.title ||
          itemId ||
          'Producto',
        sku: itemId,
        quantity,
        status:
          order.status,
        financials: {
          gross,
          fee,
          shipping,
          productCost,
          netProfit,
          margin:
            gross > 0
              ? (
                  (netProfit /
                    gross) *
                  100
                ).toFixed(1)
              : 0
        }
      };
    })
    .filter(Boolean);

  const netProfitTotal =
    totalRevenue -
    totalFees -
    totalShipping -
    totalProductCost;

  return {
    parsedOrders,
    summary: {
      totalRevenue,
      totalFees,
      totalShipping,
      totalProductCost,
      netProfitTotal,
      overallMargin:
        totalRevenue > 0
          ? (
              (netProfitTotal /
                totalRevenue) *
              100
            ).toFixed(1)
          : 0,
      totalOrders:
        validOrders.length,
      cancelledOrders:
        cancelledCount
    }
  };
}

// ---------- Product Ads ----------

const ADS_METRICS = [
  'clicks',
  'prints',
  'ctr',
  'cost',
  'cpc',
  'acos',
  'cvr',
  'roas',
  'sov',
  'organic_units_quantity',
  'organic_units_amount',
  'organic_items_quantity',
  'direct_items_quantity',
  'indirect_items_quantity',
  'advertising_items_quantity',
  'direct_units_quantity',
  'indirect_units_quantity',
  'units_quantity',
  'direct_amount',
  'indirect_amount',
  'total_amount'
].join(',');

let advertiserCache = null;

async function getAdvertiser() {
  if (advertiserCache) {
    return advertiserCache;
  }

  const data =
    await mlFetch(
      '/advertising/advertisers?product_id=PADS',
      {
        headers: {
          'Api-Version': '1'
        }
      }
    );

  const list =
    data.advertisers ||
    data.results ||
    (Array.isArray(data)
      ? data
      : []);

  if (!list.length) {
    throw new Error(
      'No se encontró ningún advertiser de Product Ads activo para esta cuenta.'
    );
  }

  const selected =
    list.find(
      advertiser =>
        advertiser.site_id === 'MLA'
    ) ||
    list[0];

  const advertiserId =
    selected.advertiser_id ||
    selected.id ||
    selected.user_id;

  if (!advertiserId) {
    throw new Error(
      `No se pudo obtener advertiser_id. Respuesta: ${JSON.stringify(
        selected
      )}`
    );
  }

  advertiserCache = {
    ...selected,
    advertiser_id:
      advertiserId
  };

  return advertiserCache;
}

async function fetchCampaignsWithMetrics(
  advertiserId,
  date_from,
  date_to
) {
  const url =
    `/advertising/advertisers/${advertiserId}` +
    `/product_ads/campaigns` +
    `?date_from=${date_from}` +
    `&date_to=${date_to}` +
    `&metrics=${ADS_METRICS}` +
    `&limit=50&offset=0`;

  try {
    const data =
      await mlFetch(
        url,
        {
          headers: {
            'Api-Version': '2'
          }
        }
      );

    return (
      data.results ||
      data.campaigns ||
      []
    );
  } catch (error) {
    const data =
      await mlFetch(
        url,
        {
          headers: {
            'Api-Version': '1'
          }
        }
      );

    return (
      data.results ||
      data.campaigns ||
      []
    );
  }
}

async function fetchItemsWithMetrics(
  advertiserId,
  date_from,
  date_to
) {
  const url =
    `/advertising/advertisers/${advertiserId}` +
    `/product_ads/items` +
    `?date_from=${date_from}` +
    `&date_to=${date_to}` +
    `&metrics=${ADS_METRICS}` +
    `&metrics_summary=true` +
    `&sort_by=cost` +
    `&sort=desc` +
    `&limit=50&offset=0`;

  try {
    const data =
      await mlFetch(
        url,
        {
          headers: {
            'Api-Version': '2'
          }
        }
      );

    return (
      data.results ||
      data.items ||
      []
    );
  } catch (error) {
    const data =
      await mlFetch(
        url,
        {
          headers: {
            'Api-Version': '1'
          }
        }
      );

    return (
      data.results ||
      data.items ||
      []
    );
  }
}

function emptyAdsMetrics() {
  return {
    clicks: 0,
    prints: 0,
    cost: 0,
    total_amount: 0,
    direct_amount: 0,
    indirect_amount: 0,
    units_quantity: 0,
    direct_units_quantity: 0,
    indirect_units_quantity: 0
  };
}

async function getProductAdsReport(
  period
) {
  const {
    date_from,
    date_to
  } =
    getAdsDateRange(period);

  let advertiser;

  try {
    advertiser =
      await getAdvertiser();
  } catch (error) {
    return {
      ok: true,
      period,
      date_from,
      date_to,
      advertiser: {},
      summary:
        emptyAdsMetrics(),
      campaigns: [],
      items: [],
      warning:
        error.message
    };
  }

  let campaigns = [];
  let items = [];
  let fetchError = null;

  try {
    [
      campaigns,
      items
    ] =
      await Promise.all([
        fetchCampaignsWithMetrics(
          advertiser.advertiser_id,
          date_from,
          date_to
        ),
        fetchItemsWithMetrics(
          advertiser.advertiser_id,
          date_from,
          date_to
        )
      ]);
  } catch (error) {
    console.error(
      'Error Product Ads:',
      error.message
    );

    fetchError =
      error.message;
  }

  const totals =
    campaigns.reduce(
      (acc, campaign) => {
        const metrics =
          campaign.metrics ||
          campaign;

        for (
          const key of [
            'clicks',
            'prints',
            'cost',
            'direct_amount',
            'indirect_amount',
            'total_amount',
            'direct_units_quantity',
            'indirect_units_quantity',
            'units_quantity'
          ]
        ) {
          acc[key] =
            Number(
              acc[key] || 0
            ) +
            Number(
              metrics[key] || 0
            );
        }

        return acc;
      },
      emptyAdsMetrics()
    );

  const summary = {
    ...totals,

    ctr:
      totals.prints > 0
        ? Number(
            (
              (totals.clicks /
                totals.prints) *
              100
            ).toFixed(2)
          )
        : 0,

    cpc:
      totals.clicks > 0
        ? Number(
            (
              totals.cost /
              totals.clicks
            ).toFixed(2)
          )
        : 0,

    roas:
      totals.cost > 0
        ? Number(
            (
              totals.total_amount /
              totals.cost
            ).toFixed(2)
          )
        : 0,

    acos:
      totals.total_amount > 0
        ? Number(
            (
              (totals.cost /
                totals.total_amount) *
              100
            ).toFixed(2)
          )
        : 0
  };

  const campaignsOut =
    campaigns.map(
      campaign => ({
        id: campaign.id,
        name:
          campaign.name ||
          `Campaña ${campaign.id}`,
        status:
          campaign.status ||
          '—',
        budget:
          Number(
            campaign.budget || 0
          ),
        currency:
          campaign.currency_id ||
          'ARS',
        strategy:
          campaign.strategy ||
          '—',
        acosTarget:
          campaign.acos_target ??
          null,
        metrics:
          campaign.metrics ||
          {}
      })
    );

  const itemsOut =
    items.map(item => {
      const metrics =
        item.metrics_summary ||
        item.metrics ||
        {};

      const cost =
        Number(
          metrics.cost || 0
        );

      const totalAmount =
        Number(
          metrics.total_amount ||
            0
        );

      return {
        itemId:
          item.item_id ||
          item.id,

        title:
          item.title ||
          item.item_id ||
          item.id,

        price:
          item.price || 0,

        status:
          item.status || '—',

        campaignId:
          item.campaign_id ||
          null,

        buyBoxWinner:
          item.buy_box_winner,

        metrics: {
          clicks:
            Number(
              metrics.clicks || 0
            ),

          prints:
            Number(
              metrics.prints || 0
            ),

          ctr:
            metrics.ctr ??
            (
              metrics.prints > 0
                ? (
                    metrics.clicks /
                    metrics.prints
                  ) *
                  100
                : 0
            ),

          cost,

          cpc:
            Number(
              metrics.cpc ||
                (
                  metrics.clicks > 0
                    ? cost /
                      metrics.clicks
                    : 0
                )
            ),

          acos:
            Number(
              metrics.acos ||
                (
                  totalAmount > 0
                    ? (cost /
                        totalAmount) *
                      100
                    : 0
                )
            ),

          cvr:
            Number(
              metrics.cvr || 0
            ),

          roas:
            metrics.roas ??
            (
              cost > 0
                ? totalAmount /
                  cost
                : 0
            ),

          unitsQuantity:
            Number(
              metrics.units_quantity ||
                0
            ),

          directUnitsQuantity:
            Number(
              metrics.direct_units_quantity ||
                0
            ),

          indirectUnitsQuantity:
            Number(
              metrics.indirect_units_quantity ||
                0
            ),

          totalAmount,

          directAmount:
            Number(
              metrics.direct_amount ||
                0
            ),

          indirectAmount:
            Number(
              metrics.indirect_amount ||
                0
            )
        }
      };
    });

  return {
    ok: true,
    period,
    date_from,
    date_to,

    advertiser: {
      id:
        advertiser.advertiser_id,
      siteId:
        advertiser.site_id,
      name:
        advertiser.advertiser_name,
      account:
        advertiser.account_name
    },

    summary,

    campaigns:
      campaignsOut,

    items:
      itemsOut,

    ...(fetchError
      ? {
          fetch_error:
            fetchError
        }
      : {})
  };
}

// ---------- Stock ----------

async function getStockAlerts() {
  if (!tokenCache?.user_id) {
    throw new Error(
      'Mercado Libre no conectado'
    );
  }

  const to = new Date();

  const from =
    new Date(
      to.getTime() -
        30 *
          24 *
          60 *
          60 *
          1000
    );

  const orders =
    await fetchOrdersByRange(
      tokenCache.user_id,
      from,
      to,
      500
    );

  const unitsBySku = {};

  orders
    .filter(
      order =>
        !EXCLUDED_STATUSES.has(
          order.status
        )
    )
    .forEach(order => {
      (
        order.order_items || []
      ).forEach(item => {
        const id =
          item.item?.id;

        if (!id) return;

        unitsBySku[id] =
          (
            unitsBySku[id] || 0
          ) +
          Number(
            item.quantity || 0
          );
      });
    });

  const skuIds =
    Object.keys(
      unitsBySku
    );

  if (!skuIds.length) {
    return [];
  }

  const stockMap = {};

  for (
    let i = 0;
    i < skuIds.length;
    i += 20
  ) {
    const batch =
      skuIds.slice(
        i,
        i + 20
      );

    const data =
      await mlFetch(
        `/items?ids=${batch.join(',')}` +
        `&attributes=id,title,available_quantity`
      );

    (
      Array.isArray(data)
        ? data
        : []
    ).forEach(entry => {
      if (
        entry.code === 200 &&
        entry.body
      ) {
        stockMap[
          entry.body.id
        ] = {
          title:
            entry.body.title,
          stock:
            Number(
              entry.body
                .available_quantity ||
                0
            )
        };
      }
    });
  }

  const alerts =
    skuIds.map(id => {
      const avgDaily =
        unitsBySku[id] /
        30;

      const info =
        stockMap[id] || {
          title: id,
          stock: 0
        };

      const daysRemaining =
        avgDaily > 0
          ? info.stock /
            avgDaily
          : null;

      return {
        itemId: id,
        title: info.title,
        stock: info.stock,
        unitsSold30d:
          unitsBySku[id],
        avgDailySales:
          Number(
            avgDaily.toFixed(2)
          ),
        daysRemaining:
          daysRemaining !== null
            ? Number(
                daysRemaining.toFixed(
                  1
                )
              )
            : null
      };
    });

  alerts.sort(
    (a, b) => {
      if (
        a.daysRemaining ===
        null
      ) {
        return 1;
      }

      if (
        b.daysRemaining ===
        null
      ) {
        return -1;
      }

      return (
        a.daysRemaining -
        b.daysRemaining
      );
    }
  );

  return alerts;
}

// ---------- SSE ----------

function broadcast(
  type,
  data
) {
  const payload =
    `data: ${JSON.stringify({
      type,
      data
    })}\n\n`;

  for (
    const client of sseClients
  ) {
    try {
      client.write(
        payload
      );
    } catch {}
  }
}

app.get(
  '/api/events',
  (req, res) => {
    res.writeHead(
      200,
      {
        'Content-Type':
          'text/event-stream',
        'Cache-Control':
          'no-cache',
        Connection:
          'keep-alive'
      }
    );

    res.write(
      'retry: 5000\n\n'
    );

    sseClients.add(res);

    const heartbeat =
      setInterval(
        () => {
          try {
            res.write(
              ':hb\n\n'
            );
          } catch {}
        },
        25000
      );

    req.on(
      'close',
      () => {
        clearInterval(
          heartbeat
        );

        sseClients.delete(
          res
        );
      }
    );
  }
);

// ---------- OAuth ----------

app.get(
  '/auth/login',
  (req, res) => {
    try {
      if (!CLIENT_ID) {
        throw new Error(
          'Falta ML_CLIENT_ID en Render.'
        );
      }

      if (!CLIENT_SECRET) {
        throw new Error(
          'Falta ML_CLIENT_SECRET en Render.'
        );
      }

      oauthState =
        randomState();

      const pkce =
        makePkce();

      pkceVerifier =
        pkce.verifier;

      const url =
        new URL(
          `${AUTH_DOMAIN}/authorization`
        );

      url.searchParams.set(
        'response_type',
        'code'
      );

      url.searchParams.set(
        'client_id',
        CLIENT_ID
      );

      url.searchParams.set(
        'redirect_uri',
        REDIRECT_URI
      );

      url.searchParams.set(
        'state',
        oauthState
      );

      url.searchParams.set(
        'code_challenge',
        pkce.challenge
      );

      url.searchParams.set(
        'code_challenge_method',
        'S256'
      );

      res.redirect(
        url.toString()
      );
    } catch (error) {
      res
        .status(500)
        .send(
          `<pre>${escapeHtml(
            error.message
          )}</pre>`
        );
    }
  }
);

app.get(
  '/auth/callback',
  async (req, res) => {
    try {
      if (req.query.error) {
        return res
          .status(400)
          .send(
            `<pre>${escapeHtml(
              req.query.error_description ||
                req.query.error
            )}</pre>`
          );
      }

      if (
        oauthState &&
        req.query.state !==
          oauthState
      ) {
        return res
          .status(400)
          .send(
            'State OAuth inválido.'
          );
      }

      if (!req.query.code) {
        return res
          .status(400)
          .send(
            'Falta el código OAuth.'
          );
      }

      await exchangeCode(
        req.query.code
      );

      oauthState = null;
      pkceVerifier = null;

      res.redirect(
        '/?connected=1'
      );
    } catch (error) {
      console.error(
        'OAuth error:',
        error
      );

      res
        .status(
          error.status || 500
        )
        .send(
          `<h1>No se pudo conectar Mercado Libre</h1>
           <pre>${escapeHtml(
             error.message
           )}</pre>`
        );
    }
  }
);

// ---------- API status ----------

app.get(
  '/api/status',
  async (req, res) => {
    const result = {
      ok: true,
      connected:
        !!tokenCache?.access_token,
      user_id:
        tokenCache?.user_id ||
        null,
      redirect_uri:
        REDIRECT_URI
    };

    if (
      result.connected
    ) {
      try {
        const me =
          await mlFetch(
            '/users/me'
          );

        result.user = {
          id: me.id,
          nickname:
            me.nickname,
          country_id:
            me.country_id
        };
      } catch (error) {
        result.api_error =
          error.message;
      }
    }

    res.json(result);
  }
);

// ---------- Ventas ----------

app.get(
  '/api/live-metrics',
  async (req, res) => {
    try {
      if (
        !tokenCache?.user_id
      ) {
        throw new Error(
          'Mercado Libre no conectado'
        );
      }

      const allowedPeriods =
        [
          'today',
          'yesterday',
          'week',
          'month'
        ];

      const period =
        allowedPeriods.includes(
          req.query.period
        )
          ? req.query.period
          : 'today';

      const now =
        new Date();

      let from;
      let to = now;

      if (
        period ===
        'today'
      ) {
        const date =
          dateShiftAR(0);

        from =
          new Date(
            `${date}T00:00:00-03:00`
          );
      } else if (
        period ===
        'yesterday'
      ) {
        const date =
          dateShiftAR(-1);

        from =
          new Date(
            `${date}T00:00:00-03:00`
          );

        to =
          new Date(
            `${dateShiftAR(
              0
            )}T00:00:00-03:00`
          );
      } else if (
        period ===
        'week'
      ) {
        from =
          new Date(
            `${dateShiftAR(
              -6
            )}T00:00:00-03:00`
          );
      } else {
        const today =
          todayAR();

        from =
          new Date(
            `${today.slice(
              0,
              7
            )}-01T00:00:00-03:00`
          );
      }

      const orders =
        await fetchOrdersByRange(
          tokenCache.user_id,
          from,
          to,
          500
        );

      const costsResult =
        await pool.query(
          'SELECT item_id, cost_price FROM product_costs'
        );

      const costsMap =
        Object.fromEntries(
          costsResult.rows.map(
            row => [
              row.item_id,
              Number(
                row.cost_price
              )
            ]
          )
        );

      const {
        parsedOrders,
        summary
      } =
        computeMetrics(
          orders,
          costsMap
        );

      res.json({
        ok: true,
        period,
        summary,
        orders:
          parsedOrders
      });
    } catch (error) {
      console.error(
        'Error /api/live-metrics:',
        error
      );

      res
        .status(
          error.status || 500
        )
        .json({
          ok: false,
          error:
            error.message,
          details:
            error.details ||
            null
        });
    }
  }
);

// ---------- Orders ----------

app.get(
  '/api/orders',
  async (req, res) => {
    try {
      if (
        !tokenCache?.user_id
      ) {
        throw new Error(
          'Primero conectá Mercado Libre.'
        );
      }

      const limit =
        Math.min(
          Math.max(
            Number(
              req.query.limit
            ) || 50,
            1
          ),
          50
        );

      const offset =
        Math.max(
          Number(
            req.query.offset
          ) || 0,
          0
        );

      const params =
        new URLSearchParams({
          seller:
            String(
              tokenCache.user_id
            ),
          limit:
            String(limit),
          offset:
            String(offset),
          sort:
            'date_desc'
        });

      if (
        req.query.status
      ) {
        params.set(
          'order.status',
          req.query.status
        );
      }

      const data =
        await mlFetch(
          `/orders/search?${params.toString()}`
        );

      res.json({
        ok: true,
        ...data
      });
    } catch (error) {
      res
        .status(
          error.status || 500
        )
        .json({
          ok: false,
          error:
            error.message,
          details:
            error.details ||
            null
        });
    }
  }
);

// ---------- Product Ads ----------

app.get(
  '/api/product-ads',
  async (req, res) => {
    try {
      const period =
        [
          'today',
          'yesterday',
          'week',
          'month'
        ].includes(
          req.query.period
        )
          ? req.query.period
          : 'today';

      const report =
        await getProductAdsReport(
          period
        );

      res.json(
        report
      );
    } catch (error) {
      console.error(
        'Error /api/product-ads:',
        error
      );

      res
        .status(
          error.status || 500
        )
        .json({
          ok: false,
          error:
            error.message,
          details:
            error.details ||
            null
        });
    }
  }
);

// Alias por compatibilidad
app.get(
  '/api/ads/report',
  async (req, res) => {
    try {
      const period =
        [
          'today',
          'yesterday',
          'week',
          'month'
        ].includes(
          req.query.period
        )
          ? req.query.period
          : 'today';

      res.json(
        await getProductAdsReport(
          period
        )
      );
    } catch (error) {
      res
        .status(
          error.status || 500
        )
        .json({
          ok: false,
          error:
            error.message,
          details:
            error.details ||
            null
        });
    }
  }
);

// ---------- Stock ----------

app.get(
  '/api/stock-alerts',
  async (req, res) => {
    try {
      const alerts =
        await getStockAlerts();

      res.json({
        ok: true,
        alerts
      });
    } catch (error) {
      res
        .status(500)
        .json({
          ok: false,
          error:
            error.message
        });
    }
  }
);

// ---------- Notificaciones ----------

app.get(
  '/api/notifications',
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
            SELECT
              id,
              order_id AS "orderId",
              title,
              amount,
              created_at AS "createdAt"
            FROM notifications
            ORDER BY created_at DESC
            LIMIT 20
          `
        );

      res.json({
        ok: true,
        notifications:
          result.rows
      });
    } catch (error) {
      res
        .status(500)
        .json({
          ok: false,
          error:
            error.message
        });
    }
  }
);

// ---------- Costos ----------

app.post(
  '/api/costs',
  async (req, res) => {
    try {
      const itemId =
        String(
          req.body?.itemId ||
            ''
        ).trim();

      const costPrice =
        Number(
          req.body?.costPrice
        );

      if (
        !itemId ||
        !Number.isFinite(
          costPrice
        ) ||
        costPrice < 0
      ) {
        throw new Error(
          'ID de publicación o costo inválido.'
        );
      }

      await pool.query(
        `
          INSERT INTO product_costs
            (item_id, cost_price, updated_at)
          VALUES
            ($1, $2, NOW())
          ON CONFLICT (item_id)
          DO UPDATE SET
            cost_price =
              EXCLUDED.cost_price,
            updated_at =
              NOW()
        `,
        [
          itemId,
          costPrice
        ]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      res
        .status(500)
        .json({
          ok: false,
          error:
            error.message
        });
    }
  }
);

// ---------- Sincronización ----------

app.post(
  '/api/sync',
  async (req, res) => {
    try {
      if (
        !tokenCache?.user_id
      ) {
        throw new Error(
          'Primero conectá Mercado Libre.'
        );
      }

      const limit =
        Math.min(
          Math.max(
            Number(
              req.body?.limit
            ) || 50,
            1
          ),
          50
        );

      const params =
        new URLSearchParams({
          seller:
            String(
              tokenCache.user_id
            ),
          limit:
            String(limit),
          offset: '0',
          sort:
            'date_desc'
        });

      const data =
        await mlFetch(
          `/orders/search?${params.toString()}`
        );

      res.json({
        ok: true,
        synced_at:
          new Date().toISOString(),
        total:
          data.paging?.total ??
          data.results?.length ??
          0,
        orders:
          data.results || []
      });
    } catch (error) {
      res
        .status(
          error.status || 500
        )
        .json({
          ok: false,
          error:
            error.message,
          details:
            error.details ||
            null
        });
    }
  }
);

// ---------- Webhook Mercado Libre ----------

app.post(
  '/api/webhooks/meli',
  async (req, res) => {
    // Responder inmediatamente a ML
    res.status(200).send('OK');

    try {
      const {
        topic,
        resource
      } = req.body;

      if (
        topic !==
          'orders_v2' ||
        !resource
      ) {
        return;
      }

      const orderData =
        await mlFetch(
          resource
        );

      const item =
        orderData
          .order_items?.[0];

      const title =
        item?.item?.title ||
        'Venta nueva';

      const amount =
        Number(
          orderData.total_amount ||
            0
        );

      await pool.query(
        `
          INSERT INTO notifications
            (order_id, title, amount)
          VALUES
            ($1, $2, $3)
        `,
        [
          String(
            orderData.id
          ),
          title,
          amount
        ]
      );

      broadcast(
        'new_order',
        {
          orderId:
            orderData.id,
          title,
          amount,
          date:
            orderData.date_created
        }
      );

      console.log(
        'Nueva venta recibida:',
        orderData.id
      );
    } catch (error) {
      console.error(
        'Error procesando webhook:',
        error.message
      );
    }
  }
);

// ---------- Push notifications ----------

app.get(
  '/api/push/public-key',
  (req, res) => {
    const publicKey =
      process.env.VAPID_PUBLIC_KEY;

    if (!publicKey) {
      return res
        .status(503)
        .json({
          ok: false,
          error:
            'VAPID_PUBLIC_KEY no está configurada en Render.'
        });
    }

    res.json({
      ok: true,
      publicKey
    });
  }
);

app.post(
  '/api/push/subscribe',
  async (req, res) => {
    try {
      const subscription =
        req.body;

      if (
        !subscription?.endpoint
      ) {
        throw new Error(
          'Suscripción push inválida.'
        );
      }

      await pool.query(
        `
          INSERT INTO push_subscriptions
            (endpoint, subscription, updated_at)
          VALUES
            ($1, $2, NOW())
          ON CONFLICT (endpoint)
          DO UPDATE SET
            subscription =
              EXCLUDED.subscription,
            updated_at =
              NOW()
        `,
        [
          subscription.endpoint,
          JSON.stringify(
            subscription
          )
        ]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      res
        .status(500)
        .json({
          ok: false,
          error:
            error.message
        });
    }
  }
);

app.post(
  '/api/push/unsubscribe',
  async (req, res) => {
    try {
      const endpoint =
        String(
          req.body?.endpoint ||
            ''
        );

      if (endpoint) {
        await pool.query(
          `
            DELETE FROM push_subscriptions
            WHERE endpoint = $1
          `,
          [endpoint]
        );
      }

      res.json({
        ok: true
      });
    } catch (error) {
      res
        .status(500)
        .json({
          ok: false,
          error:
            error.message
        });
    }
  }
);

// ---------- Health ----------

app.get(
  '/health',
  (req, res) => {
    res.status(200).json({
      status: 'OK',
      timestamp:
        new Date().toISOString()
    });
  }
);

// ---------- ROOT ----------

// Esta ruta es la que evita "Cannot GET /"
app.get(
  '/',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    );
  }
);

// ---------- Error 404 ----------

app.use(
  (req, res) => {
    res.status(404).json({
      ok: false,
      error:
        `Ruta no encontrada: ${req.method} ${req.originalUrl}`
    });
  }
);

// ---------- Inicio ----------

app.listen(
  PORT,
  async () => {
    console.log(
      `Conteonix escuchando en puerto ${PORT}`
    );

    await initDB();
  }
);
