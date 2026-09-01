```javascript
require('dotenv').config();

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

// ============================================================
// CONFIGURACIÓN
// ============================================================

const PORT = Number(process.env.PORT) || 3000;

const BASE_URL =
  process.env.BASE_URL ||
  'https://conteo-rt2c.onrender.com';

const CLIENT_ID = process.env.ML_CLIENT_ID;
const CLIENT_SECRET = process.env.ML_CLIENT_SECRET;

const REDIRECT_URI =
  process.env.ML_REDIRECT_URI ||
  `${BASE_URL}/auth/callback`;

const AUTH_DOMAIN =
  process.env.ML_AUTH_DOMAIN ||
  'https://auth.mercadolibre.com.ar';

const API_BASE =
  process.env.ML_API_BASE ||
  'https://api.mercadolibre.com';

const DATA_DIR =
  process.env.DATA_DIR ||
  path.join(__dirname, 'data');

const TOKEN_FILE =
  process.env.TOKEN_FILE ||
  path.join(DATA_DIR, 'tokens.json');

const PRODUCTS_FILE =
  process.env.PRODUCTS_FILE ||
  path.join(DATA_DIR, 'products.json');

// ============================================================
// EXPRESS
// ============================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PUBLIC_DIR =
  path.join(__dirname, 'public');

app.use(express.static(PUBLIC_DIR));

// ============================================================
// DIRECTORIO DE DATOS
// ============================================================

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, {
    recursive: true
  });
}

// ============================================================
// TOKENS
// ============================================================

let tokenCache = loadTokens();

function loadTokens() {
  try {
    if (!fs.existsSync(TOKEN_FILE)) {
      return null;
    }

    const content =
      fs.readFileSync(TOKEN_FILE, 'utf8');

    if (!content.trim()) {
      return null;
    }

    return JSON.parse(content);

  } catch (error) {
    console.error(
      'Error cargando tokens:',
      error.message
    );

    return null;
  }
}

function saveTokens(tokens) {
  const tmp =
    `${TOKEN_FILE}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(tokens, null, 2),
    {
      mode: 0o600
    }
  );

  fs.renameSync(
    tmp,
    TOKEN_FILE
  );

  tokenCache = tokens;
}

// ============================================================
// PRODUCTOS / COSTOS / STOCK
// ============================================================

let productConfig = loadProductConfig();

function loadProductConfig() {
  try {
    if (!fs.existsSync(PRODUCTS_FILE)) {
      return {};
    }

    const content =
      fs.readFileSync(
        PRODUCTS_FILE,
        'utf8'
      );

    if (!content.trim()) {
      return {};
    }

    return JSON.parse(content);

  } catch (error) {
    console.error(
      'Error cargando productos:',
      error.message
    );

    return {};
  }
}

function saveProductConfig() {
  const tmp =
    `${PRODUCTS_FILE}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(
      productConfig,
      null,
      2
    )
  );

  fs.renameSync(
    tmp,
    PRODUCTS_FILE
  );
}

function getProductConfig(itemId) {
  if (!itemId) {
    return {
      cost: 0,
      minStock: 5,
      targetDays: 15
    };
  }

  return (
    productConfig[String(itemId)] || {
      cost: 0,
      minStock: 5,
      targetDays: 15
    }
  );
}

// ============================================================
// OAUTH
// ============================================================

let oauthState = null;
let pkceVerifier = null;

function base64url(buffer) {
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function createPKCE() {
  const verifier =
    base64url(
      crypto.randomBytes(32)
    );

  const challenge =
    base64url(
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

// ============================================================
// HELPERS
// ============================================================

function escapeHtml(value) {
  return String(value).replace(
    /[&<>'"]/g,
    char => {
      const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
      };

      return map[char];
    }
  );
}

function todayArgentina() {
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
    ).formatToParts(
      new Date()
    );

  const result = {};

  for (const part of parts) {
    result[part.type] =
      part.value;
  }

  return (
    `${result.year}-${result.month}-${result.day}`
  );
}

function requireConfig() {
  const missing = [];

  if (!CLIENT_ID) {
    missing.push('ML_CLIENT_ID');
  }

  if (!CLIENT_SECRET) {
    missing.push('ML_CLIENT_SECRET');
  }

  if (!REDIRECT_URI) {
    missing.push('ML_REDIRECT_URI');
  }

  if (missing.length) {
    throw new Error(
      `Faltan variables de entorno: ${missing.join(', ')}`
    );
  }
}

function sleep(ms) {
  return new Promise(
    resolve => setTimeout(resolve, ms)
  );
}

// ============================================================
// TOKEN MERCADO LIBRE
// ============================================================

async function tokenRequest(body) {
  const response =
    await fetch(
      `${API_BASE}/oauth/token`,
      {
        method: 'POST',

        headers: {
          accept:
            'application/json',

          'content-type':
            'application/x-www-form-urlencoded'
        },

        body:
          new URLSearchParams(body)
      }
    );

  const text =
    await response.text();

  let data;

  try {
    data =
      JSON.parse(text);
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    const error =
      new Error(
        data.error_description ||
        data.error ||
        `HTTP ${response.status}`
      );

    error.status =
      response.status;

    error.details =
      data;

    throw error;
  }

  return data;
}

async function exchangeCode(code) {
  const body = {
    grant_type:
      'authorization_code',

    client_id:
      CLIENT_ID,

    client_secret:
      CLIENT_SECRET,

    code,

    redirect_uri:
      REDIRECT_URI
  };

  if (pkceVerifier) {
    body.code_verifier =
      pkceVerifier;
  }

  const data =
    await tokenRequest(body);

  const now =
    Date.now();

  saveTokens({
    ...data,

    obtained_at:
      now,

    expires_at:
      now +
      (
        (data.expires_in || 21600) *
        1000
      )
  });

  return data;
}

async function refreshAccessToken() {
  if (
    !tokenCache?.refresh_token
  ) {
    throw new Error(
      'No existe refresh_token. Hay que conectar Mercado Libre nuevamente.'
    );
  }

  const data =
    await tokenRequest({
      grant_type:
        'refresh_token',

      client_id:
        CLIENT_ID,

      client_secret:
        CLIENT_SECRET,

      refresh_token:
        tokenCache.refresh_token
    });

  const now =
    Date.now();

  saveTokens({
    ...data,

    obtained_at:
      now,

    expires_at:
      now +
      (
        (data.expires_in || 21600) *
        1000
      )
  });

  return data.access_token;
}

async function getAccessToken() {
  if (
    !tokenCache?.access_token
  ) {
    throw new Error(
      'Mercado Libre no está conectado.'
    );
  }

  const safety =
    60 * 1000;

  if (
    tokenCache.expires_at &&
    Date.now() <
      tokenCache.expires_at - safety
  ) {
    return tokenCache.access_token;
  }

  return refreshAccessToken();
}

// ============================================================
// REQUEST GENÉRICO ML
// ============================================================

async function mlFetch(
  endpoint,
  options = {},
  retry = true
) {
  const accessToken =
    await getAccessToken();

  const headers = {
    ...(options.headers || {}),

    Authorization:
      `Bearer ${accessToken}`,

    Accept:
      'application/json'
  };

  const response =
    await fetch(
      `${API_BASE}${endpoint}`,
      {
        ...options,
        headers
      }
    );

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

  const text =
    await response.text();

  let data;

  try {
    data =
      JSON.parse(text);
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    const error =
      new Error(
        data.message ||
        data.error ||
        `Mercado Libre HTTP ${response.status}`
      );

    error.status =
      response.status;

    error.details =
      data;

    throw error;
  }

  return data;
}

// ============================================================
// PRODUCT ADS
// ============================================================

async function mlAdsFetch(
  endpoint,
  options = {},
  retry = true
) {
  const accessToken =
    await getAccessToken();

  const headers = {
    ...(options.headers || {}),

    Authorization:
      `Bearer ${accessToken}`,

    Accept:
      'application/json',

    'api-version':
      '2'
  };

  const response =
    await fetch(
      `${API_BASE}${endpoint}`,
      {
        ...options,
        headers
      }
    );

  if (
    response.status === 401 &&
    retry &&
    tokenCache?.refresh_token
  ) {
    await refreshAccessToken();

    return mlAdsFetch(
      endpoint,
      options,
      false
    );
  }

  const text =
    await response.text();

  let data;

  try {
    data =
      JSON.parse(text);
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    const error =
      new Error(
        data.message ||
        data.error ||
        `Product Ads HTTP ${response.status}`
      );

    error.status =
      response.status;

    error.details =
      data;

    throw error;
  }

  return data;
}

// ============================================================
// ORDERS
// ============================================================

async function fetchOrders(
  limit = 50,
  offset = 0
) {
  const me =
    await mlFetch('/users/me');

  const params =
    new URLSearchParams();

  params.set(
    'seller',
    String(me.id)
  );

  params.set(
    'limit',
    String(
      Math.min(
        Math.max(
          Number(limit) || 50,
          1
        ),
        50
      )
    )
  );

  params.set(
    'offset',
    String(
      Math.max(
        Number(offset) || 0,
        0
      )
    )
  );

  params.set(
    'sort',
    'date_desc'
  );

  return mlFetch(
    `/orders/search?${params.toString()}`
  );
}

// ============================================================
// ENRIQUECER ORDEN CON COSTOS
// ============================================================

function enrichOrder(order) {
  const items =
    Array.isArray(
      order.order_items
    )
      ? order.order_items
      : [];

  let productCost =
    0;

  let units =
    0;

  const enrichedItems =
    items.map(item => {
      const quantity =
        Number(
          item.quantity
        ) || 0;

      const itemId =
        item.item?.id ||
        item.item_id ||
        null;

      const title =
        item.item?.title ||
        item.title ||
        'Producto';

      const config =
        getProductConfig(itemId);

      const unitCost =
        Number(config.cost) || 0;

      const totalCost =
        unitCost * quantity;

      units += quantity;
      productCost += totalCost;

      return {
        ...item,

        conteonix: {
          itemId,
          title,
          quantity,
          unitCost,
          totalCost,
          minStock:
            Number(config.minStock) || 0,
          targetDays:
            Number(config.targetDays) || 15
        }
      };
    });

  return {
    ...order,

    conteonix: {
      units,
      productCost,
      grossAmount:
        Number(order.total_amount) || 0,

      estimatedProfit:
        (
          Number(order.total_amount) || 0
        ) -
        productCost
    },

    order_items:
      enrichedItems
  };
}

// ============================================================
// SSE TIEMPO REAL
// ============================================================

const clients =
  new Set();

function broadcast(event) {
  const payload =
    JSON.stringify(event);

  for (
    const client
    of clients
  ) {
    try {
      client.write(
        `data: ${payload}\n\n`
      );
    } catch {
      clients.delete(client);
    }
  }
}

app.get(
  '/api/events',
  (req, res) => {
    res.setHeader(
      'Content-Type',
      'text/event-stream'
    );

    res.setHeader(
      'Cache-Control',
      'no-cache'
    );

    res.setHeader(
      'Connection',
      'keep-alive'
    );

    res.flushHeaders();

    res.write(
      `data: ${JSON.stringify({
        type: 'connected',
        time:
          new Date().toISOString()
      })}\n\n`
    );

    clients.add(res);

    const heartbeat =
      setInterval(
        () => {
          try {
            res.write(
              ': heartbeat\n\n'
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

        clients.delete(res);
      }
    );
  }
);

// ============================================================
// HOME
// ============================================================

app.get(
  '/',
  (req, res) => {
    const index =
      path.join(
        PUBLIC_DIR,
        'index.html'
      );

    if (
      !fs.existsSync(index)
    ) {
      return res
        .status(500)
        .send(
          'No existe public/index.html'
        );
    }

    res.sendFile(index);
  }
);

// ============================================================
// HEALTH
// ============================================================

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,

      service:
        'conteonix',

      status:
        'online',

      connected:
        !!tokenCache?.access_token,

      time:
        new Date().toISOString()
    });
  }
);

// ============================================================
// LOGIN
// ============================================================

app.get(
  '/auth/login',
  (req, res) => {
    try {
      requireConfig();

      oauthState =
        crypto
          .randomBytes(24)
          .toString('hex');

      const pkce =
        createPKCE();

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

// ============================================================
// CALLBACK
// ============================================================

app.get(
  '/auth/callback',
  async (req, res) => {
    try {
      requireConfig();

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
        !oauthState ||
        req.query.state !==
          oauthState
      ) {
        return res
          .status(400)
          .send(
            'State OAuth inválido o expirado.'
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

      oauthState =
        null;

      pkceVerifier =
        null;

      res.redirect(
        '/?connected=1'
      );

    } catch (error) {
      console.error(
        'OAuth error:',
        error.details ||
        error
      );

      res
        .status(
          error.status ||
          500
        )
        .send(
          `<h1>Error conectando Mercado Libre</h1>
           <pre>${escapeHtml(
             error.message
           )}</pre>`
        );
    }
  }
);

// ============================================================
// STATUS
// ============================================================

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
          id:
            me.id,

          nickname:
            me.nickname,

          country_id:
            me.country_id
        };

        saveTokens({
          ...tokenCache,
          user_id:
            me.id
        });

        result.user_id =
          me.id;

      } catch (error) {
        result.api_error =
          error.message;
      }
    }

    res.json(result);
  }
);

// ============================================================
// ORDERS API
// ============================================================

app.get(
  '/api/orders',
  async (req, res) => {
    try {
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

      const data =
        await fetchOrders(
          limit,
          offset
        );

      const results =
        (
          data.results || []
        ).map(
          enrichOrder
        );

      res.json({
        ok: true,

        paging:
          data.paging || {},

        results
      });

    } catch (error) {
      console.error(
        'ORDERS ERROR:',
        error.message
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

// ============================================================
// DASHBOARD COMPLETO
// ============================================================

app.get(
  '/api/dashboard',
  async (req, res) => {
    try {
      const today =
        todayArgentina();

      const ordersData =
        await fetchOrders(
          50,
          0
        );

      const rawOrders =
        ordersData.results || [];

      const orders =
        rawOrders.map(
          enrichOrder
        );

      const todayOrders =
        orders.filter(
          order => {
            if (
              !order.date_created
            ) {
              return false;
            }

            const date =
              new Date(
                order.date_created
              );

            const local =
              new Intl.DateTimeFormat(
                'en-CA',
                {
                  timeZone:
                    'America/Argentina/Buenos_Aires',
                  year: 'numeric',
                  month: '2-digit',
                  day: '2-digit'
                }
              ).format(date);

            return local === today;
          }
        );

      let sales =
        0;

      let units =
        0;

      let productCost =
        0;

      for (
        const order
        of todayOrders
      ) {
        sales +=
          Number(
            order.total_amount
          ) || 0;

        units +=
          Number(
            order.conteonix?.units
          ) || 0;

        productCost +=
          Number(
            order.conteonix?.productCost
          ) || 0;
      }

      let ads = {
        cost: 0,
        total_amount: 0,
        units_quantity: 0,
        clicks: 0,
        roas: 0,
        acos: 0
      };

      try {
        ads =
          await getAdsSummary(
            today,
            today
          );
      } catch (error) {
        console.error(
          'Dashboard Ads:',
          error.message
        );
      }

      const estimatedProfit =
        sales -
        Number(ads.cost || 0) -
        productCost;

      res.json({
        ok: true,

        date:
          today,

        summary: {
          sales,
          units,
          orders:
            todayOrders.length,

          productCost,

          advertisingCost:
            Number(ads.cost || 0),

          advertisingSales:
            Number(
              ads.total_amount || 0
            ),

          profit:
            estimatedProfit,

          roas:
            Number(
              ads.roas || 0
            ),

          acos:
            Number(
              ads.acos || 0
            )
        },

        orders:
          orders.slice(0, 50),

        ads
      });

    } catch (error) {
      console.error(
        'DASHBOARD ERROR:',
        error.message
      );

      res
        .status(
          error.status || 500
        )
        .json({
          ok: false,

          error:
            error.message
        });
    }
  }
);

// ============================================================
// PRODUCT ADS
// ============================================================

async function fetchAdvertisers() {
  const accessToken =
    await getAccessToken();

  const response =
    await fetch(
      `${API_BASE}/advertising/advertisers?product_id=PADS`,
      {
        headers: {
          Authorization:
            `Bearer ${accessToken}`,

          Accept:
            'application/json',

          'api-version':
            '1'
        }
      }
    );

  const text =
    await response.text();

  let data;

  try {
    data =
      JSON.parse(text);
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    throw new Error(
      data.message ||
      data.error ||
      `Advertising HTTP ${response.status}`
    );
  }

  return data;
}

async function getAdvertiser() {
  const data =
    await fetchAdvertisers();

  const advertisers =
    data.advertisers ||
    data.results ||
    [];

  if (
    !Array.isArray(
      advertisers
    ) ||
    advertisers.length === 0
  ) {
    throw new Error(
      'No se encontró advertiser de Product Ads.'
    );
  }

  return (
    advertisers.find(
      advertiser =>
        String(
          advertiser.site_id
        ).toUpperCase() ===
        'MLA'
    ) ||
    advertisers[0]
  );
}

const AD_METRICS = [
  'clicks',
  'prints',
  'ctr',
  'cost',
  'cpc',
  'acos',
  'organic_units_quantity',
  'organic_units_amount',
  'organic_items_quantity',
  'direct_items_quantity',
  'indirect_items_quantity',
  'advertising_items_quantity',
  'cvr',
  'roas',
  'sov',
  'direct_units_quantity',
  'indirect_units_quantity',
  'units_quantity',
  'direct_amount',
  'indirect_amount',
  'total_amount'
].join(',');

function emptyAdsSummary() {
  return {
    clicks: 0,
    prints: 0,
    cost: 0,
    total_amount: 0,
    direct_amount: 0,
    indirect_amount: 0,
    units_quantity: 0,
    direct_units_quantity: 0,
    indirect_units_quantity: 0,
    ctr: 0,
    cpc: 0,
    roas: 0,
    acos: 0
  };
}

async function getAdsSummary(
  dateFrom,
  dateTo
) {
  const advertiser =
    await getAdvertiser();

  const site =
    advertiser.site_id ||
    'MLA';

  const advertiserId =
    advertiser.advertiser_id;

  if (!advertiserId) {
    throw new Error(
      'Mercado Libre no devolvió advertiser_id.'
    );
  }

  const params =
    new URLSearchParams();

  params.set(
    'limit',
    '50'
  );

  params.set(
    'offset',
    '0'
  );

  params.set(
    'date_from',
    dateFrom
  );

  params.set(
    'date_to',
    dateTo
  );

  params.set(
    'metrics',
    AD_METRICS
  );

  if (
    dateFrom === dateTo
  ) {
    params.set(
      'aggregation_type',
      'DAILY'
    );
  } else {
    params.set(
      'metrics_summary',
      'true'
    );
  }

  const endpoint =
    `/advertising/${site}/advertisers/${advertiserId}/product_ads/campaigns/search?${params.toString()}`;

  const data =
    await mlAdsFetch(
      endpoint
    );

  const campaigns =
    Array.isArray(
      data.results
    )
      ? data.results
      : [];

  const metrics =
    emptyAdsSummary();

  const numericFields = [
    'clicks',
    'prints',
    'cost',
    'direct_amount',
    'indirect_amount',
    'total_amount',
    'direct_units_quantity',
    'indirect_units_quantity',
    'units_quantity'
  ];

  const summary =
    data.metrics_summary ||
    {};

  for (
    const field
    of numericFields
  ) {
    if (
      summary[field] !==
      undefined
    ) {
      metrics[field] =
        Number(
          summary[field] || 0
        );
    }
  }

  if (
    Object.keys(summary)
      .length === 0
  ) {
    for (
      const campaign
      of campaigns
    ) {
      for (
        const field
        of numericFields
      ) {
        metrics[field] +=
          Number(
            campaign[field] ||
            campaign.metrics?.[field] ||
            0
          );
      }
    }
  }

  metrics.ctr =
    metrics.prints > 0
      ? (
          metrics.clicks /
          metrics.prints
        ) * 100
      : 0;

  metrics.cpc =
    metrics.clicks > 0
      ? (
          metrics.cost /
          metrics.clicks
        )
      : 0;

  metrics.acos =
    metrics.total_amount > 0
      ? (
          metrics.cost /
          metrics.total_amount
        ) * 100
      : 0;

  metrics.roas =
    metrics.cost > 0
      ? (
          metrics.total_amount /
          metrics.cost
        )
      : 0;

  return {
    ...metrics,

    campaigns
  };
}

app.get(
  '/api/ads',
  async (req, res) => {
    try {
      const dateFrom =
        req.query.date_from ||
        req.query.date ||
        todayArgentina();

      const dateTo =
        req.query.date_to ||
        req.query.date ||
        dateFrom;

      const summary =
        await getAdsSummary(
          dateFrom,
          dateTo
        );

      res.json({
        ok: true,

        date_from:
          dateFrom,

        date_to:
          dateTo,

        summary,

        campaigns:
          summary.campaigns ||
          []
      });

    } catch (error) {
      console.error(
        'ADS ERROR:',
        error.details ||
        error.message
      );

      res.json({
        ok: true,

        date_from:
          req.query.date_from ||
          todayArgentina(),

        date_to:
          req.query.date_to ||
          todayArgentina(),

        summary:
          emptyAdsSummary(),

        campaigns: [],

        fetch_error:
          error.message
      });
    }
  }
);

// ============================================================
// PRODUCTOS
// ============================================================

async function getItem(itemId) {
  return mlFetch(
    `/items/${encodeURIComponent(itemId)}`
  );
}

async function buildProductList() {
  const map =
    {};

  const ordersData =
    await fetchOrders(
      50,
      0
    );

  const orders =
    ordersData.results || [];

  for (
    const order
    of orders
  ) {
    const items =
      order.order_items || [];

    for (
      const item
      of items
    ) {
      const itemId =
        item.item?.id ||
        item.item_id;

      if (!itemId) {
        continue;
      }

      if (
        map[itemId]
      ) {
        continue;
      }

      map[itemId] = {
        id:
          itemId,

        title:
          item.item?.title ||
          item.title ||
          'Producto',

        soldUnits:
          0,

        stock:
          null,

        price:
          Number(
            item.unit_price
          ) || 0
      };
    }
  }

  const ids =
    Object.keys(map);

  for (
    const id
    of ids
  ) {
    try {
      const item =
        await getItem(id);

      map[id].title =
        item.title ||
        map[id].title;

      map[id].stock =
        Number(
          item.available_quantity
        );

      map[id].price =
        Number(
          item.price
        ) ||
        map[id].price;

    } catch (error) {
      console.error(
        `Error item ${id}:`,
        error.message
      );
    }

    await sleep(100);
  }

  for (
    const order
    of orders
  ) {
    for (
      const orderItem
      of (
        order.order_items ||
        []
      )
    ) {
      const id =
        orderItem.item?.id ||
        orderItem.item_id;

      if (
        id &&
        map[id]
      ) {
        map[id].soldUnits +=
          Number(
            orderItem.quantity
          ) || 0;
      }
    }
  }

  return Object.values(
    map
  ).map(product => {
    const config =
      getProductConfig(
        product.id
      );

    return {
      ...product,

      cost:
        Number(config.cost) || 0,

      minStock:
        Number(config.minStock) || 5,

      targetDays:
        Number(config.targetDays) || 15
    };
  });
}

app.get(
  '/api/products',
  async (req, res) => {
    try {
      const products =
        await buildProductList();

      res.json({
        ok: true,

        products
      });

    } catch (error) {
      console.error(
        'PRODUCTS ERROR:',
        error.message
      );

      res
        .status(
          error.status || 500
        )
        .json({
          ok: false,

          error:
            error.message
        });
    }
  }
);

// ============================================================
// GUARDAR CONFIGURACIÓN DE PRODUCTO
// ============================================================

app.post(
  '/api/products/config',
  (req, res) => {
    try {
      const {
        itemId,
        cost,
        minStock,
        targetDays
      } = req.body || {};

      if (!itemId) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              'Falta itemId.'
          });
      }

      const numericCost =
        Number(cost);

      const numericMin =
        Number(minStock);

      const numericTarget =
        Number(targetDays);

      if (
        !Number.isFinite(
          numericCost
        ) ||
        numericCost < 0
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              'El costo debe ser un número igual o mayor a 0.'
          });
      }

      productConfig[
        String(itemId)
      ] = {
        cost:
          numericCost,

        minStock:
          Number.isFinite(
            numericMin
          )
            ? Math.max(
                0,
                numericMin
              )
            : 5,

        targetDays:
          Number.isFinite(
            numericTarget
          )
            ? Math.max(
                1,
                numericTarget
              )
            : 15
      };

      saveProductConfig();

      res.json({
        ok: true,

        itemId:
          String(itemId),

        config:
          productConfig[
            String(itemId)
          ]
      });

    } catch (error) {
      console.error(
        'SAVE PRODUCT:',
        error.message
      );

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

// ============================================================
// BORRAR CONFIGURACIÓN
// ============================================================

app.delete(
  '/api/products/config/:itemId',
  (req, res) => {
    const itemId =
      String(
        req.params.itemId
      );

    delete productConfig[
      itemId
    ];

    saveProductConfig();

    res.json({
      ok: true
    });
  }
);

// ============================================================
// STOCK / REPOSICIÓN
// ============================================================

app.get(
  '/api/stock',
  async (req, res) => {
    try {
      const products =
        await buildProductList();

      const result =
        products.map(
          product => {
            const avgDaily =
              product.soldUnits > 0
                ? (
                    product.soldUnits /
                    30
                  )
                : 0;

            const daysStock =
              avgDaily > 0
                ? (
                    product.stock /
                    avgDaily
                  )
                : null;

            const targetUnits =
              avgDaily > 0
                ? Math.ceil(
                    avgDaily *
                    product.targetDays
                  )
                : product.minStock;

            const reorder =
              Math.max(
                0,
                targetUnits -
                Number(
                  product.stock || 0
                )
              );

            let status =
              'ok';

            if (
              Number(
                product.stock || 0
              ) <=
              Number(
                product.minStock
              )
            ) {
              status =
                'critical';
            } else if (
              daysStock !== null &&
              daysStock <= 7
            ) {
              status =
                'warning';
            }

            return {
              ...product,

              avgDailySales:
                Number(
                  avgDaily.toFixed(2)
                ),

              daysStock:
                daysStock === null
                  ? null
                  : Number(
                      daysStock.toFixed(1)
                    ),

              reorderQuantity:
                reorder,

              status
            };
          }
        );

      res.json({
        ok: true,

        products:
          result
      });

    } catch (error) {
      console.error(
        'STOCK ERROR:',
        error.message
      );

      res
        .status(
          error.status || 500
        )
        .json({
          ok: false,

          error:
            error.message
        });
    }
  }
);

// ============================================================
// WEBHOOK MERCADO LIBRE
// ============================================================

async function processMLNotification(
  notification
) {
  if (
    !notification
  ) {
    return;
  }

  console.log(
    'NOTIFICACIÓN MERCADO LIBRE:',
    JSON.stringify(
      notification
    )
  );

  if (
    notification.topic !==
      'orders_v2' &&
    notification.topic !==
      'orders'
  ) {
    return;
  }

  const resource =
    notification.resource;

  if (!resource) {
    return;
  }

  try {
    const order =
      await mlFetch(
        resource
      );

    const enriched =
      enrichOrder(
        order
      );

    console.log(
      'NUEVA/ACTUALIZADA ORDEN:',
      order.id
    );

    broadcast({
      type:
        'new_order',

      order:
        enriched,

      time:
        new Date().toISOString()
    });

  } catch (error) {
    console.error(
      'Error procesando webhook:',
      error.message
    );

    broadcast({
      type:
        'notification_error',

      error:
        error.message
    });
  }
}

app.post(
  '/notifications',
  (req, res) => {
    res.status(200).json({
      ok: true
    });

    setImmediate(
      () =>
        processMLNotification(
          req.body || {}
        )
    );
  }
);

app.post(
  '/webhooks/mercadolibre',
  (req, res) => {
    res.status(200).json({
      ok: true
    });

    setImmediate(
      () =>
        processMLNotification(
          req.body || {}
        )
    );
  }
);

// ============================================================
// SYNC
// ============================================================

app.post(
  '/api/sync',
  async (req, res) => {
    try {
      const me =
        await mlFetch(
          '/users/me'
        );

      saveTokens({
        ...tokenCache,

        user_id:
          me.id
      });

      const orders =
        await fetchOrders(
          50,
          0
        );

      res.json({
        ok: true,

        synced_at:
          new Date().toISOString(),

        total:
          orders.paging?.total ||
          orders.results?.length ||
          0,

        orders:
          orders.results || []
      });

    } catch (error) {
      res
        .status(
          error.status || 500
        )
        .json({
          ok: false,

          error:
            error.message
        });
    }
  }
);

// ============================================================
// LOGOUT
// ============================================================

app.post(
  '/api/logout',
  (req, res) => {
    tokenCache = null;

    try {
      if (
        fs.existsSync(
          TOKEN_FILE
        )
      ) {
        fs.unlinkSync(
          TOKEN_FILE
        );
      }
    } catch (error) {
      console.error(
        error.message
      );
    }

    res.json({
      ok: true
    });
  }
);

// ============================================================
// 404 API
// ============================================================

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      ok: false,

      error:
        `Ruta no encontrada: ${req.method} ${req.originalUrl}`
    });
  }
);

// ============================================================
// 404 GENERAL
// ============================================================

app.use(
  (req, res) => {
    res
      .status(404)
      .send(
        `Ruta no encontrada: ${req.method} ${req.originalUrl}`
      );
  }
);

// ============================================================
// SERVER
// ============================================================

const server =
  app.listen(
    PORT,
    '0.0.0.0',
    () => {

      console.log(
        '=========================================='
      );

      console.log(
        'CONTEONIX ONLINE'
      );

      console.log(
        `PORT: ${PORT}`
      );

      console.log(
        `BASE_URL: ${BASE_URL}`
      );

      console.log(
        `HEALTH: ${BASE_URL}/api/health`
      );

      console.log(
        `DASHBOARD: ${BASE_URL}/api/dashboard`
      );

      console.log(
        `ADS: ${BASE_URL}/api/ads`
      );

      console.log(
        `PRODUCTS: ${BASE_URL}/api/products`
      );

      console.log(
        `STOCK: ${BASE_URL}/api/stock`
      );

      console.log(
        `WEBHOOK: ${BASE_URL}/notifications`
      );

      console.log(
        '=========================================='
      );
    }
  );

server.on(
  'error',
  error => {
    console.error(
      'SERVER ERROR:',
      error
    );
  }
);

process.on(
  'uncaughtException',
  error => {
    console.error(
      'UNCAUGHT EXCEPTION:',
      error
    );
  }
);

process.on(
  'unhandledRejection',
  error => {
    console.error(
      'UNHANDLED REJECTION:',
      error
    );
  }
);
```
