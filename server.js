require('dotenv').config();

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

// ============================================================
// CONFIG
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

const TOKEN_FILE =
  process.env.TOKEN_FILE ||
  path.join(__dirname, 'data', 'tokens.json');

// ============================================================
// EXPRESS
// ============================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PUBLIC_DIR = path.join(__dirname, 'public');

app.use(express.static(PUBLIC_DIR));

// ============================================================
// TOKEN / LOCAL DATA
// ============================================================

const tokenDirectory = path.dirname(TOKEN_FILE);

if (!fs.existsSync(tokenDirectory)) {
  fs.mkdirSync(tokenDirectory, {
    recursive: true
  });
}

let tokenCache = loadTokens();

function loadTokens() {
  try {
    if (!fs.existsSync(TOKEN_FILE)) {
      return null;
    }

    const content = fs.readFileSync(
      TOKEN_FILE,
      'utf8'
    );

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
  const tmp = `${TOKEN_FILE}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(tokens, null, 2),
    {
      mode: 0o600
    }
  );

  fs.renameSync(tmp, TOKEN_FILE);

  tokenCache = tokens;
}

function getLocalData() {
  return {
    productCosts:
      tokenCache?.productCosts || {},

    settings:
      tokenCache?.settings || {
        stockAlertDays: 10,
        stockCriticalDays: 5
      }
  };
}

function saveLocalData(data) {
  saveTokens({
    ...(tokenCache || {}),
    productCosts:
      data.productCosts || {},
    settings:
      data.settings || {}
  });
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
    ).formatToParts(new Date());

  const result = {};

  for (const part of parts) {
    result[part.type] = part.value;
  }

  return `${result.year}-${result.month}-${result.day}`;
}

function dateInArgentina(value) {
  if (!value) {
    return '';
  }

  return new Intl.DateTimeFormat(
    'en-CA',
    {
      timeZone:
        'America/Argentina/Buenos_Aires',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    }
  ).format(new Date(value));
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

// ============================================================
// MERCADO LIBRE TOKEN
// ============================================================

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
    data = {
      raw: text
    };
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

  const data =
    await tokenRequest(body);

  const now = Date.now();

  saveTokens({
    ...data,

    obtained_at: now,

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
  if (!tokenCache?.refresh_token) {
    throw new Error(
      'No existe refresh_token. Hay que conectar Mercado Libre nuevamente.'
    );
  }

  const data =
    await tokenRequest({
      grant_type: 'refresh_token',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token:
        tokenCache.refresh_token
    });

  const now = Date.now();

  saveTokens({
    ...tokenCache,
    ...data,

    obtained_at: now,

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
  if (!tokenCache?.access_token) {
    throw new Error(
      'Mercado Libre no está conectado.'
    );
  }

  const safety = 60 * 1000;

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
// GENERIC ML REQUEST
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

  const response = await fetch(
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

    'api-version': '2'
  };

  const response = await fetch(
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
      `Product Ads HTTP ${response.status}`
    );

    error.status = response.status;
    error.details = data;

    throw error;
  }

  return data;
}

// ============================================================
// SSE
// ============================================================

const clients = new Set();

function broadcast(event) {
  const payload =
    JSON.stringify(event);

  for (const client of clients) {
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
      setInterval(() => {
        try {
          res.write(
            ': heartbeat\n\n'
          );
        } catch {}
      }, 25000);

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

    if (!fs.existsSync(index)) {
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
      service: 'conteonix',
      status: 'online',
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

      oauthState = null;
      pkceVerifier = null;

      res.redirect(
        '/?connected=1'
      );

    } catch (error) {
      console.error(
        'OAuth error:',
        error.details || error
      );

      res
        .status(
          error.status || 500
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

    if (result.connected) {
      try {
        const me =
          await mlFetch(
            '/users/me'
          );

        result.user = {
          id: me.id,
          nickname: me.nickname,
          country_id:
            me.country_id
        };

        saveTokens({
          ...tokenCache,
          user_id: me.id
        });

        result.user_id = me.id;

      } catch (error) {
        result.api_error =
          error.message;
      }
    }

    res.json(result);
  }
);

// ============================================================
// ORDERS
// ============================================================

app.get(
  '/api/orders',
  async (req, res) => {
    try {
      const me =
        await mlFetch(
          '/users/me'
        );

      const seller = me.id;

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
        new URLSearchParams();

      params.set(
        'seller',
        String(seller)
      );

      params.set(
        'limit',
        String(limit)
      );

      params.set(
        'offset',
        String(offset)
      );

      params.set(
        'sort',
        'date_desc'
      );

      if (req.query.status) {
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
            error.details || null
        });
    }
  }
);

// ============================================================
// PRODUCT COSTS
// ============================================================

app.get(
  '/api/costs',
  (req, res) => {
    const local =
      getLocalData();

    res.json({
      ok: true,
      costs:
        local.productCosts,
      settings:
        local.settings
    });
  }
);

app.post(
  '/api/costs',
  (req, res) => {
    try {
      const itemId =
        String(
          req.body.item_id || ''
        ).trim();

      const cost =
        Number(
          req.body.cost
        );

      if (!itemId) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              'Falta item_id.'
          });
      }

      if (
        !Number.isFinite(cost) ||
        cost < 0
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              'Costo inválido.'
          });
      }

      const local =
        getLocalData();

      local.productCosts[itemId] =
        cost;

      saveLocalData(local);

      res.json({
        ok: true,
        item_id: itemId,
        cost
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

// ============================================================
// SETTINGS
// ============================================================

app.post(
  '/api/settings',
  (req, res) => {
    try {
      const local =
        getLocalData();

      if (
        req.body.stockAlertDays !==
        undefined
      ) {
        local.settings.stockAlertDays =
          Math.max(
            Number(
              req.body.stockAlertDays
            ) || 10,
            1
          );
      }

      if (
        req.body.stockCriticalDays !==
        undefined
      ) {
        local.settings.stockCriticalDays =
          Math.max(
            Number(
              req.body.stockCriticalDays
            ) || 5,
            1
          );
      }

      saveLocalData(local);

      res.json({
        ok: true,
        settings:
          local.settings
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

// ============================================================
// ITEM CACHE
// ============================================================

const itemMemoryCache = new Map();

async function getItem(itemId) {
  if (!itemId) {
    return null;
  }

  if (itemMemoryCache.has(itemId)) {
    return itemMemoryCache.get(itemId);
  }

  try {
    const item =
      await mlFetch(
        `/items/${encodeURIComponent(
          itemId
        )}`
      );

    itemMemoryCache.set(
      itemId,
      item
    );

    return item;

  } catch (error) {
    console.error(
      `Error item ${itemId}:`,
      error.message
    );

    return null;
  }
}

// ============================================================
// PRODUCTS
// ============================================================

app.get(
  '/api/products',
  async (req, res) => {
    try {
      const ordersData =
        await mlFetch(
          '/orders/search?seller=' +
          encodeURIComponent(
            tokenCache.user_id
          ) +
          '&limit=50&offset=0&sort=date_desc'
        );

      const orders =
        ordersData.results || [];

      const productsMap =
        new Map();

      for (const order of orders) {
        for (
          const orderItem
          of order.order_items || []
        ) {
          const item =
            orderItem.item || {};

          const itemId =
            item.id;

          if (!itemId) {
            continue;
          }

          if (
            !productsMap.has(
              itemId
            )
          ) {
            productsMap.set(
              itemId,
              {
                id: itemId,

                title:
                  item.title ||
                  itemId,

                sold_units: 0,

                revenue: 0,

                orders: 0
              }
            );
          }

          const product =
            productsMap.get(
              itemId
            );

          const quantity =
            Number(
              orderItem.quantity
            ) || 0;

          const unitPrice =
            Number(
              orderItem.unit_price
            ) || 0;

          product.sold_units +=
            quantity;

          product.revenue +=
            quantity *
            unitPrice;

          product.orders += 1;
        }
      }

      const local =
        getLocalData();

      const products =
        await Promise.all(
          Array.from(
            productsMap.values()
          ).map(
            async product => {
              const mlItem =
                await getItem(
                  product.id
                );

              const cost =
                Number(
                  local.productCosts[
                    product.id
                  ]
                ) || 0;

              const stock =
                Number(
                  mlItem?.available_quantity
                );

              const price =
                Number(
                  mlItem?.price
                ) || 0;

              const averageDaily =
                product.sold_units /
                30;

              const daysStock =
                averageDaily > 0 &&
                Number.isFinite(stock)
                  ? stock /
                    averageDaily
                  : null;

              const stockValue =
                Number.isFinite(stock)
                  ? stock * cost
                  : null;

              const grossProfit =
                product.revenue -
                (
                  product.sold_units *
                  cost
                );

              let status =
                'ok';

              if (
                Number.isFinite(
                  daysStock
                )
              ) {
                if (
                  daysStock <=
                  local.settings
                    .stockCriticalDays
                ) {
                  status =
                    'critical';
                } else if (
                  daysStock <=
                  local.settings
                    .stockAlertDays
                ) {
                  status =
                    'warning';
                }
              }

              return {
                ...product,

                title:
                  mlItem?.title ||
                  product.title,

                permalink:
                  mlItem?.permalink ||
                  null,

                thumbnail:
                  mlItem?.thumbnail ||
                  null,

                price,

                stock:
                  Number.isFinite(
                    stock
                  )
                    ? stock
                    : null,

                cost,

                cost_configured:
                  cost > 0,

                gross_profit:
                  grossProfit,

                margin:
                  product.revenue > 0
                    ? (
                        grossProfit /
                        product.revenue
                      ) *
                      100
                    : 0,

                average_daily:
                  averageDaily,

                days_stock:
                  daysStock,

                stock_value:
                  stockValue,

                status
              };
            }
          )
        );

      products.sort(
        (a, b) =>
          (a.days_stock ?? 999999) -
          (b.days_stock ?? 999999)
      );

      res.json({
        ok: true,
        products,
        settings:
          local.settings
      });

    } catch (error) {
      console.error(
        'PRODUCTS ERROR:',
        error
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
// ADS - ADVERTISER
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

// ============================================================
// ADS
// ============================================================

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

app.get(
  '/api/ads',
  async (req, res) => {
    try {
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

      const dateFrom =
        req.query.date_from ||
        req.query.date ||
        todayArgentina();

      const dateTo =
        req.query.date_to ||
        req.query.date ||
        dateFrom;

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

      res.json({
        ok: true,

        date_from:
          dateFrom,

        date_to:
          dateTo,

        advertiser: {
          id:
            advertiserId,

          siteId:
            site,

          name:
            advertiser.advertiser_name ||
            advertiser.name ||
            null
        },

        summary:
          metrics,

        campaigns
      });

    } catch (error) {
      console.error(
        'ADS ERROR:',
        error.details ||
        error.message
      );

      res.status(200).json({
        ok: true,

        date_from:
          req.query.date_from ||
          todayArgentina(),

        date_to:
          req.query.date_to ||
          todayArgentina(),

        advertiser: null,

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
// DASHBOARD SUMMARY
// ============================================================

app.get(
  '/api/dashboard',
  async (req, res) => {
    try {
      const me =
        await mlFetch(
          '/users/me'
        );

      const seller =
        me.id;

      const params =
        new URLSearchParams({
          seller:
            String(seller),

          limit:
            '50',

          offset:
            '0',

          sort:
            'date_desc'
        });

      const data =
        await mlFetch(
          `/orders/search?${params.toString()}`
        );

      const orders =
        data.results || [];

      const today =
        todayArgentina();

      const todayOrders =
        orders.filter(
          order =>
            dateInArgentina(
              order.date_created
            ) === today
        );

      let sales = 0;
      let units = 0;
      let cost = 0;

      const local =
        getLocalData();

      for (
        const order
        of todayOrders
      ) {
        sales +=
          Number(
            order.total_amount
          ) || 0;

        for (
          const orderItem
          of order.order_items || []
        ) {
          const item =
            orderItem.item || {};

          const quantity =
            Number(
              orderItem.quantity
            ) || 0;

          units += quantity;

          const itemCost =
            Number(
              local.productCosts[
                item.id
              ]
            ) || 0;

          cost +=
            quantity *
            itemCost;
        }
      }

      let ads =
        emptyAdsSummary();

      try {
        const advertiser =
          await getAdvertiser();

        const site =
          advertiser.site_id ||
          'MLA';

        const advertiserId =
          advertiser.advertiser_id;

        if (advertiserId) {
          const paramsAds =
            new URLSearchParams();

          paramsAds.set(
            'limit',
            '50'
          );

          paramsAds.set(
            'offset',
            '0'
          );

          paramsAds.set(
            'date_from',
            today
          );

          paramsAds.set(
            'date_to',
            today
          );

          paramsAds.set(
            'metrics',
            AD_METRICS
          );

          paramsAds.set(
            'aggregation_type',
            'DAILY'
          );

          const adsData =
            await mlAdsFetch(
              `/advertising/${site}/advertisers/${advertiserId}/product_ads/campaigns/search?${paramsAds.toString()}`
            );

          const summary =
            adsData.metrics_summary ||
            {};

          for (
            const field of [
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
            ads[field] =
              Number(
                summary[field] || 0
              );
          }

          ads.acos =
            ads.total_amount > 0
              ? (
                  ads.cost /
                  ads.total_amount
                ) * 100
              : 0;

          ads.roas =
            ads.cost > 0
              ? (
                  ads.total_amount /
                  ads.cost
                )
              : 0;
        }

      } catch (error) {
        console.error(
          'Dashboard ADS:',
          error.message
        );
      }

      const grossProfit =
        sales - cost;

      const netProfit =
        grossProfit -
        ads.cost;

      const margin =
        sales > 0
          ? (
              netProfit /
              sales
            ) * 100
          : 0;

      res.json({
        ok: true,

        date:
          today,

        sales,
        units,

        orders:
          todayOrders.length,

        product_cost:
          cost,

        gross_profit:
          grossProfit,

        advertising:
          ads.cost,

        net_profit:
          netProfit,

        margin,

        ads
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
// WEBHOOK MERCADO LIBRE
// ============================================================

const recentNotifications =
  new Map();

function alreadyProcessed(orderId) {
  if (!orderId) {
    return false;
  }

  const now =
    Date.now();

  for (
    const [id, time]
    of recentNotifications
  ) {
    if (
      now - time >
      10 * 60 * 1000
    ) {
      recentNotifications.delete(
        id
      );
    }
  }

  if (
    recentNotifications.has(
      String(orderId)
    )
  ) {
    return true;
  }

  recentNotifications.set(
    String(orderId),
    now
  );

  return false;
}

async function processMLNotification(
  notification
) {
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

    if (
      alreadyProcessed(
        order.id
      )
    ) {
      return;
    }

    console.log(
      'NUEVA VENTA:',
      order.id
    );

    broadcast({
      type:
        'new_order',

      order,

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
  async (req, res) => {
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
  async (req, res) => {
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
      const data =
        await mlFetch(
          '/users/me'
        );

      const seller =
        data.id;

      const params =
        new URLSearchParams({
          seller:
            String(seller),

          limit:
            '50',

          offset:
            '0',

          sort:
            'date_desc'
        });

      const orders =
        await mlFetch(
          `/orders/search?${params.toString()}`
        );

      saveTokens({
        ...tokenCache,
        user_id:
          seller
      });

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
            error.message,

          details:
            error.details ||
            null
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
    res.status(404).send(
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
        `PRODUCTS: ${BASE_URL}/api/products`
      );

      console.log(
        `ADS: ${BASE_URL}/api/ads`
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
