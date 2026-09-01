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
// TOKENS
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
    JSON.stringify(
      tokens,
      null,
      2
    ),
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
// TOKEN REQUEST
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

// ============================================================
// OBTENER TOKEN
// ============================================================

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
// REQUEST GENERAL MERCADO LIBRE
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

  const text =
    await response.text();

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

    error.status =
      response.status;

    error.details =
      data;

    throw error;
  }

  return data;
}

// ============================================================
// REQUEST PRODUCT ADS
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

    error.status =
      response.status;

    error.details =
      data;

    throw error;
  }

  return data;
}

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
            me.country_id,

          email:
            me.email ||
            null
        };

        saveTokens({
          ...tokenCache,

          user_id: me.id
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
      console.error(
        'ORDERS ERROR:',
        error.details ||
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
// SINCRONIZACIÓN
// ============================================================

app.post(
  '/api/sync',
  async (req, res) => {
    try {
      const me =
        await mlFetch(
          '/users/me'
        );

      const seller = me.id;

      const params =
        new URLSearchParams({
          seller: String(seller),

          limit: '50',

          offset: '0',

          sort: 'date_desc'
        });

      const orders =
        await mlFetch(
          `/orders/search?${params.toString()}`
        );

      saveTokens({
        ...tokenCache,

        user_id: seller
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
          orders.results ||
          []
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
// ADVERTISERS PRODUCT ADS
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
    const error =
      new Error(
        data.message ||
        data.error ||
        `Advertising HTTP ${response.status}`
      );

    error.status =
      response.status;

    error.details =
      data;

    throw error;
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
        ).toUpperCase() === 'MLA'
    ) ||
    advertisers[0]
  );
}

// ============================================================
// MÉTRICAS PRODUCT ADS
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

// ============================================================
// TEST PRODUCT ADS
// ============================================================

app.get(
  '/api/ads/test',
  async (req, res) => {
    try {
      const advertiser =
        await getAdvertiser();

      res.json({
        ok: true,

        advertiser
      });

    } catch (error) {
      res.status(200).json({
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
// PRODUCT ADS
// ============================================================

app.get(
  '/api/ads',
  async (req, res) => {
    const dateFrom =
      req.query.date_from ||
      req.query.date ||
      todayArgentina();

    const dateTo =
      req.query.date_to ||
      req.query.date ||
      dateFrom;

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

      console.log(
        'PRODUCT ADS REQUEST:',
        endpoint
      );

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

      // --------------------------------------------------------
      // Primero intentamos metrics_summary
      // --------------------------------------------------------

      const summary =
        data.metrics_summary ||
        data.summary ||
        {};

      for (
        const field
        of numericFields
      ) {
        if (
          summary[field] !==
          undefined &&
          summary[field] !== null
        ) {
          metrics[field] =
            Number(
              summary[field]
            ) || 0;
        }
      }

      // --------------------------------------------------------
      // Si no vino summary, sumamos campañas
      // --------------------------------------------------------

      if (
        Object.keys(summary).length === 0
      ) {
        for (
          const campaign
          of campaigns
        ) {
          const source =
            campaign.metrics ||
            campaign;

          for (
            const field
            of numericFields
          ) {
            metrics[field] +=
              Number(
                source[field]
              ) || 0;
          }
        }
      }

      // --------------------------------------------------------
      // Algunas respuestas pueden devolver métricas
      // dentro de arrays de resultados
      // --------------------------------------------------------

      if (
        metrics.cost === 0 &&
        campaigns.length > 0
      ) {
        for (
          const campaign
          of campaigns
        ) {
          const possibleMetrics = [
            campaign.metrics,
            campaign.metric,
            campaign.metrics_summary
          ];

          for (
            const source
            of possibleMetrics
          ) {
            if (!source) {
              continue;
            }

            metrics.cost +=
              Number(
                source.cost
              ) || 0;

            metrics.total_amount +=
              Number(
                source.total_amount
              ) || 0;

            metrics.direct_amount +=
              Number(
                source.direct_amount
              ) || 0;

            metrics.indirect_amount +=
              Number(
                source.indirect_amount
              ) || 0;

            metrics.units_quantity +=
              Number(
                source.units_quantity
              ) || 0;
          }
        }
      }

      // --------------------------------------------------------
      // CÁLCULOS
      // --------------------------------------------------------

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

      console.log(
        'PRODUCT ADS SUMMARY:',
        JSON.stringify(
          metrics,
          null,
          2
        )
      );

      res.json({
        ok: true,

        date_from: dateFrom,

        date_to: dateTo,

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

        campaigns,

        raw_metrics_summary:
          data.metrics_summary ||
          null
      });

    } catch (error) {
      console.error(
        'ADS ERROR:',
        error.details ||
        error.message
      );

      // No rompemos el dashboard si Product Ads
      // falla temporalmente.
      res.status(200).json({
        ok: true,

        date_from: dateFrom,

        date_to: dateTo,

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
// SSE TIEMPO REAL
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

        clients.delete(
          res
        );
      }
    );
  }
);

// ============================================================
// WEBHOOK MERCADO LIBRE
// ============================================================

async function processNotification(
  notification
) {
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

    console.log(
      'NUEVA/ACTUALIZADA ORDEN:',
      order.id
    );

    broadcast({
      type: 'new_order',

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
    // Mercado Libre necesita respuesta rápida.
    res.status(200).json({
      ok: true
    });

    setImmediate(
      () =>
        processNotification(
          req.body || {}
        )
    );
  }
);

// Algunos configuradores usan /webhooks
app.post(
  '/webhooks/mercadolibre',
  async (req, res) => {
    res.status(200).json({
      ok: true
    });

    setImmediate(
      () =>
        processNotification(
          req.body || {}
        )
    );
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
        'Error eliminando token:',
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
