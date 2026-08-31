```javascript
require('dotenv').config();

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
// ARCHIVOS ESTÁTICOS
// ============================================================

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

// ============================================================
// CONFIGURACIÓN
// ============================================================

const PORT =
  process.env.PORT || 3000;

const BASE_URL =
  process.env.BASE_URL ||
  'https://conteo-rt2c.onrender.com';

// IMPORTANTE:
// Se evita usar template literals acá para eliminar
// cualquier posibilidad de que Render reciba caracteres
// escapados incorrectamente.

const REDIRECT_URI =
  process.env.ML_REDIRECT_URI ||
  BASE_URL + '/auth/callback';

const CLIENT_ID =
  process.env.ML_CLIENT_ID;

const CLIENT_SECRET =
  process.env.ML_CLIENT_SECRET;

const AUTH_DOMAIN =
  process.env.ML_AUTH_DOMAIN ||
  'https://auth.mercadolibre.com.ar';

const API_BASE =
  process.env.ML_API_BASE ||
  'https://api.mercadolibre.com';

const SYNC_API_KEY =
  process.env.SYNC_API_KEY;

const TOKEN_FILE =
  process.env.TOKEN_FILE ||
  path.join(
    __dirname,
    'data',
    'tokens.json'
  );

// ============================================================
// CREAR CARPETA DE DATOS
// ============================================================

if (
  !fs.existsSync(
    path.dirname(TOKEN_FILE)
  )
) {
  fs.mkdirSync(
    path.dirname(TOKEN_FILE),
    {
      recursive: true
    }
  );
}

// ============================================================
// ESTADO OAUTH
// ============================================================

let oauthState = null;

let pkceVerifier = null;

let tokenCache =
  loadTokens();

// ============================================================
// TOKENS
// ============================================================

function loadTokens() {
  try {
    return JSON.parse(
      fs.readFileSync(
        TOKEN_FILE,
        'utf8'
      )
    );
  } catch {
    return null;
  }
}

function saveTokens(tokens) {
  const tmp =
    TOKEN_FILE + '.tmp';

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
// CONFIGURACIÓN OBLIGATORIA
// ============================================================

function requireConfig() {
  const missing = [];

  if (!CLIENT_ID) {
    missing.push(
      'ML_CLIENT_ID'
    );
  }

  if (!CLIENT_SECRET) {
    missing.push(
      'ML_CLIENT_SECRET'
    );
  }

  if (!REDIRECT_URI) {
    missing.push(
      'ML_REDIRECT_URI'
    );
  }

  if (missing.length) {
    throw new Error(
      'Faltan variables de entorno: ' +
      missing.join(', ')
    );
  }
}

// ============================================================
// UTILIDADES
// ============================================================

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

function escapeHtml(value) {
  return String(value).replace(
    /[&<>'"]/g,
    function (char) {
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

  const data = {};

  for (const part of parts) {
    data[part.type] =
      part.value;
  }

  return (
    data.year +
    '-' +
    data.month +
    '-' +
    data.day
  );
}

// ============================================================
// MERCADO LIBRE - TOKEN REQUEST
// ============================================================

async function tokenRequest(body) {
  const response =
    await fetch(
      API_BASE +
      '/oauth/token',
      {
        method: 'POST',

        headers: {
          accept:
            'application/json',

          'content-type':
            'application/x-www-form-urlencoded'
        },

        body:
          new URLSearchParams(
            body
          )
      }
    );

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
    const error =
      new Error(
        data.error_description ||
        data.error ||
        'HTTP ' +
          response.status
      );

    error.status =
      response.status;

    error.details = data;

    throw error;
  }

  return data;
}

// ============================================================
// INTERCAMBIO DEL CODE OAuth
// ============================================================

async function exchangeCode(code) {
  const body = {
    grant_type:
      'authorization_code',

    client_id:
      CLIENT_ID,

    client_secret:
      CLIENT_SECRET,

    code:
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

  saveTokens({
    ...data,

    obtained_at:
      Date.now(),

    expires_at:
      Date.now() +
      (
        (data.expires_in ||
          21600) *
        1000
      )
  });

  return data;
}

// ============================================================
// REFRESH TOKEN
// ============================================================

async function refreshAccessToken() {
  if (
    !tokenCache?.refresh_token
  ) {
    throw new Error(
      'No hay refresh_token. Hay que conectar Mercado Libre nuevamente.'
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

  saveTokens({
    ...data,

    obtained_at:
      Date.now(),

    expires_at:
      Date.now() +
      (
        (data.expires_in ||
          21600) *
        1000
      )
  });

  return data.access_token;
}

// ============================================================
// ACCESS TOKEN
// ============================================================

async function getAccessToken() {
  if (
    !tokenCache?.access_token
  ) {
    throw new Error(
      'Mercado Libre no está conectado.'
    );
  }

  const safetyWindow =
    60 * 1000;

  if (
    tokenCache.expires_at &&
    Date.now() <
      tokenCache.expires_at -
      safetyWindow
  ) {
    return tokenCache.access_token;
  }

  return refreshAccessToken();
}

// ============================================================
// REQUEST GENERAL A MERCADO LIBRE
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
      'Bearer ' +
      accessToken,

    Accept:
      'application/json'
  };

  const response =
    await fetch(
      API_BASE + endpoint,
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
    const error =
      new Error(
        data.message ||
        data.error ||
        'Mercado Libre HTTP ' +
          response.status
      );

    error.status =
      response.status;

    error.details = data;

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
  retry = true,
  apiVersion = '2'
) {
  const accessToken =
    await getAccessToken();

  const headers = {
    ...(options.headers || {}),

    Authorization:
      'Bearer ' +
      accessToken,

    Accept:
      'application/json',

    'api-version':
      apiVersion
  };

  const response =
    await fetch(
      API_BASE + endpoint,
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
      false,
      apiVersion
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
    const error =
      new Error(
        data.message ||
        data.error ||
        'Mercado Libre HTTP ' +
          response.status
      );

    error.status =
      response.status;

    error.details = data;

    throw error;
  }

  return data;
}

// ============================================================
// PÁGINA PRINCIPAL
// ============================================================

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

// ============================================================
// LOGIN MERCADO LIBRE
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
          AUTH_DOMAIN +
          '/authorization'
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
          '<pre>' +
            escapeHtml(
              error.message
            ) +
            '</pre>'
        );
    }
  }
);

// ============================================================
// CALLBACK OAuth
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
            '<pre>' +
              escapeHtml(
                req.query.error_description ||
                req.query.error
              ) +
              '</pre>'
          );
      }

      if (
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
            'Falta el código de autorización.'
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
        'Error OAuth:',
        error.details || error
      );

      res
        .status(
          error.status || 500
        )
        .send(
          '<h1>No se pudo conectar Mercado Libre</h1>' +
          '<pre>' +
          escapeHtml(
            error.message
          ) +
          '</pre>'
        );
    }
  }
);

// ============================================================
// ESTADO DE CONEXIÓN
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
      } catch (error) {
        result.api_error =
          error.message;
      }
    }

    res.json(result);
  }
);

// ============================================================
// OBTENER VENTAS
// ============================================================

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

      if (req.query.status) {
        params.set(
          'order.status',
          req.query.status
        );
      }

      const data =
        await mlFetch(
          '/orders/search?' +
          params.toString()
        );

      res.json({
        ok: true,
        ...data
      });
    } catch (error) {
      console.error(
        'Error /api/orders:',
        error.details || error
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
// SINCRONIZAR VENTAS
// ============================================================

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
              req.body?.limit ||
              req.query.limit
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

          offset:
            '0',

          sort:
            'date_desc'
        });

      const data =
        await mlFetch(
          '/orders/search?' +
          params.toString()
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
      console.error(
        'Error /api/sync:',
        error.details || error
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
    } catch {}

    res.json({
      ok: true,

      message:
        'Credenciales locales eliminadas. La autorización en Mercado Libre no se revoca desde este endpoint.'
    });
  }
);

// ============================================================
// OBTENER ADVERTISER PRODUCT ADS
//
// ESTE ENDPOINT USA API-VERSION 1.
// Mercado Libre documenta actualmente:
//
// GET /advertising/advertisers?product_id=PADS
//
// ============================================================

async function getAdvertiser() {
  const data =
    await mlAdsFetch(
      '/advertising/advertisers?product_id=PADS',
      {},
      true,
      '1'
    );

  const advertisers =
    data.advertisers ||
    data.results ||
    [];

  if (
    !advertisers.length
  ) {
    throw new Error(
      'No se encontró un anunciante de Product Ads para esta cuenta.'
    );
  }

  const advertiser =
    advertisers.find(
      item =>
        item.site_id ===
        'MLA'
    ) ||
    advertisers[0];

  return advertiser;
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

// ============================================================
// API ADS
//
// Endpoint vigente de campañas:
//
// /advertising/{SITE}/advertisers/{ADVERTISER_ID}
// /product_ads/campaigns/search
//
// api-version: 2
// ============================================================

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

      const date =
        req.query.date ||
        todayArgentina();

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
        date
      );

      params.set(
        'date_to',
        date
      );

      params.set(
        'metrics',
        AD_METRICS
      );

      params.set(
        'aggregation_type',
        'DAILY'
      );

      const endpoint =
        '/advertising/' +
        site +
        '/advertisers/' +
        advertiserId +
        '/product_ads/campaigns/search?' +
        params.toString();

      const data =
        await mlAdsFetch(
          endpoint,
          {},
          true,
          '2'
        );

      const campaigns =
        data.results || [];

      const metrics = {};

      const numericFields = [
        'clicks',
        'prints',
        'cost',
        'direct_amount',
        'indirect_amount',
        'total_amount',
        'direct_units_quantity',
        'indirect_units_quantity',
        'units_quantity',
        'direct_items_quantity',
        'indirect_items_quantity',
        'advertising_items_quantity',
        'organic_units_quantity',
        'organic_units_amount',
        'organic_items_quantity'
      ];

      for (
        const campaign
        of campaigns
      ) {
        const values =
          campaign.metrics ||
          campaign;

        for (
          const field
          of numericFields
        ) {
          metrics[field] =
            (
              metrics[field] ||
              0
            ) +
            Number(
              values[field] || 0
            );
        }
      }

      metrics.ctr =
        metrics.prints
          ? (
              metrics.clicks /
              metrics.prints
            ) * 100
          : 0;

      metrics.cpc =
        metrics.clicks
          ? (
              metrics.cost /
              metrics.clicks
            )
          : 0;

      metrics.acos =
        metrics.total_amount
          ? (
              metrics.cost /
              metrics.total_amount
            ) * 100
          : 0;

      metrics.roas =
        metrics.cost
          ? (
              metrics.total_amount /
              metrics.cost
            )
          : 0;

      res.json({
        ok: true,

        date,

        advertiser: {
          id:
            advertiserId,

          siteId:
            site,

          name:
            advertiser.advertiser_name ||
            advertiser.name ||
            null,

          account:
            advertiser.account_name ||
            advertiser.account ||
            null
        },

        summary:
          metrics,

        campaigns,

        items: []
      });
    } catch (error) {
      console.error(
        'Error /api/ads:',
        error.details || error
      );

      res.status(200).json({
        ok: true,

        period:
          req.query.period ||
          'today',

        date_from:
          req.query.date_from ||
          req.query.date ||
          todayArgentina(),

        date_to:
          req.query.date_to ||
          req.query.date ||
          todayArgentina(),

        advertiser:
          null,

        summary: {
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
        },

        campaigns: [],

        items: [],

        fetch_error:
          error.message
      });
    }
  }
);

// ============================================================
// SALUD DEL SERVIDOR
// ============================================================

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,

      service:
        'conteonix',

      time:
        new Date().toISOString(),

      connected:
        !!tokenCache?.access_token
    });
  }
);

// ============================================================
// INICIAR SERVIDOR
// ============================================================

app.listen(
  PORT,
  () => {
    console.log(
      'Conteonix escuchando en puerto ' +
      PORT
    );

    console.log(
      'BASE_URL: ' +
      BASE_URL
    );

    console.log(
      'REDIRECT_URI: ' +
      REDIRECT_URI
    );
  }
);
```
