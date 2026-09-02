require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const webpush = require('web-push');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || 'https://conteo-rt2c.onrender.com';
const REDIRECT_URI = process.env.ML_REDIRECT_URI || `${BASE_URL}/auth/callback`;
const CLIENT_ID = process.env.ML_CLIENT_ID;
const CLIENT_SECRET = process.env.ML_CLIENT_SECRET;
const AUTH_DOMAIN =
  process.env.ML_AUTH_DOMAIN || 'https://auth.mercadolibre.com.ar';
const API_BASE =
  process.env.ML_API_BASE || 'https://api.mercadolibre.com';

const AR_OFFSET_MS = -3 * 60 * 60 * 1000;

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

const sseClients = new Set();

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT =
  process.env.VAPID_SUBJECT || 'mailto:soporte@conteonix.app';

const pushEnabled = !!(
  VAPID_PUBLIC_KEY &&
  VAPID_PRIVATE_KEY
);

if (pushEnabled) {
  webpush.setVapidDetails(
    VAPID_SUBJECT,
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY
  );
} else {
  console.warn(
    'VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY no configuradas: push desactivado.'
  );
}


/* =========================================================
   BASE DE DATOS
========================================================= */

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

      CREATE TABLE IF NOT EXISTS push_subscriptions (
        endpoint TEXT PRIMARY KEY,
        subscription JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS manual_ad_spend (
        spend_date DATE PRIMARY KEY,
        amount NUMERIC(12,2) NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      /*
       * Caché de reportes de facturación de Mercado Libre.
       * NO consultamos la API de billing cada 20 segundos.
       */
      CREATE TABLE IF NOT EXISTS billing_cache (
        cache_key VARCHAR(100) PRIMARY KEY,
        data JSONB NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    tokenCache = await loadTokens();

    console.log('Base de datos inicializada.');
  } catch (err) {
    console.error('Error DB:', err);
  }
}

async function loadTokens() {
  try {
    const res = await pool.query(
      'SELECT tokens FROM me_tokens WHERE id = 1'
    );

    return res.rows[0]?.tokens || null;
  } catch {
    return null;
  }
}

async function saveTokens(tokens) {
  try {
    tokenCache = tokens;

    await pool.query(
      `
      INSERT INTO me_tokens
        (id, tokens, updated_at)
      VALUES
        (1, $1, NOW())
      ON CONFLICT (id)
      DO UPDATE SET
        tokens = EXCLUDED.tokens,
        updated_at = NOW()
      `,
      [JSON.stringify(tokens)]
    );
  } catch (err) {
    console.error('Error guardando tokens:', err);
  }
}


/* =========================================================
   UTILIDADES
========================================================= */

function randomState() {
  return crypto.randomBytes(24).toString('hex');
}

function base64url(buf) {
  return buf
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

function safeNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function roundMoney(value) {
  return Math.round((safeNumber(value) + Number.EPSILON) * 100) / 100;
}


/* =========================================================
   OAUTH
========================================================= */

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

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.error_description ||
      data.error ||
      'Error obteniendo token'
    );
  }

  return data;
}

async function refreshAccessToken() {
  if (!tokenCache?.refresh_token) {
    throw new Error('No hay refresh_token');
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
      'Mercado Libre no conectado.'
    );
  }

  if (
    tokenCache.expires_at &&
    Date.now() <
      tokenCache.expires_at - 60000
  ) {
    return tokenCache.access_token;
  }

  return refreshAccessToken();
}

async function mlFetch(
  endpoint,
  extraHeaders = {},
  _isRetry = false
) {
  const accessToken =
    await getAccessToken();

  const url =
    endpoint.startsWith('http')
      ? endpoint
      : `${API_BASE}${endpoint}`;

  const res = await fetch(url, {
    headers: {
      Authorization:
        `Bearer ${accessToken}`,
      Accept: 'application/json',
      ...extraHeaders
    }
  });

  if (
    res.status === 401 &&
    !_isRetry
  ) {
    await refreshAccessToken();

    return mlFetch(
      endpoint,
      extraHeaders,
      true
    );
  }

  const raw = await res.text();

  let data = null;

  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch {
      throw new Error(
        `Mercado Libre devolvió una respuesta inválida ` +
        `(status ${res.status}) en ${endpoint}: ` +
        raw.slice(0, 300)
      );
    }
  }

  if (!res.ok) {
    const msg =
      data?.message ||
      data?.error ||
      `Error ${res.status} en ${endpoint}` +
      (raw
        ? `: ${raw.slice(0, 200)}`
        : ' (sin cuerpo de respuesta)');

    throw new Error(msg);
  }

  return data ?? {};
}


/* =========================================================
   FECHAS ARGENTINA
========================================================= */

function nowAR() {
  return new Date(
    Date.now() + AR_OFFSET_MS
  );
}

function startOfDayAR(dayShift = 0) {
  const d = nowAR();

  d.setUTCDate(
    d.getUTCDate() + dayShift
  );

  d.setUTCHours(
    0,
    0,
    0,
    0
  );

  return new Date(
    d.getTime() - AR_OFFSET_MS
  );
}

function startOfMonthAR() {
  const d = nowAR();

  d.setUTCDate(1);

  d.setUTCHours(
    0,
    0,
    0,
    0
  );

  return new Date(
    d.getTime() - AR_OFFSET_MS
  );
}

function getDateRange(period) {
  const now = new Date();

  switch (period) {
    case 'yesterday':
      return {
        from: startOfDayAR(-1),
        to: startOfDayAR(0)
      };

    case 'week':
      return {
        from: startOfDayAR(-6),
        to: now
      };

    case 'month':
      return {
        from: startOfMonthAR(),
        to: now
      };

    case 'today':
    default:
      return {
        from: startOfDayAR(0),
        to: now
      };
  }
}

function ymdAR(dayShift = 0) {
  const d = nowAR();

  d.setUTCDate(
    d.getUTCDate() + dayShift
  );

  return d
    .toISOString()
    .slice(0, 10);
}

function getAdsDateRange(period) {
  switch (period) {
    case 'yesterday':
      return {
        date_from: ymdAR(-1),
        date_to: ymdAR(-1)
      };

    case 'week':
      return {
        date_from: ymdAR(-6),
        date_to: ymdAR(0)
      };

    case 'month': {
      const d = nowAR();

      d.setUTCDate(1);

      return {
        date_from:
          d.toISOString().slice(0, 10),
        date_to: ymdAR(0)
      };
    }

    case 'today':
    default:
      return {
        date_from: ymdAR(0),
        date_to: ymdAR(0)
      };
  }
}

function toMLDate(date) {
  return date
    .toISOString()
    .replace('Z', '-00:00');
}


/* =========================================================
   ÓRDENES
========================================================= */

async function fetchOrdersByRange(
  sellerId,
  from,
  to,
  maxResults = 1000
) {
  const limit = 50;
  let offset = 0;
  const all = [];

  while (true) {
    const url =
      `/orders/search?seller=${sellerId}` +
      `&order.date_created.from=` +
      `${encodeURIComponent(toMLDate(from))}` +
      `&order.date_created.to=` +
      `${encodeURIComponent(toMLDate(to))}` +
      `&sort=date_desc` +
      `&limit=${limit}` +
      `&offset=${offset}`;

    const data = await mlFetch(url);

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

  return all.slice(
    0,
    maxResults
  );
}

const EXCLUDED_STATUSES =
  new Set([
    'cancelled',
    'invalid'
  ]);


/* =========================================================
   COSTOS DE PRODUCTO
========================================================= */

async function getProductCosts() {
  const result =
    await pool.query(
      'SELECT * FROM product_costs'
    );

  return Object.fromEntries(
    result.rows.map(row => [
      row.item_id,
      safeNumber(row.cost_price)
    ])
  );
}


/* =========================================================
   MÉTRICAS OPERACIONALES
========================================================= */

function computeMetrics(
  orders,
  costsMap
) {
  const validOrders =
    orders.filter(
      o =>
        !EXCLUDED_STATUSES.has(
          o.status
        )
    );

  const cancelledCount =
    orders.length -
    validOrders.length;

  let totalRevenue = 0;
  let totalFees = 0;
  let totalShipping = 0;
  let totalProductCost = 0;
  let totalTaxes = 0;

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
        safeNumber(
          order.total_amount
        );

      const fee =
        items.reduce(
          (acc, i) =>
            acc +
            safeNumber(
              i.sale_fee
            ),
          0
        );

      const shipping =
        safeNumber(
          order.shipping?.cost
        );

      const taxes =
        safeNumber(
          order.taxes?.amount
        );

      let productCost = 0;

      for (const i of items) {
        const itemId =
          i.item?.id;

        const unitCost =
          safeNumber(
            costsMap[itemId]
          );

        productCost +=
          unitCost *
          safeNumber(i.quantity);
      }

      const netProfit =
        gross -
        fee -
        shipping -
        taxes -
        productCost;

      totalRevenue += gross;
      totalFees += fee;
      totalShipping += shipping;
      totalTaxes += taxes;
      totalProductCost +=
        productCost;

      return {
        id: order.id,
        date: order.date_created,

        title:
          firstItem.item?.title ||
          'Producto',

        sku:
          firstItem.item?.id ||
          null,

        quantity:
          items.reduce(
            (sum, i) =>
              sum +
              safeNumber(
                i.quantity
              ),
            0
          ),

        status:
          order.status,

        financials: {
          gross,
          fee,
          shipping,
          taxes,
          productCost,
          netProfit,

          margin:
            gross > 0
              ? Number(
                  (
                    (netProfit /
                      gross) *
                    100
                  ).toFixed(1)
                )
              : 0
        }
      };
    })
    .filter(Boolean);

  const netProfitTotal =
    totalRevenue -
    totalFees -
    totalShipping -
    totalTaxes -
    totalProductCost;

  return {
    parsedOrders,

    summary: {
      totalRevenue:
        roundMoney(totalRevenue),

      totalFees:
        roundMoney(totalFees),

      totalShipping:
        roundMoney(totalShipping),

      totalTaxes:
        roundMoney(totalTaxes),

      totalProductCost:
        roundMoney(totalProductCost),

      netProfitTotal:
        roundMoney(netProfitTotal),

      overallMargin:
        totalRevenue > 0
          ? Number(
              (
                (netProfitTotal /
                  totalRevenue) *
                100
              ).toFixed(1)
            )
          : 0,

      totalOrders:
        validOrders.length,

      cancelledOrders:
        cancelledCount
    }
  };
}


/* =========================================================
   BILLING / FACTURACIÓN REAL DE MERCADO LIBRE
========================================================= */

/*
 * La API de Billing trabaja por períodos.
 *
 * La key del período es YYYY-MM-01.
 *
 * Ejemplo:
 * 2026-09-01
 */

function getBillingPeriodKey() {
  const d = nowAR();

  return (
    d.toISOString()
      .slice(0, 7) +
    '-01'
  );
}


/*
 * Obtiene el resumen de facturación.
 *
 * Este endpoint NO se consulta constantemente.
 * Se guarda en billing_cache.
 */

async function fetchBillingSummary(
  periodKey,
  forceRefresh = false
) {
  const cacheKey =
    `billing_summary_${periodKey}`;

  if (!forceRefresh) {
    const cached =
      await pool.query(
        `
        SELECT data, updated_at
        FROM billing_cache
        WHERE cache_key = $1
        `,
        [cacheKey]
      );

    if (
      cached.rows.length
    ) {
      const updated =
        new Date(
          cached.rows[0].updated_at
        );

      const age =
        Date.now() -
        updated.getTime();

      /*
       * 30 minutos de caché.
       * La API de billing no debe
       * consultarse como si fuera
       * una API operacional.
       */
      if (
        age <
        30 * 60 * 1000
      ) {
        return cached.rows[0].data;
      }
    }
  }

  const endpoint =
    `/billing/integration/periods/key/` +
    `${periodKey}/summary/details`;

  const data =
    await mlFetch(endpoint);

  await pool.query(
    `
    INSERT INTO billing_cache
      (cache_key, data, updated_at)
    VALUES
      ($1, $2, NOW())
    ON CONFLICT (cache_key)
    DO UPDATE SET
      data = EXCLUDED.data,
      updated_at = NOW()
    `,
    [
      cacheKey,
      JSON.stringify(data)
    ]
  );

  return data;
}


/*
 * Obtiene todos los detalles ML
 * del período usando from_id.
 *
 * Esto evita el problema de offset
 * cuando existen más de 10.000 registros.
 */

async function fetchBillingMLDetails(
  periodKey,
  forceRefresh = false
) {
  const cacheKey =
    `billing_ml_details_${periodKey}`;

  if (!forceRefresh) {
    const cached =
      await pool.query(
        `
        SELECT data, updated_at
        FROM billing_cache
        WHERE cache_key = $1
        `,
        [cacheKey]
      );

    if (
      cached.rows.length
    ) {
      const updated =
        new Date(
          cached.rows[0].updated_at
        );

      const age =
        Date.now() -
        updated.getTime();

      if (
        age <
        30 * 60 * 1000
      ) {
        return cached.rows[0].data;
      }
    }
  }

  const all = [];

  let fromId = 0;

  while (true) {
    const endpoint =
      `/billing/integration/periods/key/` +
      `${periodKey}/group/ML/details` +
      `?document_type=BILL` +
      `&limit=1000` +
      `&from_id=${fromId}` +
      `&sort_by=ID` +
      `&order_by=ASC`;

    const data =
      await mlFetch(endpoint);

    const results =
      data.results || [];

    all.push(
      ...results
    );

    const lastId =
      data.last_id;

    if (
      !results.length ||
      lastId == null ||
      String(lastId) ===
        String(fromId)
    ) {
      break;
    }

    fromId = lastId;
  }

  await pool.query(
    `
    INSERT INTO billing_cache
      (cache_key, data, updated_at)
    VALUES
      ($1, $2, NOW())
    ON CONFLICT (cache_key)
    DO UPDATE SET
      data = EXCLUDED.data,
      updated_at = NOW()
    `,
    [
      cacheKey,
      JSON.stringify(all)
    ]
  );

  return all;
}


/*
 * Mercado Pago:
 * lo guardamos separado.
 *
 * No se mezcla automáticamente
 * con los costos de venta para
 * evitar doble contabilización.
 */

async function fetchBillingMPDetails(
  periodKey,
  forceRefresh = false
) {
  const cacheKey =
    `billing_mp_details_${periodKey}`;

  if (!forceRefresh) {
    const cached =
      await pool.query(
        `
        SELECT data, updated_at
        FROM billing_cache
        WHERE cache_key = $1
        `,
        [cacheKey]
      );

    if (
      cached.rows.length
    ) {
      const updated =
        new Date(
          cached.rows[0].updated_at
        );

      const age =
        Date.now() -
        updated.getTime();

      if (
        age <
        30 * 60 * 1000
      ) {
        return cached.rows[0].data;
      }
    }
  }

  const all = [];

  let fromId = 0;

  while (true) {
    const endpoint =
      `/billing/integration/periods/key/` +
      `${periodKey}/group/MP/details` +
      `?document_type=BILL` +
      `&limit=1000` +
      `&from_id=${fromId}` +
      `&sort_by=ID` +
      `&order_by=ASC`;

    const data =
      await mlFetch(endpoint);

    const results =
      data.results || [];

    all.push(
      ...results
    );

    const lastId =
      data.last_id;

    if (
      !results.length ||
      lastId == null ||
      String(lastId) ===
        String(fromId)
    ) {
      break;
    }

    fromId = lastId;
  }

  await pool.query(
    `
    INSERT INTO billing_cache
      (cache_key, data, updated_at)
    VALUES
      ($1, $2, NOW())
    ON CONFLICT (cache_key)
    DO UPDATE SET
      data = EXCLUDED.data,
      updated_at = NOW()
    `,
    [
      cacheKey,
      JSON.stringify(all)
    ]
  );

  return all;
}


/* =========================================================
   HELPERS BILLING
========================================================= */

function getBillingChargeInfo(detail) {
  return (
    detail?.charge_info ||
    detail
  );
}

function getBillingAmount(detail) {
  const info =
    getBillingChargeInfo(detail);

  return safeNumber(
    info?.detail_amount
  );
}

function getBillingSubtype(detail) {
  const info =
    getBillingChargeInfo(detail);

  return (
    info?.detail_sub_type ||
    'OTHER'
  );
}

function getBillingType(detail) {
  const info =
    getBillingChargeInfo(detail);

  return (
    info?.detail_type ||
    'CHARGE'
  );
}

function getBillingDescription(detail) {
  const info =
    getBillingChargeInfo(detail);

  return (
    info?.transaction_detail ||
    'Otro cargo'
  );
}


/*
 * Determina la fecha de imputación.
 *
 * Para cargos asociados a una venta
 * usamos sale_date_time.
 *
 * Si no existe:
 * creation_date_time.
 */

function getBillingDate(detail) {
  const sales =
    detail?.sales_info;

  if (
    Array.isArray(sales) &&
    sales.length
  ) {
    if (
      sales[0]?.sale_date_time
    ) {
      return sales[0]
        .sale_date_time
        .slice(0, 10);
    }
  }

  if (
    detail?.shipping_info?.order
      ?.date_created
  ) {
    return detail.shipping_info.order
      .date_created
      .slice(0, 10);
  }

  const info =
    getBillingChargeInfo(detail);

  if (
    info?.creation_date_time
  ) {
    return info.creation_date_time
      .slice(0, 10);
  }

  return null;
}


/*
 * Detecta el order_id relacionado.
 */

function getBillingOrderId(detail) {
  if (
    Array.isArray(
      detail?.sales_info
    ) &&
    detail.sales_info.length
  ) {
    return (
      detail.sales_info[0]?.order_id ||
      null
    );
  }

  return (
    detail?.shipping_info?.order
      ?.order_id ||
    null
  );
}


/* =========================================================
   CLASIFICACIÓN DE COSTOS
========================================================= */

function classifyBillingDetail(
  detail
) {
  const subtype =
    getBillingSubtype(detail);

  const description =
    getBillingDescription(
      detail
    ).toLowerCase();

  /*
   * Product Ads
   */
  if (
    subtype === 'PADS' ||
    description.includes(
      'product ads'
    ) ||
    description.includes(
      'publicidad'
    )
  ) {
    return 'advertising';
  }

  /*
   * Cargo por venta
   */
  if (
    subtype === 'CV' ||
    description.includes(
      'cargo por venta'
    ) ||
    description.includes(
      'cargo por vender'
    ) ||
    description.includes(
      'cobro por vender'
    )
  ) {
    return 'sale_fee';
  }

  /*
   * Mercado Envíos
   */
  if (
    subtype === 'CXD' ||
    subtype === 'CFLX' ||
    subtype === 'CFCB' ||
    description.includes(
      'mercado envíos'
    ) ||
    description.includes(
      'mercado envios'
    ) ||
    description.includes(
      'shipping'
    ) ||
    description.includes(
      'envío'
    )
  ) {
    return 'shipping';
  }

  /*
   * Fulfillment
   */
  if (
    subtype === 'CFCB' ||
    description.includes(
      'fulfillment'
    ) ||
    description.includes(
      'recolección'
    ) ||
    description.includes(
      'almacenamiento'
    )
  ) {
    return 'fulfillment';
  }

  /*
   * Garantías / servicios
   */
  if (
    subtype === 'CEW' ||
    description.includes(
      'garantía'
    ) ||
    description.includes(
      'warranty'
    )
  ) {
    return 'services';
  }

  /*
   * Bonificación
   */
  if (
    getBillingType(detail)
      .toUpperCase() ===
      'BONUS'
  ) {
    return 'bonus';
  }

  /*
   * Todo lo que no
   * conocemos todavía.
   */
  return 'other';
}


/* =========================================================
   ANALIZAR BILLING
========================================================= */

function analyzeBillingDetails(
  details,
  dateFrom,
  dateTo
) {
  const totals = {
    advertising: 0,
    saleFee: 0,
    shipping: 0,
    fulfillment: 0,
    services: 0,
    otherCharges: 0,
    bonuses: 0,
    perceptions: 0,
    totalCharges: 0,
    totalBonuses: 0
  };

  const bySubtype = {};
  const daily = {};

  for (const detail of details) {
    const amount =
      getBillingAmount(detail);

    const type =
      getBillingType(detail)
        .toUpperCase();

    const subtype =
      getBillingSubtype(detail);

    const description =
      getBillingDescription(
        detail
      );

    const date =
      getBillingDate(detail);

    /*
     * Percepciones no siempre aparecen
     * como un detail_type normal.
     */
    if (
      detail?.perception_info
    ) {
      totals.perceptions +=
        safeNumber(
          detail.perception_info
            .taxable_amount
        );
    }

    /*
     * Filtrar fechas para
     * el período solicitado.
     */
    if (
      date &&
      (
        date < dateFrom ||
        date > dateTo
      )
    ) {
      continue;
    }

    if (!bySubtype[subtype]) {
      bySubtype[subtype] = {
        subtype,
        description,
        amount: 0,
        count: 0
      };
    }

    bySubtype[subtype].amount +=
      amount;

    bySubtype[subtype].count++;

    if (!daily[date || 'unknown']) {
      daily[date || 'unknown'] = {
        advertising: 0,
        saleFee: 0,
        shipping: 0,
        fulfillment: 0,
        services: 0,
        otherCharges: 0,
        bonuses: 0,
        totalCharges: 0
      };
    }

    /*
     * Las bonificaciones reducen
     * el costo.
     */
    if (
      type === 'BONUS' ||
      subtype.startsWith('B')
    ) {
      totals.bonuses +=
        amount;

      totals.totalBonuses +=
        amount;

      daily[date || 'unknown']
        .bonuses += amount;

      continue;
    }

    /*
     * Algunos cargos pueden venir
     * marcados como NO debitados.
     * No los contamos como gasto
     * real del vendedor.
     */
    const debited =
      getBillingChargeInfo(detail)
        ?.debited_from_operation;

    if (
      debited === 'NO'
    ) {
      continue;
    }

    totals.totalCharges +=
      amount;

    const category =
      classifyBillingDetail(
        detail
      );

    switch (category) {
      case 'advertising':
        totals.advertising +=
          amount;

        daily[date || 'unknown']
          .advertising += amount;

        break;

      case 'sale_fee':
        totals.saleFee +=
          amount;

        daily[date || 'unknown']
          .saleFee += amount;

        break;

      case 'shipping':
        totals.shipping +=
          amount;

        daily[date || 'unknown']
          .shipping += amount;

        break;

      case 'fulfillment':
        totals.fulfillment +=
          amount;

        daily[date || 'unknown']
          .fulfillment += amount;

        break;

      case 'services':
        totals.services +=
          amount;

        daily[date || 'unknown']
          .services += amount;

        break;

      default:
        totals.otherCharges +=
          amount;

        daily[date || 'unknown']
          .otherCharges += amount;
    }

    daily[date || 'unknown']
      .totalCharges += amount;
  }

  totals.advertising =
    roundMoney(
      totals.advertising
    );

  totals.saleFee =
    roundMoney(
      totals.saleFee
    );

  totals.shipping =
    roundMoney(
      totals.shipping
    );

  totals.fulfillment =
    roundMoney(
      totals.fulfillment
    );

  totals.services =
    roundMoney(
      totals.services
    );

  totals.otherCharges =
    roundMoney(
      totals.otherCharges
    );

  totals.bonuses =
    roundMoney(
      totals.bonuses
    );

  totals.perceptions =
    roundMoney(
      totals.perceptions
    );

  totals.totalCharges =
    roundMoney(
      totals.totalCharges
    );

  totals.totalBonuses =
    roundMoney(
      totals.totalBonuses
    );

  /*
   * Costo neto de billing.
   */
  totals.netBillingCost =
    roundMoney(
      totals.totalCharges -
      totals.totalBonuses
    );

  return {
    totals,

    bySubtype:
      Object.values(
        bySubtype
      )
        .map(x => ({
          ...x,
          amount:
            roundMoney(
              x.amount
            )
        }))
        .sort(
          (a, b) =>
            b.amount -
            a.amount
        ),

    daily
  };
}


/* =========================================================
   BILLING COMPLETO
========================================================= */

async function getBillingReport(
  period = 'today',
  forceRefresh = false
) {
  const {
    date_from,
    date_to
  } = getAdsDateRange(
    period
  );

  const periodKey =
    getBillingPeriodKey();

  const [
    summary,
    details
  ] =
    await Promise.all([
      fetchBillingSummary(
        periodKey,
        forceRefresh
      ),

      fetchBillingMLDetails(
        periodKey,
        forceRefresh
      )
    ]);

  const analyzed =
    analyzeBillingDetails(
      details,
      date_from,
      date_to
    );

  /*
   * El resumen de billing tiene
   * información global del período.
   */
  const summaryCharges =
    summary?.bill_includes
      ?.charges || [];

  const summaryBonuses =
    summary?.bill_includes
      ?.bonuses || [];

  const summaryPerceptions =
    safeNumber(
      summary?.bill_includes
        ?.total_perceptions
    );

  return {
    period,
    date_from,
    date_to,
    periodKey,

    summary: {
      totalAmount:
        safeNumber(
          summary?.bill_includes
            ?.total_amount
        ),

      totalPerceptions:
        summaryPerceptions,

      charges:
        summaryCharges,

      bonuses:
        summaryBonuses,

      paymentCollected:
        summary?.payment_collected ||
        {}
    },

    detail: analyzed
  };
}


/* =========================================================
   PUBLICIDAD MANUAL
========================================================= */

async function getManualAdsSpend(
  period
) {
  const {
    date_from,
    date_to
  } = getAdsDateRange(
    period
  );

  const result =
    await pool.query(
      `
      SELECT
        COALESCE(SUM(amount), 0)
        AS total
      FROM manual_ad_spend
      WHERE spend_date
      BETWEEN $1 AND $2
      `,
      [
        date_from,
        date_to
      ]
    );

  const today =
    await pool.query(
      `
      SELECT amount
      FROM manual_ad_spend
      WHERE spend_date = $1
      `,
      [ymdAR(0)]
    );

  return {
    total:
      safeNumber(
        result.rows[0]?.total
      ),

    today:
      safeNumber(
        today.rows[0]?.amount
      )
  };
}


/* =========================================================
   RENTABILIDAD REAL
========================================================= */

/*
 * ESTA ES LA FUNCIÓN PRINCIPAL
 * QUE VA A USAR EL PANEL.
 */

async function calculateProfitability(
  period = 'today',
  forceRefresh = false
) {
  if (
    !tokenCache?.user_id
  ) {
    throw new Error(
      'Mercado Libre no conectado'
    );
  }

  const {
    from,
    to
  } = getDateRange(period);

  /*
   * 1. Órdenes
   */
  const orders =
    await fetchOrdersByRange(
      tokenCache.user_id,
      from,
      to,
      1000
    );

  /*
   * 2. Costos de mercadería
   */
  const costsMap =
    await getProductCosts();

  /*
   * 3. Métricas operativas
   */
  const operational =
    computeMetrics(
      orders,
      costsMap
    );

  /*
   * 4. Billing real
   */
  let billing = null;

  try {
    billing =
      await getBillingReport(
        period,
        forceRefresh
      );
  } catch (err) {
    console.error(
      'Error obteniendo Billing:',
      err.message
    );
  }

  /*
   * 5. Publicidad manual
   */
  const manualAds =
    await getManualAdsSpend(
      period
    );

  /*
   * -------------------------------------------------------
   * COSTOS
   * -------------------------------------------------------
   */

  const productCost =
    operational.summary
      .totalProductCost;

  let marketplaceFees =
    operational.summary
      .totalFees;

  let shipping =
    operational.summary
      .totalShipping;

  let taxes =
    operational.summary
      .totalTaxes;

  let billingAdvertising = 0;
  let billingOther = 0;
  let billingFulfillment = 0;
  let billingServices = 0;
  let billingBonuses = 0;

  /*
   * Cuando Billing está disponible,
   * usamos sus datos como fuente
   * fiscal/reconciliadora.
   *
   * Para evitar doble conteo:
   *
   * - CV reemplaza sale_fee operativo
   * - CXD/CFLX reemplaza shipping operativo
   *
   * Product Ads se toma de Billing.
   */

  if (billing) {
    const bt =
      billing.detail.totals;

    if (
      bt.saleFee > 0
    ) {
      marketplaceFees =
        bt.saleFee;
    }

    if (
      bt.shipping > 0
    ) {
      shipping =
        bt.shipping;
    }

    billingAdvertising =
      bt.advertising;

    billingFulfillment =
      bt.fulfillment;

    billingServices =
      bt.services;

    billingOther =
      bt.otherCharges;

    billingBonuses =
      bt.bonuses;

    /*
     * Percepciones informadas
     * por billing.
     *
     * Se exponen separadamente
     * porque pueden representar
     * retenciones/percepciones
     * fiscales y no siempre deben
     * tratarse igual que una
     * comisión comercial.
     */
    if (
      bt.perceptions > 0
    ) {
      taxes =
        Math.max(
          taxes,
          bt.perceptions
        );
    }
  }

  /*
   * Si Billing no devolvió PADS,
   * usamos el gasto manual.
   */
  let advertising =
    billingAdvertising;

  let advertisingSource =
    'mercado_libre_billing';

  if (
    advertising <= 0 &&
    manualAds.total > 0
  ) {
    advertising =
      manualAds.total;

    advertisingSource =
      'manual';
  }

  /*
   * Total de costos de plataforma.
   */
  const totalMarketplaceCosts =
    marketplaceFees +
    shipping +
    billingFulfillment +
    billingServices +
    billingOther +
    advertising +
    taxes -
    billingBonuses;

  /*
   * Ganancia real.
   */
  const revenue =
    operational.summary
      .totalRevenue;

  const totalExpenses =
    productCost +
    totalMarketplaceCosts;

  const netProfit =
    revenue -
    totalExpenses;

  const margin =
    revenue > 0
      ? (
          (netProfit /
            revenue) *
          100
        )
      : 0;

  /*
   * Cuánto se llevó ML.
   */
  const totalMercadoLibre =
    marketplaceFees +
    shipping +
    billingFulfillment +
    billingServices +
    billingOther +
    advertising +
    taxes -
    billingBonuses;

  /*
   * Cuánto queda de cada $100.
   */
  const netPer100 =
    revenue > 0
      ? (
          netProfit /
          revenue
        ) * 100
      : 0;

  /*
   * Ticket promedio.
   */
  const averageTicket =
    operational.summary
      .totalOrders > 0
      ? revenue /
        operational.summary
          .totalOrders
      : 0;

  /*
   * Publicidad / ventas.
   */
  const tacos =
    revenue > 0
      ? (
          advertising /
          revenue
        ) * 100
      : 0;

  /*
   * ROAS.
   */
  const roas =
    advertising > 0
      ? revenue /
        advertising
      : 0;

  return {
    ok: true,

    period,

    generatedAt:
      new Date().toISOString(),

    dateFrom:
      from.toISOString(),

    dateTo:
      to.toISOString(),

    summary: {
      revenue:
        roundMoney(revenue),

      sales:
        operational.summary
          .totalOrders,

      cancelled:
        operational.summary
          .cancelledOrders,

      averageTicket:
        roundMoney(
          averageTicket
        ),

      productCost:
        roundMoney(
          productCost
        ),

      marketplaceFees:
        roundMoney(
          marketplaceFees
        ),

      shipping:
        roundMoney(
          shipping
        ),

      fulfillment:
        roundMoney(
          billingFulfillment
        ),

      services:
        roundMoney(
          billingServices
        ),

      advertising:
        roundMoney(
          advertising
        ),

      taxes:
        roundMoney(taxes),

      otherMarketplaceCosts:
        roundMoney(
          billingOther
        ),

      bonuses:
        roundMoney(
          billingBonuses
        ),

      totalMercadoLibre:
        roundMoney(
          totalMercadoLibre
        ),

      totalExpenses:
        roundMoney(
          totalExpenses
        ),

      netProfit:
        roundMoney(
          netProfit
        ),

      margin:
        Number(
          margin.toFixed(2)
        ),

      netPer100:
        Number(
          netPer100.toFixed(2)
        ),

      tacos:
        Number(
          tacos.toFixed(2)
        ),

      roas:
        Number(
          roas.toFixed(2)
        ),

      advertisingSource
    },

    billing: billing
      ? {
          periodKey:
            billing.periodKey,

          dateFrom:
            billing.date_from,

          dateTo:
            billing.date_to,

          summary:
            billing.summary,

          bySubtype:
            billing.detail
              .bySubtype,

          daily:
            billing.detail
              .daily
        }
      : null,

    orders:
      operational.parsedOrders
  };
}


/* =========================================================
   SSE
========================================================= */

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
    const res of sseClients
  ) {
    try {
      res.write(payload);
    } catch {
      sseClients.delete(res);
    }
  }
}

async function pushNotifyAll({
  title,
  body,
  url = '/',
  tag
}) {
  if (!pushEnabled) {
    return;
  }

  let rows;

  try {
    rows =
      (
        await pool.query(
          `
          SELECT endpoint,
                 subscription
          FROM push_subscriptions
          `
        )
      ).rows;
  } catch (err) {
    console.error(
      'Error leyendo push:',
      err.message
    );

    return;
  }

  const payload =
    JSON.stringify({
      title,
      body,
      url,
      tag
    });

  await Promise.all(
    rows.map(
      async row => {
        try {
          await webpush
            .sendNotification(
              row.subscription,
              payload
            );
        } catch (err) {
          if (
            err.statusCode ===
              404 ||
            err.statusCode ===
              410
          ) {
            await pool.query(
              `
              DELETE FROM
              push_subscriptions
              WHERE endpoint = $1
              `,
              [row.endpoint]
            );
          } else {
            console.error(
              'Error push:',
              err.message
            );
          }
        }
      }
    )
  );
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
        () =>
          res.write(
            ':hb\n\n'
          ),
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


/* =========================================================
   AUTH LOGIN
========================================================= */

app.get(
  '/auth/login',
  (req, res) => {
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
  }
);

app.get(
  '/auth/callback',
  async (req, res) => {
    try {
      if (
        oauthState &&
        req.query.state &&
        req.query.state !==
          oauthState
      ) {
        throw new Error(
          'OAuth state inválido.'
        );
      }

      if (!req.query.code) {
        throw new Error(
          'Mercado Libre no devolvió el code.'
        );
      }

      const data =
        await tokenRequest({
          grant_type:
            'authorization_code',

          client_id:
            CLIENT_ID,

          client_secret:
            CLIENT_SECRET,

          code:
            req.query.code,

          redirect_uri:
            REDIRECT_URI,

          code_verifier:
            pkceVerifier
        });

      await saveTokens({
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

      oauthState = null;
      pkceVerifier = null;

      res.redirect(
        '/?connected=1'
      );
    } catch (e) {
      res
        .status(500)
        .send(
          `Error de conexión: ${e.message}`
        );
    }
  }
);


/* =========================================================
   STATUS
========================================================= */

app.get(
  '/api/status',
  async (req, res) => {
    res.json({
      ok: true,

      connected:
        !!tokenCache
          ?.access_token,

      user_id:
        tokenCache
          ?.user_id ||
        null
    });
  }
);


/* =========================================================
   NUEVA API:
   RENTABILIDAD
========================================================= */

app.get(
  '/api/profitability',
  async (req, res) => {
    try {
      const allowed = [
        'today',
        'yesterday',
        'week',
        'month'
      ];

      const period =
        allowed.includes(
          req.query.period
        )
          ? req.query.period
          : 'today';

      const forceRefresh =
        req.query.refresh ===
        '1';

      const report =
        await calculateProfitability(
          period,
          forceRefresh
        );

      res.json(report);
    } catch (e) {
      console.error(
        'Error profitability:',
        e
      );

      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);


/* =========================================================
   MÉTRICAS OPERACIONALES
========================================================= */

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

      const allowed = [
        'today',
        'yesterday',
        'week',
        'month'
      ];

      const period =
        allowed.includes(
          req.query.period
        )
          ? req.query.period
          : 'today';

      const {
        from,
        to
      } =
        getDateRange(
          period
        );

      const orders =
        await fetchOrdersByRange(
          tokenCache.user_id,
          from,
          to
        );

      const costsMap =
        await getProductCosts();

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
    } catch (e) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);


/* =========================================================
   API BILLING
========================================================= */

app.get(
  '/api/billing',
  async (req, res) => {
    try {
      if (
        !tokenCache?.user_id
      ) {
        throw new Error(
          'Mercado Libre no conectado'
        );
      }

      const allowed = [
        'today',
        'yesterday',
        'week',
        'month'
      ];

      const period =
        allowed.includes(
          req.query.period
        )
          ? req.query.period
          : 'today';

      const forceRefresh =
        req.query.refresh ===
        '1';

      const report =
        await getBillingReport(
          period,
          forceRefresh
        );

      res.json({
        ok: true,
        ...report
      });
    } catch (e) {
      console.error(
        'Error billing:',
        e
      );

      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);


/* =========================================================
   ADS MANUAL
========================================================= */

app.post(
  '/api/ads-manual',
  async (req, res) => {
    try {
      const {
        date,
        amount
      } = req.body;

      if (
        !/^\d{4}-\d{2}-\d{2}$/
          .test(date || '')
      ) {
        throw new Error(
          'Fecha inválida.'
        );
      }

      const value =
        parseFloat(amount);

      if (
        isNaN(value) ||
        value < 0
      ) {
        throw new Error(
          'Monto inválido.'
        );
      }

      await pool.query(
        `
        INSERT INTO
        manual_ad_spend
          (
            spend_date,
            amount,
            updated_at
          )
        VALUES
          ($1, $2, NOW())
        ON CONFLICT
          (spend_date)
        DO UPDATE SET
          amount =
            EXCLUDED.amount,
          updated_at =
            NOW()
        `,
        [
          date,
          value
        ]
      );

      res.json({
        ok: true
      });
    } catch (e) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);

app.get(
  '/api/ads-manual',
  async (req, res) => {
    try {
      const allowed = [
        'today',
        'yesterday',
        'week',
        'month'
      ];

      const period =
        allowed.includes(
          req.query.period
        )
          ? req.query.period
          : 'today';

      const result =
        await getManualAdsSpend(
          period
        );

      const {
        date_from,
        date_to
      } =
        getAdsDateRange(
          period
        );

      res.json({
        ok: true,
        period,
        date_from,
        date_to,
        total:
          result.total,
        today:
          result.today
      });
    } catch (e) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);


/* =========================================================
   STOCK
========================================================= */

async function getStockAlerts() {
  if (
    !tokenCache?.user_id
  ) {
    throw new Error(
      'Mercado Libre no conectado'
    );
  }

  const to =
    new Date();

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
      o =>
        !EXCLUDED_STATUSES.has(
          o.status
        )
    )
    .forEach(o => {
      (
        o.order_items ||
        []
      ).forEach(i => {
        const id =
          i.item.id;

        unitsBySku[id] =
          (
            unitsBySku[id] ||
            0
          ) +
          safeNumber(
            i.quantity
          );
      });
    });

  const skuIds =
    Object.keys(
      unitsBySku
    );

  if (
    skuIds.length === 0
  ) {
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
    ).forEach(
      entry => {
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
              entry.body
                .available_quantity ??
              0
          };
        }
      }
    );
  }

  const alerts =
    skuIds.map(
      id => {
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

          title:
            info.title,

          stock:
            info.stock,

          unitsSold30d:
            unitsBySku[id],

          avgDailySales:
            Number(
              avgDaily.toFixed(2)
            ),

          daysRemaining:
            daysRemaining !==
            null
              ? Number(
                  daysRemaining
                    .toFixed(1)
                )
              : null
        };
      }
    );

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
    } catch (e) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);


/* =========================================================
   PUSH
========================================================= */

app.get(
  '/api/push/public-key',
  (req, res) => {
    if (!pushEnabled) {
      return res
        .status(503)
        .json({
          ok: false,
          error:
            'Push no configurado.'
        });
    }

    res.json({
      ok: true,
      publicKey:
        VAPID_PUBLIC_KEY
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
          'Suscripción inválida'
        );
      }

      await pool.query(
        `
        INSERT INTO
        push_subscriptions
          (
            endpoint,
            subscription
          )
        VALUES
          ($1, $2)
        ON CONFLICT
          (endpoint)
        DO UPDATE SET
          subscription =
            EXCLUDED.subscription
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
    } catch (e) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);

app.post(
  '/api/push/unsubscribe',
  async (req, res) => {
    try {
      const {
        endpoint
      } = req.body;

      if (endpoint) {
        await pool.query(
          `
          DELETE FROM
          push_subscriptions
          WHERE endpoint = $1
          `,
          [endpoint]
        );
      }

      res.json({
        ok: true
      });
    } catch (e) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);


/* =========================================================
   NOTIFICACIONES
========================================================= */

app.get(
  '/api/notifications',
  async (req, res) => {
    try {
      const r =
        await pool.query(
          `
          SELECT *
          FROM notifications
          ORDER BY
            created_at DESC
          LIMIT 20
          `
        );

      res.json({
        ok: true,
        notifications:
          r.rows
      });
    } catch (e) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);


/* =========================================================
   COSTOS PRODUCTO
========================================================= */

app.post(
  '/api/costs',
  async (req, res) => {
    try {
      const {
        itemId,
        costPrice
      } = req.body;

      const value =
        parseFloat(
          costPrice
        );

      if (
        !itemId ||
        !Number.isFinite(
          value
        ) ||
        value < 0
      ) {
        throw new Error(
          'itemId o costo inválido.'
        );
      }

      await pool.query(
        `
        INSERT INTO
        product_costs
          (
            item_id,
            cost_price,
            updated_at
          )
        VALUES
          ($1, $2, NOW())
        ON CONFLICT
          (item_id)
        DO UPDATE SET
          cost_price =
            EXCLUDED.cost_price,
          updated_at =
            NOW()
        `,
        [
          itemId,
          value
        ]
      );

      res.json({
        ok: true
      });
    } catch (e) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);


/* =========================================================
   WEBHOOK MERCADO LIBRE
========================================================= */

app.post(
  '/api/webhooks/meli',
  async (req, res) => {
    res
      .status(200)
      .send('OK');

    try {
      const {
        topic,
        resource
      } = req.body;

      if (
        topic ===
          'orders_v2' &&
        resource
      ) {
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
          safeNumber(
            orderData.total_amount
          );

        await pool.query(
          `
          INSERT INTO
          notifications
            (
              order_id,
              title,
              amount
            )
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
              orderData
                .date_created
          }
        );

        pushNotifyAll({
          title:
            `¡Vendiste! ${title}`,

          body:
            new Intl
              .NumberFormat(
                'es-AR',
                {
                  style:
                    'currency',

                  currency:
                    'ARS',

                  maximumFractionDigits:
                    0
                }
              )
              .format(amount),

          tag:
            `order-${orderData.id}`
        });

        console.log(
          'Nueva orden recibida vía webhook:',
          orderData.id
        );
      }
    } catch (err) {
      console.error(
        'Error procesando webhook:',
        err.message
      );
    }
  }
);


/* =========================================================
   DEBUG BILLING
========================================================= */

/*
 * Esta ruta sirve para comprobar
 * qué está devolviendo exactamente
 * Mercado Libre.
 *
 * Abrir:
 *
 * /api/debug/billing?refresh=1
 *
 * NO hace falta llamarla desde
 * el frontend.
 */

app.get(
  '/api/debug/billing',
  async (req, res) => {
    try {
      const periodKey =
        getBillingPeriodKey();

      const force =
        req.query.refresh ===
        '1';

      const summary =
        await fetchBillingSummary(
          periodKey,
          force
        );

      const details =
        await fetchBillingMLDetails(
          periodKey,
          force
        );

      res.json({
        ok: true,

        periodKey,

        summary,

        detailsCount:
          details.length,

        firstDetails:
          details.slice(
            0,
            20
          )
      });
    } catch (e) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  }
);


/* =========================================================
   INICIAR SERVIDOR
========================================================= */

app.listen(
  PORT,
  async () => {
    await initDB();

    console.log(
      `Servidor activo en puerto ${PORT}`
    );

    console.log(
      `BASE_URL: ${BASE_URL}`
    );

    console.log(
      `REDIRECT_URI: ${REDIRECT_URI}`
    );
  }
);
