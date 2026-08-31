const express = require('express');
const app = express();

app.use(express.json());

// ---------- Utilitarios y Helpers ----------

// Retorna la fecha/hora actual ajustada a zona horaria de Argentina (UTC-3)
function nowAR() {
  const d = new Date();
  const utc = d.getTime() + (d.getTimezoneOffset() * 60000);
  return new Date(utc - (3 * 60 * 60 * 1000));
}

// Función auxiliar para llamadas a la API de Mercado Libre / Mercado Ads (Corregida)
async function mlFetch(endpoint, customHeaders = {}) {
  const accessToken = process.env.MELI_ACCESS_TOKEN;
  if (!accessToken) {
    throw new Error('MELI_ACCESS_TOKEN no está configurado en las variables de entorno.');
  }

  const url = endpoint.startsWith('http') 
    ? endpoint 
    : `https://api.mercadolibre.com${endpoint}`;

  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      ...customHeaders
    }
  });

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(`ML API Error (${response.status}): ${responseText}`);
  }

  // Manejo seguro por si la respuesta viene vacía
  if (!responseText) {
    return {};
  }

  try {
    return JSON.parse(responseText);
  } catch (err) {
    throw new Error(`Error al parsear JSON de ML API: ${err.message}. Respuesta original: ${responseText}`);
  }
}


// ---------- Product Ads (Mercado Ads) ----------

const ADS_METRICS = [
  'clicks', 'prints', 'ctr', 'cost', 'cpc', 'acos', 'cvr', 'roas', 'sov',
  'organic_units_quantity', 'organic_units_amount',
  'direct_items_quantity', 'indirect_items_quantity', 'advertising_items_quantity',
  'direct_units_quantity', 'indirect_units_quantity', 'units_quantity',
  'direct_amount', 'indirect_amount', 'total_amount'
].join(',');

let advertiserCache = null;

async function getAdvertiser() {
  if (advertiserCache?.advertiser_id) return advertiserCache;
  
  // Se especifica Api-Version: 1 para obtener el advertiser correcto
  const data = await mlFetch('/advertising/advertisers?product_id=PADS', { 'Api-Version': '1' });
  const list = data.advertisers || data.results || (Array.isArray(data) ? data : []);
  
  if (!list.length) {
    throw new Error('No se encontró ningún advertiser de Product Ads activo.');
  }
  
  advertiserCache = list.find(a => a.site_id === 'MLA') || list[0];
  return advertiserCache;
}

function ymdAR(dayShift = 0) {
  const d = nowAR();
  d.setUTCDate(d.getUTCDate() + dayShift);
  return d.toISOString().slice(0, 10);
}

function getAdsDateRange(period) {
  switch (period) {
    case 'yesterday':
      return { date_from: ymdAR(-1), date_to: ymdAR(-1) };
    case 'week':
      return { date_from: ymdAR(-6), date_to: ymdAR(0) };
    case 'month': {
      const d = nowAR();
      d.setUTCDate(1);
      return { date_from: d.toISOString().slice(0, 10), date_to: ymdAR(0) };
    }
    case 'today':
    default:
      return { date_from: ymdAR(0), date_to: ymdAR(0) };
  }
}

function emptyAdsMetrics() {
  return {
    clicks: 0, prints: 0, cost: 0, total_amount: 0,
    direct_amount: 0, indirect_amount: 0,
    units_quantity: 0, direct_units_quantity: 0, indirect_units_quantity: 0
  };
}

// Llama a las campañas probando v2 y reintentando con v1 si devuelve 404
async function fetchCampaignsWithMetrics(advertiserId, date_from, date_to) {
  const url = `/advertising/advertisers/${advertiserId}/product_ads/campaigns` +
    `?date_from=${date_from}&date_to=${date_to}&metrics=${ADS_METRICS}&limit=50&offset=0`;
  try {
    const data = await mlFetch(url, { 'Api-Version': '2' });
    return data.results || [];
  } catch (err) {
    if (err.message && err.message.includes('404')) {
      const dataV1 = await mlFetch(url, { 'Api-Version': '1' });
      return dataV1.results || dataV1.campaigns || [];
    }
    throw err;
  }
}

// Llama a los anuncios/items probando v2 y reintentando con v1 si devuelve 404
async function fetchItemsWithMetrics(advertiserId, date_from, date_to) {
  const url = `/advertising/advertisers/${advertiserId}/product_ads/items` +
    `?date_from=${date_from}&date_to=${date_to}&metrics=${ADS_METRICS}` +
    `&metrics_summary=true&sort_by=cost&sort=desc&limit=50&offset=0`;
  try {
    const data = await mlFetch(url, { 'Api-Version': '2' });
    return data.results || [];
  } catch (err) {
    if (err.message && err.message.includes('404')) {
      const dataV1 = await mlFetch(url, { 'Api-Version': '1' });
      return dataV1.results || dataV1.items || [];
    }
    throw err;
  }
}

async function getProductAdsReport(period) {
  let advertiser;
  try {
    advertiser = await getAdvertiser();
  } catch (err) {
    return {
      period,
      date_from: ymdAR(0),
      date_to: ymdAR(0),
      advertiser: {},
      summary: emptyAdsMetrics(),
      campaigns: [],
      items: [],
      warning: err.message || 'No se encontraron campañas de Product Ads configuradas o activas.'
    };
  }

  const { date_from, date_to } = getAdsDateRange(period);

  let campaigns = [];
  let items = [];

  try {
    [campaigns, items] = await Promise.all([
      fetchCampaignsWithMetrics(advertiser.advertiser_id, date_from, date_to),
      fetchItemsWithMetrics(advertiser.advertiser_id, date_from, date_to)
    ]);
  } catch (err) {
    console.error('Error al consultar métricas de publicidad:', err.message);
  }

  const totals = campaigns.reduce((acc, c) => {
    const m = c.metrics || {};
    acc.clicks += m.clicks || 0;
    acc.prints += m.prints || 0;
    acc.cost += m.cost || 0;
    acc.total_amount += m.total_amount || 0;
    acc.direct_amount += m.direct_amount || 0;
    acc.indirect_amount += m.indirect_amount || 0;
    acc.units_quantity += m.units_quantity || 0;
    acc.direct_units_quantity += m.direct_units_quantity || 0;
    acc.indirect_units_quantity += m.indirect_units_quantity || 0;
    return acc;
  }, emptyAdsMetrics());

  const summary = {
    ...totals,
    ctr: totals.prints > 0 ? parseFloat(((totals.clicks / totals.prints) * 100).toFixed(2)) : 0,
    cpc: totals.clicks > 0 ? parseFloat((totals.cost / totals.clicks).toFixed(2)) : 0,
    roas: totals.cost > 0 ? parseFloat((totals.total_amount / totals.cost).toFixed(2)) : 0,
    acos: totals.total_amount > 0 ? parseFloat(((totals.cost / totals.total_amount) * 100).toFixed(2)) : 0
  };

  const campaignsOut = campaigns.map(c => ({
    id: c.id,
    name: c.name,
    status: c.status,
    budget: c.budget,
    currency: c.currency_id,
    strategy: c.strategy,
    acosTarget: c.acos_target,
    metrics: c.metrics || {}
  }));

  const itemsOut = items.map(it => {
    const m = it.metrics_summary || it.metrics || {};
    return {
      itemId: it.item_id,
      title: it.title,
      price: it.price,
      status: it.status,
      campaignId: it.campaign_id,
      buyBoxWinner: it.buy_box_winner,
      metrics: {
        clicks: m.clicks || 0,
        prints: m.prints || 0,
        ctr: m.ctr ?? (m.prints > 0 ? parseFloat(((m.clicks / m.prints) * 100).toFixed(2)) : 0),
        cost: m.cost || 0,
        cpc: m.cpc || 0,
        acos: m.acos || 0,
        cvr: m.cvr || 0,
        roas: m.roas ?? (m.cost > 0 ? parseFloat(((m.total_amount || 0) / m.cost).toFixed(2)) : 0),
        unitsQuantity: m.units_quantity || 0,
        directUnitsQuantity: m.direct_units_quantity || 0,
        indirectUnitsQuantity: m.indirect_units_quantity || 0,
        totalAmount: m.total_amount || 0,
        directAmount: m.direct_amount || 0,
        indirectAmount: m.indirect_amount || 0
      }
    };
  });

  return {
    period,
    date_from,
    date_to,
    advertiser: {
      id: advertiser.advertiser_id,
      siteId: advertiser.site_id,
      name: advertiser.advertiser_name,
      account: advertiser.account_name
    },
    summary,
    campaigns: campaignsOut,
    items: itemsOut
  };
}


// ---------- Rutas / Endpoints API ----------

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date() });
});

app.get('/api/ads/report', async (req, res) => {
  try {
    const period = req.query.period || 'today';
    const report = await getProductAdsReport(period);
    res.json(report);
  } catch (error) {
    console.error('Error procesando reporte de Ads:', error);
    res.status(500).json({ error: error.message });
  }
});


// ---------- Inicio del Servidor ----------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor iniciado correctamente y escuchando en el puerto ${PORT}`);
});
