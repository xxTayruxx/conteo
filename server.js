require('dotenv').config();

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;

const BASE_URL =
  process.env.BASE_URL || 'https://conteo-rt2c.onrender.com';

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

const SYNC_API_KEY = process.env.SYNC_API_KEY;

const TOKEN_FILE =
  process.env.TOKEN_FILE ||
  path.join(__dirname, 'data', 'tokens.json');

if (!fs.existsSync(path.dirname(TOKEN_FILE))) {
  fs.mkdirSync(path.dirname(TOKEN_FILE), {
    recursive: true
  });
}

let oauthState = null;
let pkceVerifier = null;
let tokenCache = loadTokens();

function loadTokens() {
  try {
    return JSON.parse(
      fs.readFileSync(TOKEN_FILE, 'utf8')
    );
  } catch {
    return null;
  }
}

function saveTokens(tokens) {
  const tmp = `${TOKEN_FILE}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(tokens, null, 2),
    { mode: 0o600 }
  );

  fs.renameSync(tmp, TOKEN_FILE);

  tokenCache = tokens;
}

function requireConfig() {
  const missing = [];

  if (!CLIENT_ID) missing.push('ML_CLIENT_ID');
  if (!CLIENT_SECRET) missing.push('ML_CLIENT_SECRET');
  if (!REDIRECT_URI) missing.push('ML_REDIRECT_URI');

  if (missing.length) {
    throw new Error(
      `Faltan variables: ${missing.join(', ')}`
    );
  }
}

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
    const err = new Error(
      data.error_description ||
      data.error ||
      `HTTP ${response.status}`
    );

    err.status = response.status;
    err.details = data;

    throw err;
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

  saveTokens({
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

  saveTokens({
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

async function mlFetch(
  endpoint,
  options = {},
  retry = true
) {
  const accessToken = await getAccessToken();

  const headers = {
    ...(options.headers || {}),
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/json'
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
    data = { raw: text };
  }

  if (!response.ok) {
    const err = new Error(
      data.message ||
      data.error ||
      `Mercado Libre HTTP ${response.status}`
    );

    err.status = response.status;
    err.details = data;

    throw err;
  }

  return data;
}

/*
  API KEY

  La mantenemos para accesos externos.
*/
function apiKey(req, res, next) {
  if (!SYNC_API_KEY) {
    return next();
  }

  const supplied =
    req.get('x-api-key') ||
    req.query.api_key;

  if (supplied !== SYNC_API_KEY) {
    return res.status(401).json({
      ok: false,
      error: 'API key inválida o ausente'
    });
  }

  next();
}

/*
  FRONTEND INTERNO

  Los botones de Conteonix pueden usar
  estas rutas sin exponer la API key.
*/
function internalApi(req, res, next) {
  next();
}

app.get('/', (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      'public',
      'index.html'
    )
  );
});

app.get('/auth/login', (req, res) => {
  try {
    requireConfig();

    oauthState = randomState();

    const pkce = makePkce();

    pkceVerifier = pkce.verifier;

    const url = new URL(
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

    res.redirect(url.toString());

  } catch (e) {
    res.status(500).send(`
      <h1>Error de configuración</h1>
      <pre>${escapeHtml(e.message)}</pre>
    `);
  }
});

app.get('/auth/callback', async (req, res) => {
  try {
    requireConfig();

    if (req.query.error) {
      return res.status(400).send(`
        <h1>Mercado Libre rechazó la autorización</h1>
        <pre>
          ${escapeHtml(
            req.query.error_description ||
            req.query.error
          )}
        </pre>
      `);
    }

    if (
      !req.query.state ||
      req.query.state !== oauthState
    ) {
      return res.status(400).send(`
        <h1>Error de seguridad</h1>
        <p>
          El state no coincide.
          Volvé a iniciar la conexión.
        </p>
      `);
    }

    if (!req.query.code) {
      return res.status(400).send(`
        <h1>Falta el code</h1>
      `);
    }

    await exchangeCode(req.query.code);

    oauthState = null;
    pkceVerifier = null;

    res.redirect('/?connected=1');

  } catch (e) {
    console.error(
      'OAuth callback:',
      e.details || e
    );

    res.status(e.status || 500).send(`
      <h1>No se pudo conectar Mercado Libre</h1>

      <pre>
        ${escapeHtml(e.message)}
      </pre>

      <p>
        Revisá ML_CLIENT_ID,
        ML_CLIENT_SECRET y
        ML_REDIRECT_URI.
      </p>
    `);
  }
});

app.get('/api/status', async (req, res) => {
  const connected =
    !!tokenCache?.access_token;

  const result = {
    ok: true,
    connected,
    redirect_uri: REDIRECT_URI,
    user_id:
      tokenCache?.user_id || null,
    expires_at:
      tokenCache?.expires_at || null
  };

  if (connected) {
    try {
      const me =
        await mlFetch('/users/me');

      result.user = {
        id: me.id,
        nickname: me.nickname,
        country_id: me.country_id
      };

    } catch (e) {
      result.api_error = e.message;
    }
  }

  res.json(result);
});

app.get(
  '/api/orders',
  internalApi,
  async (req, res) => {
    try {
      const limit = Math.min(
        Math.max(
          Number(req.query.limit) || 50,
          1
        ),
        50
      );

      const offset = Math.max(
        Number(req.query.offset) || 0,
        0
      );

      if (!tokenCache?.user_id) {
        throw new Error(
          'Primero conectá Mercado Libre.'
        );
      }

      const params =
        new URLSearchParams({
          seller: String(
            tokenCache.user_id
          ),
          limit: String(limit),
          offset: String(offset),
          sort: 'date_desc'
        });

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

    } catch (e) {
      console.error(
        'Error /api/orders:',
        e.details || e
      );

      res.status(e.status || 500).json({
        ok: false,
        error: e.message,
        details: e.details || null
      });
    }
  }
);

app.post(
  '/api/sync',
  internalApi,
  async (req, res) => {
    try {
      const limit = Math.min(
        Math.max(
          Number(
            req.body?.limit ||
            req.query.limit
          ) || 50,
          1
        ),
        50
      );

      if (!tokenCache?.user_id) {
        throw new Error(
          'Primero conectá Mercado Libre.'
        );
      }

      const params =
        new URLSearchParams({
          seller: String(
            tokenCache.user_id
          ),
          limit: String(limit),
          offset: '0',
          sort: 'date_desc'
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

    } catch (e) {
      console.error(
        'Error /api/sync:',
        e.details || e
      );

      res.status(e.status || 500).json({
        ok: false,
        error: e.message,
        details: e.details || null
      });
    }
  }
);

app.post(
  '/api/logout',
  internalApi,
  (req, res) => {
    tokenCache = null;

    try {
      if (fs.existsSync(TOKEN_FILE)) {
        fs.unlinkSync(TOKEN_FILE);
      }
    } catch {}

    res.json({
      ok: true,
      message:
        'Credenciales locales eliminadas.'
    });
  }
);

function escapeHtml(s) {
  return String(s).replace(
    /[&<>'"]/g,
    c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[c])
  );
}

app.listen(PORT, () => {
  console.log(
    `Conteonix escuchando en puerto ${PORT}`
  );
});
