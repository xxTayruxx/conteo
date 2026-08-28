# Conteonix — Mercado Libre OAuth

Backend Node.js + Express preparado para Render y Mercado Libre Argentina.

## Qué incluye

- OAuth 2.0 Server Side de Mercado Libre.
- `state` para proteger el callback.
- PKCE S256 (si la aplicación lo tiene habilitado, el flujo ya está preparado).
- Intercambio `authorization_code` → `access_token` + `refresh_token`.
- Renovación automática del access token.
- `/api/status` para verificar la conexión.
- `/api/orders` para consultar ventas.
- `/api/sync` para obtener ventas y dejar el punto de integración listo para Cuaderno.
- `SYNC_API_KEY` opcional/para proteger endpoints de sincronización.
- Interfaz mínima para probar la conexión.

## Variables de Render

`ML_CLIENT_ID=686055239506289`

`ML_CLIENT_SECRET=TU_SECRET`

`ML_REDIRECT_URI=https://conteonix.onrender.com/auth/callback`

`ML_AUTH_DOMAIN=https://auth.mercadolibre.com.ar`

`ML_API_BASE=https://api.mercadolibre.com`

`BASE_URL=https://conteonix.onrender.com`

`SYNC_API_KEY=UNA_CLAVE_LARGA_Y_SEGURA`

## Importante sobre tokens en Render

El proyecto guarda las credenciales en `data/tokens.json`. En un entorno con filesystem efímero, un redeploy/restart puede borrar ese archivo. Para una conexión persistente conviene agregar un Persistent Disk en Render y definir `TOKEN_FILE=/var/data/tokens.json`, o migrar el almacenamiento a una base de datos/servicio persistente antes de usarlo en producción.

## Prueba local

```bash
npm install
npm start
```

Abrir `http://localhost:3000`.

## Flujo

1. Configurar la Redirect URI exacta en Mercado Libre.
2. Cargar el Client Secret solo en Render.
3. Abrir `/auth/login`.
4. Autorizar con la cuenta principal de vendedor.
5. El callback guarda el access token y el refresh token.
6. `/api/status` valida el usuario con `/users/me`.
7. `/api/orders` y `/api/sync` consultan `/orders/search`.
