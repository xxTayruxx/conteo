self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// Llega un push del servidor (ej: nueva venta) mientras la app está cerrada
self.addEventListener('push', (event) => {
  let payload = { title: 'Conteonix', body: 'Tenés una novedad.' };
  try {
    if (event.data) payload = event.data.json();
  } catch (e) {
    if (event.data) payload.body = event.data.text();
  }

  const options = {
    body: payload.body,
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-192.png',
    tag: payload.tag || 'conteonix-order',
    renotify: true,
    data: { url: payload.url || '/' }
  };

  event.waitUntil(
    Promise.all([
      self.registration.showNotification(payload.title, options),
      self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientsList) => {
        clientsList.forEach((client) => client.postMessage({ type: 'PLAY_SOUND', tag: payload.tag }));
      })
    ])
  );
});

// Al tocar la notificación, abre (o enfoca) el panel
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if (client.url.includes(self.location.origin) && 'focus' in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(targetUrl);
    })
  );
});
