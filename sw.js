// Patrol Tracker — offline app shell service worker
// Bump this version any time index.html changes, so returning devices pick up the new copy.
var CACHE_NAME = 'patrol-tracker-shell-v1';
var SHELL_FILES = [
  './',
  './index.html',
  './site.webmanifest'
];

self.addEventListener('install', function(evt){
  self.skipWaiting();
  evt.waitUntil(
    caches.open(CACHE_NAME).then(function(cache){
      return cache.addAll(SHELL_FILES);
    })
  );
});

self.addEventListener('activate', function(evt){
  evt.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(keys.filter(function(k){ return k!==CACHE_NAME; }).map(function(k){ return caches.delete(k); }));
    }).then(function(){ return self.clients.claim(); })
  );
});

// Cache-first for the app shell itself (so it opens instantly offline),
// but always try the network first for anything under /api/ or similar
// data endpoints so live data is never served stale from this cache —
// the app's own outbox/localStorage logic already handles that layer.
self.addEventListener('fetch', function(evt){
  var req = evt.request;
  if(req.method !== 'GET') return;

  var url = new URL(req.url);
  var isShellRequest = url.origin === self.location.origin &&
    (url.pathname.endsWith('/') || url.pathname.endsWith('index.html') || url.pathname.endsWith('site.webmanifest'));

  if(!isShellRequest){
    // Let data/API requests pass straight through to the network as normal.
    return;
  }

  evt.respondWith(
    caches.match(req).then(function(cached){
      var network = fetch(req).then(function(res){
        if(res && res.ok){
          var copy = res.clone();
          caches.open(CACHE_NAME).then(function(cache){ cache.put(req, copy); });
        }
        return res;
      }).catch(function(){ return cached; });
      // Serve cached shell immediately if we have it, refresh in the background.
      return cached || network;
    })
  );
});
