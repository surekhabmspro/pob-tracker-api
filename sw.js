// Patrol Tracker — offline app shell service worker
var CACHE_NAME = 'patrol-tracker-shell-v2';
var SHELL_FILES = [
  './',
  './index.html',
  './site.webmanifest'
];

self.addEventListener('install', function(evt){
  self.skipWaiting();
  evt.waitUntil(
    caches.open(CACHE_NAME).then(function(cache){
      var reqs = SHELL_FILES.map(function(u){ return new Request(u, {cache:'reload'}); });
      return Promise.all(reqs.map(function(r){
        return fetch(r).then(function(res){ if(res && res.ok) return cache.put(r.url, res); }).catch(function(){});
      }));
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

self.addEventListener('fetch', function(evt){
  var req = evt.request;
  if(req.method !== 'GET') return;

  var url = new URL(req.url);
  var isShellRequest = url.origin === self.location.origin &&
    (url.pathname.endsWith('/') || url.pathname.endsWith('index.html') || url.pathname.endsWith('site.webmanifest'));

  if(!isShellRequest){
    return;
  }

  evt.respondWith(
    fetch(req, {cache:'no-store'}).then(function(res){
      if(res && res.ok){
        var copy = res.clone();
        caches.open(CACHE_NAME).then(function(cache){ cache.put(req, copy); });
      }
      return res;
    }).catch(function(){
      return caches.match(req);
    })
  );
});
