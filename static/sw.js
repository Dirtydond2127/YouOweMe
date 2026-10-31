const CACHE='oweyeah-static-v2';
const ASSETS=['/static/style.css','/static/app.js','/static/icon-192.png','/static/icon-512.png','/static/offline.html'];
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(ASSETS)))});
self.addEventListener('activate',event=>{event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))))});
self.addEventListener('fetch',event=>{const url=new URL(event.request.url);if(url.origin!==self.location.origin||event.request.method!=='GET')return;
// Never cache authenticated HTML, OAuth responses, or API data.
if(event.request.mode==='navigate'){event.respondWith(fetch(event.request).catch(()=>caches.match('/static/offline.html')));return;}
if(ASSETS.includes(url.pathname)){event.respondWith(fetch(event.request).catch(()=>caches.match(event.request)));}});
