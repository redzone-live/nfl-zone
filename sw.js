// Service worker minimal : l'appli s'ouvre même avec un réseau lent. Les données ESPN ne sont JAMAIS mises en cache ici.
const V='nflzone-v5',SHELL=['./','index.html','manifest.webmanifest','icon-180.png','icon-192.png','icon-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==V).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{const r=e.request,u=new URL(r.url);
 if(r.method!=='GET'||u.origin!==location.origin)return; // ESPN et images externes : réseau direct
 e.respondWith(fetch(r).then(res=>{const c=res.clone();caches.open(V).then(x=>x.put(r,c));return res}).catch(()=>caches.match(r).then(m=>m||caches.match('index.html'))))});

// --- Notifications push (reçues même appli fermée) ---
self.addEventListener('push',e=>{let d={};try{d=e.data?e.data.json():{}}catch(x){d={title:'Blitz Zone',body:e.data?e.data.text():''}}
 const o={body:d.body||'',icon:'icon-192.png',badge:'icon-192.png'};if(d.tag){o.tag=d.tag;o.renotify=true}
 e.waitUntil(self.registration.showNotification(d.title||'Blitz Zone',o))});
self.addEventListener('notificationclick',e=>{e.notification.close();
 e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>{for(const c of l){if('focus'in c)return c.focus()}return clients.openWindow('./')}))});
