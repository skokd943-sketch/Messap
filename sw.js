const CACHE='fabrlink-v22',FILES=['./','./index.html','./minigame.html','./manifest.json','./2341F654-35F3-4085-8DDD-522F7929D582.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(FILES)).catch(()=>{}));self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==CACHE).map(x=>caches.delete(x)))));self.clients.claim()});
// Кэшируем только файлы самого сайта. Запросы к API (messap.onrender.com) не трогаем.
self.addEventListener('fetch',e=>{
  const r=e.request,u=new URL(r.url);
  if(r.method!=='GET'||u.origin!==location.origin)return;
  e.respondWith(fetch(r).then(res=>{if(res.ok){const c=res.clone();caches.open(CACHE).then(x=>x.put(r,c))}return res}).catch(()=>caches.match(r).then(m=>m||caches.match('./index.html'))));
});

// Push-уведомления о новых сообщениях
self.addEventListener('push',e=>{
  let d={};try{d=e.data.json()}catch{d={title:'ФабрLink',body:e.data?e.data.text():'Новое сообщение'}}
  const icon='./2341F654-35F3-4085-8DDD-522F7929D582.png';
  e.waitUntil(self.registration.showNotification(d.title||'ФабрLink',{body:d.body||'',icon,badge:icon,tag:d.tag||'chat',renotify:true,data:{peer:d.peer||''}}));
});
self.addEventListener('notificationclick',e=>{
  e.notification.close();const peer=e.notification.data&&e.notification.data.peer;
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(cs=>{
    const c=cs[0];
    if(c){c.focus();if(peer)c.postMessage({openChat:peer});return}
    return self.clients.openWindow('./'+(peer?'?chat='+encodeURIComponent(peer):''));
  }));
});
