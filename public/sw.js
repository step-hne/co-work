'use strict';

var CACHE = 'ngix-v2';
var STATIC = [
    '/dist/bootstrap.min.css',
    '/dist/flags.css',
    '/dist/jquery.min.js',
    '/dist/bootstrap.min.js',
    '/dist/jquery.bootgrid.min.js',
    '/image.png',
    '/favicon.ico',
    '/banner.png'
];

self.addEventListener('install', function (e) {
    e.waitUntil(
        caches.open(CACHE).then(function (cache) {
            return cache.addAll(STATIC);
        })
    );
    self.skipWaiting();
});

self.addEventListener('activate', function (e) {
    e.waitUntil(
        caches.keys().then(function (keys) {
            return Promise.all(
                keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); })
            );
        })
    );
    self.clients.claim();
});

self.addEventListener('fetch', function (e) {
    if (e.request.method !== 'GET') { return; }
    var url = new URL(e.request.url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') { return; }
    var isStatic = url.pathname.startsWith('/dist/') ||
        /\.(png|ico|svg|webp|jpg|jpeg|gif|css|js|woff|woff2|ttf|eot)(\?|$)/.test(url.pathname);

    if (isStatic) {
        e.respondWith(
            caches.match(e.request).then(function (cached) {
                if (cached) { return cached; }
                return fetch(e.request).then(function (res) {
                    if (res && res.ok) {
                        var clone = res.clone();
                        caches.open(CACHE).then(function (cache) { cache.put(e.request, clone); });
                    }
                    return res;
                });
            })
        );
        return;
    }

    e.respondWith(
        fetch(e.request).catch(function () {
            return caches.match(e.request).then(function (cached) {
                return cached || new Response('', { status: 503 });
            });
        })
    );
});
