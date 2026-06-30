About
=====
`ngx_cache_purge` is `nginx` module which adds ability to purge content from
`proxy`caches. A purge operation removes the content with the same cache key as the purge request has.

This module requires:
- Redis 2.8 or newer. Install it with your favourite package manager - apt-get, yum, brew - or download [Redis](http://redis.io/download) and compile it.
- hiredis 0.11.0. Install it with your favourite package manager - apt-get, yum, brew - or download [hiredis](https://github.com/redis/hiredis/releases) and compile it.
- [redis_nginx_adapter](https://github.com/wandenberg/redis_nginx_adapter) library


Status
======
This module is in development


Configuration directives (same location syntax)
===============================================

* **syntax**: `redis_cache_handler on|off
* **default**: `none`
* **context**: `http`, `server`, `location`

Allow purging of selected pages from `proxy`'s cache.


Sample configuration (same location syntax)
===========================================
    proxy_cache_path /usr/local/openresty/nginx/cache keys_zone=zone:10m inactive=1d max_size=10g;

    cache_purge_redis_host "localhost";
    cache_purge_redis_port 6379;
    cache_purge_redis_database 2;
    #cache_purge_redis_socket_path "/tmp/redis.sock";

    location ~ /purge(/.*) {
        allow              127.0.0.1;
        deny               all;
        redis_cache_handler on;
        redis_cache_purge_query "$1";
    }

    add_header X-Cache-Status $upstream_cache_status;
    proxy_ignore_headers Cache-Control Expires;

    location / {
        proxy_pass           http://localhost:8081;
        proxy_cache          zone;
        proxy_cache_key      "$host@$uri$is_args$args";
        proxy_cache_valid    any 5m;
        proxy_ignore_headers Cache-Control Expires;
    }

Example database status
=======================
    [root] redis-cli 
    127.0.0.1:6379> select 2
    OK
    127.0.0.1:6379[2]> dbsize
    (integer) 7
    127.0.0.1:6379[2]> scan 0 count 100
    1) "0"
    2) 1) "127.0.0.1@/a4"
    2) "127.0.0.1@/a3"
    3) "127.0.0.1@/a5"
    4) "127.0.0.1@/a2"
    5) "127.0.0.1@/aB9"
    6) "127.0.0.1@/a6"
    7) "127.0.0.1@/a1"

Example usagae
==============
- Trigger cache

    curl -v http://127.0.0.1/a1

    curl -v http://127.0.0.1/a2

    curl -v http://127.0.0.1/a3
    

- Purge caches

    curl -v http://127.0.0.1:8080/purge/*a*
    > {"Key" : "*a*", "Success" : 3, "Failed" : 0}

    curl -v "http://127.0.0.1:8080/purge/*\[a-z\]*"
    > {"Key" : "*[a-z]*", "Success" : 5, "Failed" : 0}

See also
========
- [ngx_slowfs_cache](http://github.com/FRiCKLE/ngx_slowfs_cache).
- http://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#purger
- http://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_purge
- https://github.com/wandenberg/nginx-selective-cache-purge-module
- https://github.com/wandenberg/nginx-sorted-querystring-module
- https://github.com/ledgetech/ledge
- [Faking Surrogate Cache-Keys for Nginx Plus](https://www.innoq.com/en/blog/faking-surrogate-cache-keys-for-nginx-plus/) ([gist](https://gist.github.com/titpetric/2f142e89eaa0f36ba4e4383b16d61474))
- [Delete NGINX cached md5 items with a PURGE with wildcard support](https://gist.github.com/nosun/0cfb58d3164f829e2f027fd37b338ede)
