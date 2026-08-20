-- Dynamic SSL certificates for SNI via ssl_certificate_by_lua.
-- Flow: SNI host -> domain:{host} -> site_id -> ssl:{site_id} (PEM cert + key)
--
-- Cert updates are pushed by Angelos (SET ssl:{site_id} + PUBLISH ssl:updates).
-- Workers invalidate an L1 lrucache and bump a shared generation counter so every
-- worker reloads from Redis on the next full handshake.
--
-- Note: TLS session resumption can skip ssl_certificate_by_lua entirely and keep
-- serving the previous certificate. server_ssl.conf disables session tickets and
-- uses a short session timeout so rotated certs take effect without an Athens restart.

local ssl = require "ngx.ssl"
local redis = require "resty.redis"
local cjson = require "cjson.safe"
local lrucache = require "resty.lrucache"

local _M = { _VERSION = "1.1.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local SHM_NAME = "ssl_certs"
local GEN_KEY = "gen"
local CACHE_TTL = 60
local CACHE_SIZE = 200

-- L1 cache: host -> { cert, key, site_id, gen, expire }
local cache, cache_err = lrucache.new(CACHE_SIZE)
if not cache then
    ngx.log(ngx.ERR, "ssl_cert: failed to create lrucache: ", tostring(cache_err))
end

local function shm()
    return ngx.shared[SHM_NAME]
end

local function current_gen()
    local dict = shm()
    if not dict then
        return 0
    end
    return tonumber(dict:get(GEN_KEY)) or 0
end

local function bump_gen()
    local dict = shm()
    if not dict then
        return 0
    end
    local new_gen, err = dict:incr(GEN_KEY, 1, 0)
    if not new_gen then
        ngx.log(ngx.ERR, "ssl_cert: gen incr failed: ", tostring(err))
        return current_gen()
    end
    return new_gen
end

local function normalize_host(host)
    if not host or host == "" then
        return ""
    end
    host = tostring(host)
    host = host:match("^([^:]+)") or host
    return host:lower()
end

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 1000)
    local ok, err = red:connect(REDIS_SOCK)
    if not ok then
        return nil, err
    end
    return red
end

local function release_redis(red)
    if red then
        pcall(function() red:set_keepalive(10000, 100) end)
    end
end

local function load_ssl_for_host(host)
    host = normalize_host(host)
    if host == "" then
        return nil, "empty_sni"
    end

    local gen = current_gen()
    if cache then
        local hit = cache:get(host)
        if hit and hit.gen == gen and hit.expire and hit.expire > ngx.now() then
            if hit.disabled then
                return nil, "ssl_disabled"
            end
            return hit
        end
    end

    local red, err = get_redis(1000)
    if not red then
        return nil, "redis_connect:" .. tostring(err)
    end

    local site_id = red:get("domain:" .. host)
    if not site_id or site_id == ngx.null or site_id == "" then
        release_redis(red)
        return nil, "domain_not_found"
    end

    local raw = red:get("ssl:" .. tostring(site_id))
    release_redis(red)

    if not raw or raw == ngx.null or raw == "" then
        -- Known site without ssl key: treat as HTTP-only (do not use default cert).
        if cache then
            cache:set(host, { disabled = true, gen = gen, expire = ngx.now() + CACHE_TTL }, CACHE_TTL)
        end
        return nil, "ssl_disabled"
    end

    local obj = cjson.decode(raw)
    if type(obj) ~= "table" then
        return nil, "ssl_json_invalid"
    end

    local ssl_type = tostring(obj.ssl_type or ""):lower()
    local pem_cert = obj.ssl_cert or ""
    local pem_key = obj.ssl_cert_key or ""
    if ssl_type == "none" or pem_cert == "" or pem_key == "" then
        if cache then
            cache:set(host, { disabled = true, gen = gen, expire = ngx.now() + CACHE_TTL }, CACHE_TTL)
        end
        return nil, "ssl_disabled"
    end

    local der_cert, cerr = ssl.parse_pem_cert(pem_cert)
    if not der_cert then
        return nil, "parse_cert:" .. tostring(cerr)
    end

    local der_key, kerr = ssl.parse_pem_priv_key(pem_key)
    if not der_key then
        return nil, "parse_key:" .. tostring(kerr)
    end

    local entry = {
        cert = der_cert,
        key = der_key,
        site_id = tonumber(site_id),
        gen = gen,
        expire = ngx.now() + CACHE_TTL,
    }
    if cache then
        cache:set(host, entry, CACHE_TTL)
    end
    return entry
end

function _M.clear_cache(host)
    if not cache then
        return
    end
    if host and host ~= "" then
        cache:delete(normalize_host(host))
    else
        cache:flush_all()
    end
end

--- Invalidate L1 on this worker and bump shared gen so other workers drop stale hits.
function _M.invalidate(reason)
    local gen = bump_gen()
    _M.clear_cache()
    if ngx.worker.id() == 0 then
        ngx.log(ngx.WARN, "ssl_cert: invalidated caches gen=", gen,
            " reason=", tostring(reason or "update"))
    end
end

--- Called from ssl_certificate_by_lua_block.
function _M.certificate()
    local host, serr = ssl.server_name()
    if not host or host == "" then
        -- No SNI: keep the default server certificate from nginx.conf.
        return
    end

    local entry, err = load_ssl_for_host(host)
    if entry then
        local ok, cerr = ssl.clear_certs()
        if not ok then
            ngx.log(ngx.ERR, "ssl_cert: clear_certs failed: ", tostring(cerr))
            return
        end

        ok, cerr = ssl.set_cert(entry.cert)
        if not ok then
            ngx.log(ngx.ERR, "ssl_cert: set_cert failed for ", host, ": ", tostring(cerr))
            return
        end

        ok, cerr = ssl.set_priv_key(entry.key)
        if not ok then
            ngx.log(ngx.ERR, "ssl_cert: set_priv_key failed for ", host, ": ", tostring(cerr))
        end
        return
    end

    if err == "domain_not_found" or err == "empty_sni" then
        -- Unknown host: keep the default server certificate.
        ngx.log(ngx.WARN, "ssl_cert: no dynamic cert for sni=", host, " err=", tostring(err))
        return
    end

    -- Known site with ssl_type=none (or empty certs): refuse HTTPS.
    -- clear_certs without set_cert aborts the handshake (no default-cert fallback).
    local ok, cerr = ssl.clear_certs()
    if not ok then
        ngx.log(ngx.ERR, "ssl_cert: clear_certs failed (http-only): ", tostring(cerr))
    end
    ngx.log(ngx.WARN, "ssl_cert: HTTPS disabled for sni=", host, " err=", tostring(err))
end

local function handle_update_payload(payload)
    if type(payload) ~= "string" or payload == "" then
        _M.invalidate("empty")
        return
    end
    -- Angelos publishes "ssl:{site_id}" or "ssl_deleted:{site_id}".
    _M.invalidate(payload)
end

function _M.start_subscriber(premature)
    if premature or ngx.worker.exiting() then
        return
    end

    local backoff = 1
    while not ngx.worker.exiting() do
        local red, err = get_redis(2000)
        if not red then
            ngx.log(ngx.ERR, "ssl_cert: subscriber redis failed: ", tostring(err))
            ngx.sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        red:set_timeout(5000)
        local ok_sub, sub_err = red:subscribe("ssl:updates")
        if not ok_sub then
            ngx.log(ngx.ERR, "ssl_cert: subscribe failed: ", tostring(sub_err))
            pcall(red.close, red)
            ngx.sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        -- Backup path when Angelos SET happens without PUBLISH (or publish is missed).
        local ok_psub, psub_err = red:psubscribe("__keyevent@0__:set", "__keyevent@0__:del")
        if not ok_psub then
            ngx.log(ngx.WARN, "ssl_cert: keyevent psubscribe failed: ", tostring(psub_err))
        end

        backoff = 1
        ngx.log(ngx.INFO, "ssl_cert: subscribed to ssl:updates")

        while not ngx.worker.exiting() do
            local msg, read_err = red:read_reply()
            if not msg then
                if read_err ~= "timeout" then
                    ngx.log(ngx.ERR, "ssl_cert: read_reply failed: ", tostring(read_err))
                    break
                end
            elseif type(msg) == "table" then
                if msg[1] == "message" and msg[2] == "ssl:updates" then
                    handle_update_payload(msg[3])
                elseif msg[1] == "pmessage" then
                    local key = msg[4]
                    if type(key) == "string" and key:find("^ssl:", 1, false) then
                        handle_update_payload(key)
                    end
                end
            end
        end

        pcall(function()
            pcall(red.unsubscribe, red, "ssl:updates")
            pcall(red.punsubscribe, red, "__keyevent@0__:set")
            pcall(red.punsubscribe, red, "__keyevent@0__:del")
            pcall(red.quit, red)
            pcall(red.close, red)
        end)

        if ngx.worker.exiting() then
            break
        end
        ngx.sleep(backoff)
        backoff = math.min(backoff * 2, 30)
        ::continue::
    end
end

function _M.start()
    local ok, err = ngx.timer.at(0, _M.start_subscriber)
    if not ok then
        ngx.log(ngx.ERR, "ssl_cert: failed to start subscriber: ", tostring(err))
    end
end

return _M
