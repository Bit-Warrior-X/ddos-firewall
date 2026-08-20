-- Dynamic SSL certificates for SNI via ssl_certificate_by_lua.
-- Flow: SNI host -> domain:{host} -> site_id -> ssl:{site_id} (PEM cert + key)

local ssl = require "ngx.ssl"
local redis = require "resty.redis"
local cjson = require "cjson.safe"
local lrucache = require "resty.lrucache"

local _M = { _VERSION = "1.0.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local CACHE_TTL = 60
local CACHE_SIZE = 200

-- L1 cache: host -> { cert_der_chain, pkey_der, expire }
local cache, cache_err = lrucache.new(CACHE_SIZE)
if not cache then
    ngx.log(ngx.ERR, "ssl_cert: failed to create lrucache: ", tostring(cache_err))
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

    if cache then
        local hit = cache:get(host)
        if hit and hit.expire and hit.expire > ngx.now() then
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
        return nil, "ssl_not_found"
    end

    local obj = cjson.decode(raw)
    if type(obj) ~= "table" then
        return nil, "ssl_json_invalid"
    end

    local pem_cert = obj.ssl_cert or ""
    local pem_key = obj.ssl_cert_key or ""
    if pem_cert == "" or pem_key == "" then
        return nil, "ssl_empty"
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

--- Called from ssl_certificate_by_lua_block.
function _M.certificate()
    local host, serr = ssl.server_name()
    if not host or host == "" then
        -- No SNI: keep the default server certificate from nginx.conf.
        return
    end

    local entry, err = load_ssl_for_host(host)
    if not entry then
        ngx.log(ngx.WARN, "ssl_cert: no dynamic cert for sni=", host, " err=", tostring(err))
        return
    end

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
        return
    end
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

        backoff = 1
        ngx.log(ngx.INFO, "ssl_cert: subscribed to ssl:updates")

        while not ngx.worker.exiting() do
            local msg, read_err = red:read_reply()
            if not msg then
                if read_err ~= "timeout" then
                    ngx.log(ngx.ERR, "ssl_cert: read_reply failed: ", tostring(read_err))
                    break
                end
            elseif type(msg) == "table" and msg[1] == "message" then
                -- Any SSL change: flush L1 so next handshake reloads from Redis.
                _M.clear_cache()
            end
        end

        pcall(function()
            pcall(red.unsubscribe, red, "ssl:updates")
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
