-- Resolve request Host to site_id via Redis domain:{host} mapping.
-- Also helpers to enumerate site→domains for ACL merging.
--
-- Panel often stores domain keys as "host:port" (e.g. xstream.wtf:8080).
-- Cache keys MUST include server_port so :80 / :2052 / :8080 do not collide
-- when the Host header is bare "xstream.wtf".

local redis = require "resty.redis"
local ngx = ngx

local _M = { _VERSION = "1.1.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local SHM_NAME = "site_resolver"
local DOMAIN_MAP_KEY = "domain_map"
local DOMAIN_MAP_TTL = 5
-- Last-known-good copies served while Redis is unreachable.
local STALE_PREFIX = "stale:"
local STALE_ID_TTL = 3600
-- Shared Redis circuit breaker: while open, hot paths skip Redis entirely.
local BREAKER_KEY = "redis_down"
local BREAKER_TTL = 2

--- True while the shared Redis circuit breaker is open.
function _M.redis_down()
    local dict = ngx.shared[SHM_NAME]
    return dict ~= nil and dict:get(BREAKER_KEY) ~= nil
end

--- Open the breaker for BREAKER_TTL seconds (logs once per open).
function _M.mark_redis_down(err)
    local dict = ngx.shared[SHM_NAME]
    if dict and dict:add(BREAKER_KEY, tostring(err or "error"), BREAKER_TTL) then
        ngx.log(ngx.WARN, "site_resolver: redis circuit open for ", BREAKER_TTL,
            "s: ", tostring(err))
    end
end

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 500)
    local ok, err = red:connect(REDIS_SOCK, { pool = "athens_redis_db0" })
    if not ok then
        return nil, err
    end
    local ok_sel, sel_err = red:select(0)
    if not ok_sel then
        red:close()
        return nil, sel_err or "select_0_failed"
    end
    return red
end

local function release_redis(red)
    if red then
        pcall(function() red:set_keepalive(10000, 100) end)
    end
end

local function strip_port(host)
    if not host or host == "" then
        return ""
    end
    host = tostring(host)
    -- [ipv6]:port
    local v6 = host:match("^%[(.+)%]")
    if v6 then
        return v6:lower()
    end
    -- hostname:port or ipv4:port — only strip if trailing :digits
    local bare, port = host:match("^(.+):(%d+)$")
    if bare and port then
        return bare:lower()
    end
    return host:lower()
end

local function cache_get(cache_key)
    local dict = ngx.shared[SHM_NAME]
    if not dict then
        return nil, false
    end
    local cached = dict:get("id:" .. cache_key)
    if cached == nil then
        return nil, false
    end
    if cached == "" then
        return nil, true
    end
    return tonumber(cached), true
end

local function cache_set(cache_key, site_id)
    local dict = ngx.shared[SHM_NAME]
    if not dict then
        return
    end
    local val = site_id and tostring(site_id) or ""
    dict:set("id:" .. cache_key, val, DOMAIN_MAP_TTL)
    dict:set(STALE_PREFIX .. "id:" .. cache_key, val, STALE_ID_TTL)
end

local function stale_get(cache_key)
    local dict = ngx.shared[SHM_NAME]
    if not dict then
        return nil
    end
    local val = dict:get(STALE_PREFIX .. "id:" .. cache_key)
    if val == nil or val == "" then
        return nil
    end
    return tonumber(val)
end

--- Returns (site_id|nil, err). err is set only on Redis errors, not on "not found".
local function redis_get_domain(red, name)
    if not name or name == "" then
        return nil
    end
    local val, err = red:get("domain:" .. name)
    if err then
        return nil, err
    end
    if val and val ~= ngx.null and val ~= "" then
        return tonumber(val)
    end
    return nil
end

local function request_cache_key(host)
    local http_host = tostring(host or ngx.var.http_host or ngx.var.host or "")
    local bare = strip_port(http_host)
    if bare == "" then
        return nil
    end
    local port = tostring(ngx.var.server_port or "")
    -- Port-scoped cache key (bare host alone is unsafe when multiple sites share it).
    return port ~= "" and (bare .. ":" .. port) or bare, bare, port, http_host
end

local function remember(site_id)
    ngx.ctx._site_id_resolved = true
    ngx.ctx._site_id = site_id
    return site_id
end

--- Like lookup_site_id but never touches Redis (safe in log_by_lua / hot paths).
--- Falls back to the last-known-good mapping.
function _M.lookup_site_id_cached(host)
    if ngx.ctx._site_id_resolved then
        return ngx.ctx._site_id
    end

    local cache_key = request_cache_key(host)
    if not cache_key then
        return nil
    end
    local cached_id, hit = cache_get(cache_key)
    if hit then
        return cached_id
    end
    return stale_get(cache_key)
end

--- Return site_id (number) for current request Host, or nil.
function _M.lookup_site_id(host)
    if ngx.ctx._site_id_resolved then
        return ngx.ctx._site_id
    end

    local cache_key, bare, port, http_host = request_cache_key(host)
    if not cache_key then
        return remember(nil)
    end

    local cached_id, hit = cache_get(cache_key)
    if hit then
        return remember(cached_id)
    end

    -- Do not negative-cache Redis failures; serve last-known-good instead.
    if _M.redis_down() then
        return remember(stale_get(cache_key))
    end

    local red, err = get_redis(500)
    if not red then
        _M.mark_redis_down(err)
        return remember(stale_get(cache_key))
    end

    local site_id, gerr
    -- Prefer host:port keys (panel form), then bare host, then raw Host as stored.
    if port ~= "" then
        site_id, gerr = redis_get_domain(red, bare .. ":" .. port)
    end
    if not site_id and not gerr then
        site_id, gerr = redis_get_domain(red, bare)
    end
    if not site_id and not gerr and http_host ~= "" and http_host:lower() ~= bare then
        site_id, gerr = redis_get_domain(red, http_host:lower())
    end

    if gerr then
        red:close()
        _M.mark_redis_down(gerr)
        return remember(stale_get(cache_key))
    end
    release_redis(red)

    cache_set(cache_key, site_id)
    return remember(site_id)
end

--- Scan Redis domain:* and return { [site_id_str] = { "host1", "host2", ... }, ... }
function _M.list_site_domains()
    local dict = ngx.shared[SHM_NAME]
    if dict then
        local cached = dict:get(DOMAIN_MAP_KEY)
        if cached and cached ~= "" then
            local cjson = require "cjson.safe"
            local decoded = cjson.decode(cached)
            if type(decoded) == "table" then
                return decoded
            end
        end
    end

    local function stale_map()
        if dict then
            local stale = dict:get(STALE_PREFIX .. DOMAIN_MAP_KEY)
            if stale and stale ~= "" then
                local cjson = require "cjson.safe"
                local decoded = cjson.decode(stale)
                if type(decoded) == "table" then
                    return decoded
                end
            end
        end
        return {}
    end

    -- An empty map would rebuild site-scoped ACLs (incl. anti-CC) with no rules.
    if _M.redis_down() then
        return stale_map()
    end

    local red, err = get_redis(2000)
    if not red then
        ngx.log(ngx.WARN, "site_resolver: list_site_domains redis failed: ", tostring(err))
        _M.mark_redis_down(err)
        return stale_map()
    end

    local map = {}
    local cursor = "0"
    repeat
        local res, scan_err = red:scan(cursor, "MATCH", "domain:*", "COUNT", 100)
        if not res or scan_err then
            red:close()
            ngx.log(ngx.WARN, "site_resolver: list_site_domains scan failed: ", tostring(scan_err))
            _M.mark_redis_down(scan_err)
            return stale_map()
        end
        cursor = res[1]
        local keys = res[2]
        if keys then
            for _, key in ipairs(keys) do
                local host = tostring(key):match("^domain:(.+)$")
                if host and host ~= "" then
                    local val = red:get(key)
                    if val and val ~= ngx.null and val ~= "" then
                        local site_id = tostring(val):match("^%s*(.-)%s*$")
                        if site_id and site_id ~= "" then
                            local list = map[site_id]
                            if not list then
                                list = {}
                                map[site_id] = list
                            end
                            list[#list + 1] = host:lower()
                        end
                    end
                end
            end
        end
    until cursor == "0"

    release_redis(red)

    if dict then
        local cjson = require "cjson.safe"
        local encoded = cjson.encode(map)
        dict:set(DOMAIN_MAP_KEY, encoded, DOMAIN_MAP_TTL)
        dict:set(STALE_PREFIX .. DOMAIN_MAP_KEY, encoded, 0)
    end

    return map
end

function _M.invalidate_domain_cache()
    local dict = ngx.shared[SHM_NAME]
    if not dict then
        return
    end
    dict:delete(DOMAIN_MAP_KEY)
    for _, key in ipairs(dict:get_keys(0)) do
        if key:sub(1, 3) == "id:" then
            dict:delete(key)
        end
    end
end

return _M
