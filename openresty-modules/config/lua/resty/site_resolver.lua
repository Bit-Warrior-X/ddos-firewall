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
    dict:set("id:" .. cache_key, site_id and tostring(site_id) or "", DOMAIN_MAP_TTL)
end

local function redis_get_domain(red, name)
    if not name or name == "" then
        return nil
    end
    local val = red:get("domain:" .. name)
    if val and val ~= ngx.null and val ~= "" then
        return tonumber(val)
    end
    return nil
end

--- Return site_id (number) for current request Host, or nil.
function _M.lookup_site_id(host)
    if ngx.ctx._site_id_resolved then
        return ngx.ctx._site_id
    end

    local http_host = tostring(host or ngx.var.http_host or ngx.var.host or "")
    local bare = strip_port(http_host)
    local port = tostring(ngx.var.server_port or "")
    if bare == "" then
        ngx.ctx._site_id_resolved = true
        ngx.ctx._site_id = nil
        return nil
    end

    -- Port-scoped cache key (bare host alone is unsafe when multiple sites share it).
    local cache_key = port ~= "" and (bare .. ":" .. port) or bare
    local cached_id, hit = cache_get(cache_key)
    if hit then
        ngx.ctx._site_id_resolved = true
        ngx.ctx._site_id = cached_id
        return cached_id
    end

    local red, err = get_redis(500)
    if not red then
        -- Do not negative-cache Redis failures — retry next request.
        ngx.log(ngx.WARN, "site_resolver: redis connect failed: ", tostring(err))
        ngx.ctx._site_id_resolved = true
        ngx.ctx._site_id = nil
        return nil
    end

    local site_id
    -- Prefer host:port keys (panel form), then bare host, then raw Host as stored.
    if port ~= "" then
        site_id = redis_get_domain(red, bare .. ":" .. port)
    end
    if not site_id then
        site_id = redis_get_domain(red, bare)
    end
    if not site_id and http_host ~= "" and http_host:lower() ~= bare then
        site_id = redis_get_domain(red, http_host:lower())
    end
    release_redis(red)

    cache_set(cache_key, site_id)
    ngx.ctx._site_id_resolved = true
    ngx.ctx._site_id = site_id
    return site_id
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

    local red, err = get_redis(2000)
    if not red then
        ngx.log(ngx.WARN, "site_resolver: list_site_domains redis failed: ", tostring(err))
        return {}
    end

    local map = {}
    local cursor = "0"
    repeat
        local res, scan_err = red:scan(cursor, "MATCH", "domain:*", "COUNT", 100)
        if not res or scan_err then
            break
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
        dict:set(DOMAIN_MAP_KEY, cjson.encode(map), DOMAIN_MAP_TTL)
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
