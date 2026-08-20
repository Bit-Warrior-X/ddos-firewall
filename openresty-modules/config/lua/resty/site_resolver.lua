-- Resolve request Host to site_id via Redis domain:{host} mapping.
-- Also helpers to enumerate site→domains for ACL merging.

local redis = require "resty.redis"
local ngx = ngx

local _M = { _VERSION = "1.0.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local SHM_NAME = "site_resolver"
local DOMAIN_MAP_KEY = "domain_map"
local DOMAIN_MAP_TTL = 5

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 500)
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

local function normalize_host(host)
    if not host or host == "" then
        return ""
    end
    host = tostring(host)
    host = host:match("^([^:]+)") or host
    return host:lower()
end

local function cache_site_id(host, site_id)
    local dict = ngx.shared[SHM_NAME]
    if dict then
        dict:set("id:" .. host, site_id and tostring(site_id) or "", DOMAIN_MAP_TTL)
    end
end

--- Return site_id (number) for current request Host, or nil.
function _M.lookup_site_id(host)
    if ngx.ctx._site_id_resolved then
        return ngx.ctx._site_id
    end

    host = normalize_host(host or ngx.var.host or ngx.var.http_host or "")
    if host == "" then
        ngx.ctx._site_id_resolved = true
        ngx.ctx._site_id = nil
        return nil
    end

    local dict = ngx.shared[SHM_NAME]
    if dict then
        local cached = dict:get("id:" .. host)
        if cached ~= nil then
            local site_id = tonumber(cached)
            ngx.ctx._site_id_resolved = true
            ngx.ctx._site_id = site_id
            return site_id
        end
    end

    local red, err = get_redis(500)
    if not red then
        ngx.log(ngx.WARN, "site_resolver: redis connect failed: ", tostring(err))
        ngx.ctx._site_id_resolved = true
        ngx.ctx._site_id = nil
        return nil
    end

    local val = red:get("domain:" .. host)
    release_redis(red)

    local site_id
    if val and val ~= ngx.null and val ~= "" then
        site_id = tonumber(val)
    end

    cache_site_id(host, site_id)
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
