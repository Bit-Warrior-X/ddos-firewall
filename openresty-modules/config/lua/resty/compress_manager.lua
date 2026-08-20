-- Site-scoped compress settings from Redis key compress:{site_id}.
-- Stored for request context / future per-site gzip control.
-- nginx http gzip remains global (http_gzip.conf); this exposes site flags.

local redis = require "resty.redis"
local cjson = require "cjson.safe"
local site_resolver = require "resty.site_resolver"
local ngx = ngx

local _M = { _VERSION = "1.0.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local SHM_NAME = "compress_settings"
local REFRESH_SEC = 5

local l1 = {}

local EMPTY = {
    css = false,
    html = false,
    js = false,
    audio = false,
    font = false,
    applications = false,
}

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 2000)
    local ok, err = red:connect(REDIS_SOCK)
    if not ok then
        return nil, err
    end
    return red
end

local function normalize(flags)
    local out = {}
    for k, v in pairs(EMPTY) do
        out[k] = false
    end
    if type(flags) ~= "table" then
        return out
    end
    for k, _ in pairs(EMPTY) do
        local val = flags[k]
        if val == true or val == 1 or val == "1" or val == "true" or val == "yes" then
            out[k] = true
        end
    end
    return out
end

local function load_from_redis(site_id)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    local key = "compress:" .. tostring(site_id)
    local raw = red:get(key)
    red:set_keepalive(10000, 100)
    if not raw or raw == ngx.null or raw == "" then
        return normalize(nil)
    end
    return normalize(cjson.decode(raw))
end

local function refresh_shm()
    local dict = ngx.shared[SHM_NAME]
    if not dict then
        return
    end
    local site_domains = site_resolver.list_site_domains()
    local now = ngx.time()
    for site_id, _ in pairs(site_domains) do
        local flags, err = load_from_redis(site_id)
        if not err then
            local sid = tostring(site_id)
            dict:set("flags:" .. sid, cjson.encode(flags), 0)
            dict:set("updated:" .. sid, now, 0)
            l1[sid] = { flags = flags, version = now }
        end
    end
    dict:set("updated", now, 0)
end

function _M.get(site_id)
    site_id = site_id or site_resolver.lookup_site_id()
    if not site_id then
        return normalize(nil)
    end
    local sid = tostring(site_id)
    local dict = ngx.shared[SHM_NAME]
    local version = dict and (dict:get("updated:" .. sid) or 0) or 0
    local entry = l1[sid]
    if entry and entry.version == version and version > 0 then
        return entry.flags
    end
    if dict then
        local raw = dict:get("flags:" .. sid)
        if raw and raw ~= "" then
            local decoded = cjson.decode(raw)
            if type(decoded) == "table" then
                l1[sid] = { flags = decoded, version = version }
                return decoded
            end
        end
    end
    local loaded = load_from_redis(site_id)
    if loaded then
        local now = ngx.time()
        if dict then
            dict:set("flags:" .. sid, cjson.encode(loaded), 0)
            dict:set("updated:" .. sid, now, 0)
        end
        l1[sid] = { flags = loaded, version = now }
        return loaded
    end
    return normalize(nil)
end

function _M.start_refresh()
    local function run(premature)
        if premature or ngx.worker.exiting() then
            return
        end
        refresh_shm()
        ngx.timer.at(REFRESH_SEC, run)
    end
    local ok, err = ngx.timer.at(0.5, run)
    if not ok then
        ngx.log(ngx.ERR, "compress_manager: failed to start refresh: ", tostring(err))
    end
end

return _M
