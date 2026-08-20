-- Site-scoped listening ports from Redis key listening:{site_id}.
-- Value: { http_ports: [...], https_ports: [...] }
--
-- Edge-wide nginx listen sockets are NOT managed here. Angelos stores them under
-- Redis key "listeningports" and writes server_default_ports.conf (see
-- api_parser/core/listening_ports.py). This module only exposes each site's
-- selected HTTP/HTTPS ports for request logic.

local redis = require "resty.redis"
local cjson = require "cjson.safe"
local site_resolver = require "resty.site_resolver"
local ngx = ngx

local _M = { _VERSION = "1.0.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local SHM_NAME = "site_listening"
local REFRESH_SEC = 5

local l1 = {}
local EMPTY = { http_ports = {}, https_ports = {} }

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 2000)
    local ok, err = red:connect(REDIS_SOCK)
    if not ok then
        return nil, err
    end
    return red
end

local function normalize(payload)
    if type(payload) ~= "table" then
        return { http_ports = {}, https_ports = {} }
    end
    local http_ports = payload.http_ports
    local https_ports = payload.https_ports
    if type(http_ports) ~= "table" then
        http_ports = {}
    end
    if type(https_ports) ~= "table" then
        https_ports = {}
    end
    -- Legacy: flat list
    if #http_ports == 0 and #https_ports == 0 and payload[1] then
        for _, p in ipairs(payload) do
            if type(p) == "table" then
                local proto = tostring(p.protocol or "HTTP"):upper()
                if proto == "HTTPS" or proto == "SSL" or proto == "TLS" then
                    https_ports[#https_ports + 1] = p
                else
                    http_ports[#http_ports + 1] = p
                end
            end
        end
    end
    return { http_ports = http_ports, https_ports = https_ports }
end

local function load_from_redis(site_id)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    local key = "listening:" .. tostring(site_id)
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
        local ports, err = load_from_redis(site_id)
        if not err then
            local sid = tostring(site_id)
            dict:set("ports:" .. sid, cjson.encode(ports), 0)
            dict:set("updated:" .. sid, now, 0)
            l1[sid] = { ports = ports, version = now }
        end
    end
    dict:set("updated", now, 0)
end

function _M.get(site_id)
    site_id = site_id or site_resolver.lookup_site_id()
    if not site_id then
        return EMPTY
    end
    local sid = tostring(site_id)
    local dict = ngx.shared[SHM_NAME]
    local version = dict and (dict:get("updated:" .. sid) or 0) or 0
    local entry = l1[sid]
    if entry and entry.version == version and version > 0 then
        return entry.ports
    end
    if dict then
        local raw = dict:get("ports:" .. sid)
        if raw and raw ~= "" then
            local decoded = cjson.decode(raw)
            if type(decoded) == "table" then
                l1[sid] = { ports = decoded, version = version }
                return decoded
            end
        end
    end
    local loaded = load_from_redis(site_id)
    if loaded then
        local now = ngx.time()
        if dict then
            dict:set("ports:" .. sid, cjson.encode(loaded), 0)
            dict:set("updated:" .. sid, now, 0)
        end
        l1[sid] = { ports = loaded, version = now }
        return loaded
    end
    return EMPTY
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
        ngx.log(ngx.ERR, "listening_manager: failed to start refresh: ", tostring(err))
    end
end

return _M
