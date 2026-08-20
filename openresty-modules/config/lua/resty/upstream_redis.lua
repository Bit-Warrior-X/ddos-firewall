-- Dynamic upstream list from Redis key upstreamservers:{site_id}.
-- Expected JSON: [ { "ip_port": "192.168.1.199:100", "description": "weight=4 ..." }, ... ]

local redis  = require "resty.redis"
local cjson  = require "cjson.safe"
local site_resolver = require "resty.site_resolver"
local ngx    = ngx
local log    = ngx.log
local ERR    = ngx.ERR
local WARN   = ngx.WARN
local INFO   = ngx.INFO
local timer  = ngx.timer.at
local worker = ngx.worker
local shd    = ngx.shared

local _M = { _VERSION = "2.0.0" }

local REDIS_SOCK      = "unix:/tmp/redis.sock"
local SHM_NAME        = "upstream_servers"
local REFRESH_SEC     = 5
local DEFAULT_BACKEND = "http://127.0.0.1:9000"

-- Per-worker L1: { [site_id] = { list=..., version=... } }
local l1 = {}

local function parse_description(desc)
    if not desc or type(desc) ~= "string" then
        return { weight = 1, max_fails = 3, fail_timeout = 30 }
    end
    local weight = 1
    local max_fails = 3
    local fail_timeout = 30
    for k, v in desc:gmatch("(%w+)=([%d]+)") do
        if k == "weight" then
            weight = tonumber(v) or 1
        elseif k == "max_fails" then
            max_fails = tonumber(v) or 3
        elseif k == "fail_timeout" then
            fail_timeout = tonumber(v) or 30
        end
    end
    return { weight = weight, max_fails = max_fails, fail_timeout = fail_timeout }
end

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 2000)
    local ok, err = red:connect(REDIS_SOCK)
    if not ok then
        log(ERR, "upstream_redis: redis connect failed: ", tostring(err))
        return nil, err
    end
    return red
end

local function normalize_list(list)
    local out = {}
    if type(list) ~= "table" then
        return out
    end
    for _, item in ipairs(list) do
        if type(item) == "table" and item.ip_port and item.ip_port ~= "" then
            local desc = parse_description(item.description)
            table.insert(out, {
                host_port = item.ip_port,
                weight    = desc.weight
            })
        end
    end
    return out
end

local function load_from_redis(site_id)
    local red, err = get_redis()
    if not red then return nil, err end
    local key = "upstreamservers:" .. tostring(site_id)
    local raw, rerr = red:get(key)
    red:set_keepalive(10000, 100)
    if not raw or raw == ngx.null or raw == "" then
        return {}
    end
    local list, jerr = cjson.decode(raw)
    if not list or type(list) ~= "table" then
        log(WARN, "upstream_redis: invalid JSON for ", key, " ", tostring(jerr))
        return {}
    end
    return normalize_list(list)
end

local function expand_by_weight(list)
    local expanded = {}
    for _, s in ipairs(list) do
        local w = math.max(1, math.floor(s.weight or 1))
        for _ = 1, w do
            expanded[#expanded + 1] = s.host_port
        end
    end
    return expanded
end

local function refresh_shm()
    local dict = shd[SHM_NAME]
    if not dict then return end

    local site_domains = site_resolver.list_site_domains()
    local version = ngx.time()
    local site_ids = {}

    for site_id, _ in pairs(site_domains) do
        local list, err = load_from_redis(site_id)
        if err then
            log(WARN, "upstream_redis: load failed for site ", site_id, ": ", tostring(err))
        else
            local expanded = expand_by_weight(list)
            dict:set("list:" .. site_id, cjson.encode(expanded), 0)
            dict:set("updated:" .. site_id, version, 0)
            l1[tostring(site_id)] = { list = expanded, version = version }
            site_ids[#site_ids + 1] = tostring(site_id)
        end
    end

    dict:set("sites", table.concat(site_ids, ","), 0)
    dict:set("updated", version, 0)
end

function _M.get_backend(site_id)
    site_id = site_id or site_resolver.lookup_site_id()
    if not site_id then
        return DEFAULT_BACKEND
    end

    local sid = tostring(site_id)
    local dict = shd[SHM_NAME]
    if not dict then
        return DEFAULT_BACKEND
    end

    local version = dict:get("updated:" .. sid) or 0
    local entry = l1[sid]
    local list = entry and entry.list
    if not list or not entry or entry.version ~= version then
        local raw = dict:get("list:" .. sid)
        if not raw or raw == "" then
            -- Lazy load once if refresh has not populated this site yet.
            local loaded = load_from_redis(site_id)
            if loaded then
                list = expand_by_weight(loaded)
                local now = ngx.time()
                dict:set("list:" .. sid, cjson.encode(list), 0)
                dict:set("updated:" .. sid, now, 0)
                l1[sid] = { list = list, version = now }
            else
                return DEFAULT_BACKEND
            end
        else
            list = cjson.decode(raw)
            if not list or #list == 0 then
                return DEFAULT_BACKEND
            end
            l1[sid] = { list = list, version = version }
        end
    end

    if not list or #list == 0 then
        return DEFAULT_BACKEND
    end

    local rr_key = "round_robin:" .. sid
    local idx = dict:incr(rr_key, 1, 0)
    if idx == nil then
        dict:set(rr_key, 1, 0)
        idx = 1
    end
    local host_port = list[(idx - 1) % #list + 1]
    if type(host_port) ~= "string" or host_port == "" then
        return DEFAULT_BACKEND
    end
    return "http://" .. host_port
end

function _M.start_refresh()
    local function run(premature)
        if premature or worker.exiting() then return end
        refresh_shm()
        timer(REFRESH_SEC, run)
    end
    local ok, err = timer(0.5, run)
    if not ok then
        log(ERR, "upstream_redis: failed to start refresh timer: ", tostring(err))
    else
        log(INFO, "upstream_redis: refresh timer started for upstreamservers:{site_id}")
    end
end

return _M
