-- Dynamic upstream list from Redis key "upstreamservers".
-- Expected JSON: [ { "ip_port": "192.168.1.199:100", "description": "weight=4 max_fails=3 fail_timeout=30s" }, ... ]
-- Parses description for weight (default 1); uses weighted round-robin selection.

local redis  = require "resty.redis"
local cjson  = require "cjson.safe"
local ngx    = ngx
local log    = ngx.log
local ERR    = ngx.ERR
local WARN   = ngx.WARN
local INFO   = ngx.INFO
local timer  = ngx.timer.at
local worker = ngx.worker
local shd    = ngx.shared

local _M = { _VERSION = "1.0.0" }

local REDIS_SOCK     = "unix:/tmp/redis.sock"
local REDIS_KEY      = "upstreamservers"
local SHM_NAME       = "upstream_servers"
local REFRESH_SEC    = 5
local DEFAULT_BACKEND = "http://127.0.0.1:9000"

-- Parse "weight=4 max_fails=3 fail_timeout=30s" from description string
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

-- Load list from Redis and normalize into { { host_port, weight }, ... }
local function load_from_redis()
    local red, err = get_redis()
    if not red then return nil, err end
    local raw, rerr = red:get(REDIS_KEY)
    red:set_keepalive(10000, 100)
    if not raw or raw == ngx.null or raw == "" then
        return {}
    end
    local list, jerr = cjson.decode(raw)
    if not list or not (type(list) == "table") then
        log(WARN, "upstream_redis: invalid JSON for ", REDIS_KEY, " ", tostring(jerr))
        return {}
    end
    local out = {}
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

-- Expand list by weight for round-robin: [ { host_port, weight=4 } ] -> 4 entries of host_port
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

-- Refresh shared dict with current list (JSON-encoded expanded list for round-robin)
local function refresh_shm()
    local dict = shd[SHM_NAME]
    if not dict then return end
    local list, err = load_from_redis()
    if err then
        log(WARN, "upstream_redis: load failed: ", tostring(err))
        return
    end
    local expanded = expand_by_weight(list)
    dict:set("list", cjson.encode(expanded), 0)
    dict:set("updated", ngx.time(), 0)
end

-- Weighted round-robin: increment counter, pick backend from expanded list
function _M.get_backend()
    local dict = shd[SHM_NAME]
    if not dict then
        return DEFAULT_BACKEND
    end
    local raw = dict:get("list")
    if not raw or raw == "" then
        return DEFAULT_BACKEND
    end
    local list = cjson.decode(raw)
    if not list or #list == 0 then
        return DEFAULT_BACKEND
    end
    local idx = dict:incr("round_robin", 1, 0)
    if idx == nil then
        dict:set("round_robin", 1, 0)
        idx = 1
    end
    local host_port = list[(idx - 1) % #list + 1]
    if type(host_port) ~= "string" or host_port == "" then
        return DEFAULT_BACKEND
    end
    return "http://" .. host_port
end

-- Start periodic refresh in init_worker
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
        log(INFO, "upstream_redis: refresh timer started for key ", REDIS_KEY)
    end
end

return _M
