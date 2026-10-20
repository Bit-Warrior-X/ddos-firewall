local cjson = require "cjson.safe"
local sparta_cli = require "resty.sparta_cli"
local stats_worker = require "resty.stats_worker"

local _M = { _VERSION = "1.3.0" }

local function stats_interval()
    local stats_cache = ngx.shared.stats_cache
    return (stats_cache and stats_cache:get("STATS_INTERVAL")) or 60
end

local function current_bucket(interval)
    return math.floor(ngx.now() / interval) * interval
end

local function as_array(items)
    if type(items) ~= "table" or #items == 0 then
        return cjson.empty_array
    end
    return items
end

local function respond_json(payload, status)
    ngx.header.content_type = "application/json"
    if status then
        ngx.status = status
    end
    ngx.say(cjson.encode(payload))
end

local function respond_error(status, message)
    respond_json({ error = message }, status)
end

local function request_site_id_filter()
    local args = ngx.req.get_uri_args()
    local raw = args.siteId or args.site_id
    if raw == nil or raw == "" or type(raw) == "table" or raw == true then
        return nil
    end
    return tostring(raw)
end

--- Returns the timestamp string, nil when absent, or false after a 400 was sent.
local function request_timestamp()
    local raw = ngx.req.get_uri_args().timestamp
    if raw == nil or raw == "" then
        return nil
    end
    if type(raw) ~= "string" or not raw:match("^%d+$") then
        respond_error(ngx.HTTP_BAD_REQUEST, "Invalid timestamp")
        return false
    end
    return raw
end

local function request_wants_live()
    local live = ngx.req.get_uri_args().live
    return live == true or live == "1" or live == "true"
end

local function history_shm(name)
    return ngx.shared[stats_worker.HISTORY_SHMS[name]]
end

--- History keys for buckets that have fully closed, oldest first.
local function closed_keys(shm)
    local interval = stats_interval()
    local open_bucket = current_bucket(interval)
    local keys = {}
    for _, key in ipairs(shm:get_keys(0)) do
        local ts = tonumber(key)
        if ts and ts < open_bucket then
            keys[#keys + 1] = key
        end
    end
    table.sort(keys, function(a, b)
        return tonumber(a) < tonumber(b)
    end)
    return keys
end

local function respond_history_payload(encoded, name, site_filter)
    if not site_filter then
        ngx.header.content_type = "application/json"
        ngx.say(encoded)
        return
    end
    local obj = cjson.decode(encoded)
    if type(obj) ~= "table" then
        respond_error(ngx.HTTP_INTERNAL_SERVER_ERROR, "corrupt " .. name .. " history")
        return
    end
    local want = tonumber(site_filter)
    local filtered = {}
    for _, item in ipairs(type(obj[name]) == "table" and obj[name] or {}) do
        if tonumber(item.site_id) == want then
            filtered[#filtered + 1] = item
        end
    end
    obj[name] = as_array(filtered)
    obj.site_id = want
    respond_json(obj)
end

local function respond_live(name, build)
    local stats_cache = ngx.shared.stats_cache
    local interval = stats_interval()
    local bucket = current_bucket(interval)
    local elapsed = math.max(ngx.now() - bucket, 1)
    local site_filter = request_site_id_filter()
    local items = {}
    if stats_cache then
        items = build(stats_cache, stats_cache:get_keys(0), elapsed, site_filter)
    end
    local payload = {
        timestamp = bucket,
        [name] = as_array(items),
    }
    if site_filter then
        payload.site_id = tonumber(site_filter) or 0
    end
    respond_json(payload)
end

--- `default`: "latest" (newest closed bucket, live fallback) or "live" (bucket being filled).
local function history_endpoint(name, default, build_live)
    local ts = request_timestamp()
    if ts == false then
        return
    end
    local site_filter = request_site_id_filter()
    local shm = history_shm(name)

    if ts then
        if not shm then
            respond_error(ngx.HTTP_INTERNAL_SERVER_ERROR, stats_worker.HISTORY_SHMS[name] .. " shared dict not available")
            return
        end
        local encoded = shm:get(ts)
        if not encoded then
            respond_error(ngx.HTTP_NOT_FOUND, "No data found for timestamp " .. ts)
            return
        end
        respond_history_payload(encoded, name, site_filter)
        return
    end

    if default == "latest" and not request_wants_live() and shm then
        local keys = closed_keys(shm)
        if #keys > 0 then
            respond_history_payload(shm:get(keys[#keys]), name, site_filter)
            return
        end
    end

    respond_live(name, build_live)
end

local function sort_by_site_then(field)
    return function(a, b)
        if a.site_id == b.site_id then
            return tostring(a[field]) < tostring(b[field])
        end
        return a.site_id < b.site_id
    end
end

function _M.server_traffic_stats()
    local ts = request_timestamp()
    if ts == false then
        return
    end
    local shm = history_shm("server_traffic_stats")
    if ts then
        local encoded = shm:get(ts)
        if not encoded then
            respond_error(ngx.HTTP_NOT_FOUND, "No data found for timestamp " .. ts)
            return
        end
        ngx.header.content_type = "application/json"
        ngx.say(encoded)
        return
    end

    local keys = closed_keys(shm)
    if #keys == 0 then
        respond_error(ngx.HTTP_NOT_FOUND, "No statistics available")
        return
    end
    ngx.header.content_type = "application/json"
    ngx.say(shm:get(keys[#keys]))
end

function _M.site_traffic_stats()
    history_endpoint("site_traffic_stats", "live", function(cache, keys, elapsed, site_filter)
        return stats_worker.collect_site_items(cache, keys, elapsed, false, site_filter)
    end)
end

function _M.domain_request_stats()
    history_endpoint("domain_request_stats", "latest", function(cache, keys, elapsed, site_filter)
        return stats_worker.collect_domain_items(cache, keys, elapsed, false, site_filter)
    end)
end

for name, dim in pairs(stats_worker.DIMENSIONS) do
    _M[name] = function()
        history_endpoint(name, "latest", function(cache, keys, _, site_filter)
            local items = stats_worker.collect_dimension_items(cache, keys, dim.pattern, dim.build, false, site_filter)
            table.sort(items, sort_by_site_then(dim.field))
            return items
        end)
    end
end

function _M.content_type_request_stats()
    history_endpoint("content_type_request_stats", "latest", function(cache, keys, _, site_filter)
        return stats_worker.collect_content_type_items(cache, keys, false, site_filter)
    end)
end

function _M.cache_miss_url_stats()
    history_endpoint("cache_miss_url_stats", "latest", function(cache, keys, _, site_filter)
        return stats_worker.collect_cache_miss_url_items(cache, keys, false, site_filter)
    end)
end

function _M.block_reason_stats()
    history_endpoint("block_reason_stats", "latest", function(cache, keys, _, site_filter)
        return stats_worker.collect_block_reason_items(cache, keys, false, site_filter)
    end)
end

for name in pairs(stats_worker.HISTORY_SHMS) do
    _M[name .. "_timestamps"] = function()
        local shm = history_shm(name)
        if not shm then
            respond_error(ngx.HTTP_INTERNAL_SERVER_ERROR, stats_worker.HISTORY_SHMS[name] .. " shared dict not available")
            return
        end
        respond_json(as_array(closed_keys(shm)))
    end
end

function _M.access_logs()
    require("resty.access_logs").handle()
end

local DISPATCH_BLOCKLIST = {
    dispatch = true,
    dispatch_timestamps = true,
}

function _M.dispatch()
    local name = ngx.var.stats_endpoint
    local fn = name and _M[name]
    if type(fn) ~= "function" or DISPATCH_BLOCKLIST[name] then
        respond_error(ngx.HTTP_NOT_FOUND, "unknown stats endpoint")
        return
    end
    fn()
end

function _M.dispatch_timestamps()
    local name = ngx.var.stats_endpoint
    local fn = name and _M[name .. "_timestamps"]
    if type(fn) ~= "function" then
        respond_error(ngx.HTTP_NOT_FOUND, "unknown stats timestamps endpoint")
        return
    end
    fn()
end

local function l4_timestamps()
    local output = sparta_cli.run("sparta_cli TRAFFIC_TIMESTAMPS")
    if not output then
        return nil
    end
    local timestamps = {}
    for ts in output:gmatch("(%d+)") do
        timestamps[#timestamps + 1] = tonumber(ts)
    end
    table.sort(timestamps)
    return timestamps
end

function _M.l4_attack_stats_timestamps()
    local timestamps = l4_timestamps()
    if not timestamps then
        return
    end
    local out = {}
    for i, ts in ipairs(timestamps) do
        out[i] = tostring(ts)
    end
    respond_json(as_array(out))
end

function _M.l4_attack_stats()
    local timestamp = request_timestamp()
    if timestamp == false then
        return
    end

    if not timestamp then
        local timestamps = l4_timestamps()
        if not timestamps then
            return
        end
        if #timestamps == 0 then
            respond_error(ngx.HTTP_NOT_FOUND, "No L4 attack statistics available")
            return
        end
        timestamp = tostring(timestamps[#timestamps])
    end

    local output, err = sparta_cli.capture("sparta_cli TRAFFIC_STATS " .. timestamp)
    if err then
        if output and output:find("No data found") then
            respond_error(ngx.HTTP_NOT_FOUND, "No data found for timestamp " .. timestamp)
        else
            respond_json({ error = err, details = output }, ngx.HTTP_INTERNAL_SERVER_ERROR)
        end
        return
    end

    local stats_line
    for line in output:gmatch("([^\r\n]+)") do
        if line ~= "" and line ~= "ok" then
            stats_line = line
        end
    end

    if not stats_line then
        respond_error(ngx.HTTP_INTERNAL_SERVER_ERROR, "no stats returned from sparta_cli")
        return
    end

    local stats = {}
    for key, value in stats_line:gmatch("(%w+):(%d+)") do
        stats[key] = tonumber(value)
    end

    respond_json({
        timestamp = tonumber(timestamp),
        stats = stats,
    })
end

return _M
