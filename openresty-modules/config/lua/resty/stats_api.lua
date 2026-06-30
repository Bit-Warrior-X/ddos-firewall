local cjson = require "cjson"
local sparta_cli = require "resty.sparta_cli"

local _M = { _VERSION = "1.0.0" }

local function stats_interval()
    local stats_cache = ngx.shared.stats_cache
    return (stats_cache and stats_cache:get("STATS_INTERVAL")) or 60
end

local function current_bucket(interval)
    local current_time = ngx.now()
    return math.floor(current_time / interval) * interval
end

local function respond_json(payload, status)
    ngx.header.content_type = "application/json"
    if status then
        ngx.status = status
    end
    ngx.say(cjson.encode(payload))
end

local function history_lookup(history, timestamp, missing_error)
    if not history then
        respond_json({ error = missing_error }, ngx.HTTP_INTERNAL_SERVER_ERROR)
        return true
    end

    local stats = history:get(tostring(timestamp))
    if stats then
        ngx.header.content_type = "application/json"
        ngx.say(stats)
        return true
    end

    respond_json({ error = missing_error }, ngx.HTTP_NOT_FOUND)
    return true
end

local function live_dimension_stats(opts)
    local stats_cache = ngx.shared.stats_cache
    local interval = stats_interval()
    local bucket = current_bucket(interval)
    local items = {}

    if stats_cache then
        for _, key in ipairs(stats_cache:get_keys(0)) do
            local captured = key:match(opts.key_pattern)
            if captured then
                local count = stats_cache:get(key) or 0
                if count and count > 0 then
                    table.insert(items, opts.build_item(captured, count, stats_cache))
                end
            end
        end
    end

    table.sort(items, opts.sort_fn)
    respond_json({
        timestamp = bucket,
        [opts.response_key] = items,
    })
end

local function dimension_handler(opts)
    local args = ngx.req.get_uri_args()
    local timestamp = args.timestamp

    if timestamp then
        local history = ngx.shared[opts.history_shm]
        if not history then
            respond_json({ error = opts.shm_missing_error }, ngx.HTTP_INTERNAL_SERVER_ERROR)
            return
        end
        history_lookup(history, timestamp, opts.history_missing_error)
        return
    end

    live_dimension_stats(opts)
end

function _M.server_traffic_stats()
    local stats_history = ngx.shared.stats_history
    local args = ngx.req.get_uri_args()
    local timestamp = args.timestamp

    if timestamp then
        local stats = stats_history:get(tostring(timestamp))
        if stats then
            ngx.say(stats)
            return
        end
        ngx.status = ngx.HTTP_NOT_FOUND
        ngx.say(cjson.encode({ error = "No data for timestamp" }))
        return
    end

    local keys = stats_history:get_keys(0)
    if #keys > 0 then
        table.sort(keys, function(a, b)
            return tonumber(a) < tonumber(b)
        end)
        ngx.say(stats_history:get(keys[#keys]))
        return
    end

    ngx.say(cjson.encode({ error = "No statistics available" }))
end

function _M.ip_request_stats()
    dimension_handler({
        history_shm = "ip_stats_history",
        shm_missing_error = "ip_stats_history shared dict not available",
        history_missing_error = "No ip_request_stats data for timestamp",
        key_pattern = "^ip_req_count:(.+)$",
        response_key = "ip_request_stats",
        build_item = function(ip, count)
            return { ip = ip, request_count = count }
        end,
        sort_fn = function(a, b)
            return a.ip < b.ip
        end,
    })
end

function _M.url_request_stats()
    dimension_handler({
        history_shm = "url_stats_history",
        shm_missing_error = "url_stats_history shared dict not available",
        history_missing_error = "No url_request_stats data for timestamp",
        key_pattern = "^url_req_count:(.+)$",
        response_key = "url_request_stats",
        build_item = function(url_path, count)
            return { url = url_path, request_count = count }
        end,
        sort_fn = function(a, b)
            return a.url < b.url
        end,
    })
end

function _M.useragent_request_stats()
    dimension_handler({
        history_shm = "useragent_stats_history",
        shm_missing_error = "useragent_stats_history shared dict not available",
        history_missing_error = "No useragent_request_stats data for timestamp",
        key_pattern = "^ua_req_count:(.+)$",
        response_key = "useragent_request_stats",
        build_item = function(ua, count)
            return { user_agent = ua, request_count = count }
        end,
        sort_fn = function(a, b)
            return a.user_agent < b.user_agent
        end,
    })
end

function _M.country_request_stats()
    dimension_handler({
        history_shm = "country_stats_history",
        shm_missing_error = "country_stats_history shared dict not available",
        history_missing_error = "No country_request_stats data for timestamp",
        key_pattern = "^country_req_count:(.+)$",
        response_key = "country_request_stats",
        build_item = function(country_iso, count, stats_cache)
            return {
                country_iso = country_iso,
                request_count = count,
                block_count = stats_cache:get("block_country_req_count:" .. country_iso) or 0,
            }
        end,
        sort_fn = function(a, b)
            return a.country_iso < b.country_iso
        end,
    })
end

function _M.isp_request_stats()
    dimension_handler({
        history_shm = "isp_stats_history",
        shm_missing_error = "isp_stats_history shared dict not available",
        history_missing_error = "No isp_request_stats data for timestamp",
        key_pattern = "^isp_req_count:(.+)$",
        response_key = "isp_request_stats",
        build_item = function(isp_name, count)
            return { isp = isp_name, request_count = count }
        end,
        sort_fn = function(a, b)
            return a.isp < b.isp
        end,
    })
end

function _M.referer_request_stats()
    dimension_handler({
        history_shm = "referer_stats_history",
        shm_missing_error = "referer_stats_history shared dict not available",
        history_missing_error = "No referer_request_stats data for timestamp",
        key_pattern = "^referer_req_count:(.+)$",
        response_key = "referer_request_stats",
        build_item = function(referer, count)
            return { referer = referer, request_count = count }
        end,
        sort_fn = function(a, b)
            return a.referer < b.referer
        end,
    })
end

local function timestamps_handler(history_shm)
    local history = ngx.shared[history_shm]
    local keys = history:get_keys(0)
    table.sort(keys)
    ngx.say(cjson.encode(keys))
end

function _M.server_traffic_stats_timestamps()
    timestamps_handler("stats_history")
end

function _M.ip_request_stats_timestamps()
    timestamps_handler("ip_stats_history")
end

function _M.url_request_stats_timestamps()
    timestamps_handler("url_stats_history")
end

function _M.useragent_request_stats_timestamps()
    timestamps_handler("useragent_stats_history")
end

function _M.country_request_stats_timestamps()
    timestamps_handler("country_stats_history")
end

function _M.isp_request_stats_timestamps()
    timestamps_handler("isp_stats_history")
end

function _M.referer_request_stats_timestamps()
    timestamps_handler("referer_stats_history")
end

function _M.l4_attack_stats_timestamps()
    local output = sparta_cli.run("sparta_cli TRAFFIC_TIMESTAMPS")
    if not output then
        return
    end

    local timestamps = {}
    for ts in output:gmatch("(%d+)") do
        table.insert(timestamps, tonumber(ts))
    end
    table.sort(timestamps)

    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode(timestamps))
end

local function latest_l4_timestamp()
    local output = sparta_cli.run("sparta_cli TRAFFIC_TIMESTAMPS")
    if not output then
        return nil
    end

    local latest
    for ts in output:gmatch("(%d+)") do
        local num = tonumber(ts)
        if num and (not latest or num > latest) then
            latest = num
        end
    end
    return latest
end

function _M.l4_attack_stats()
    local args = ngx.req.get_uri_args()
    local timestamp = args.timestamp

    if timestamp and tostring(timestamp) ~= "" then
        if not tostring(timestamp):match("^%d+$") then
            respond_json({ error = "invalid timestamp parameter" }, ngx.HTTP_BAD_REQUEST)
            return
        end
    else
        local latest = latest_l4_timestamp()
        if not latest then
            respond_json({ error = "no L4 attack statistics available" }, ngx.HTTP_NOT_FOUND)
            return
        end
        timestamp = tostring(latest)
    end

    local output = sparta_cli.run("sparta_cli TRAFFIC_STATS " .. timestamp)
    if not output then
        return
    end

    local stats_line
    for line in output:gmatch("([^\r\n]+)") do
        if line ~= "" and line ~= "ok" then
            stats_line = line
        end
    end

    if not stats_line then
        respond_json({ error = "no stats returned from sparta_cli" }, ngx.HTTP_INTERNAL_SERVER_ERROR)
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
