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

local function request_site_id_filter()
    local args = ngx.req.get_uri_args()
    local raw = args.siteId or args.site_id
    if raw == nil or raw == "" then
        return nil
    end
    return tostring(raw)
end

local function live_dimension_stats(opts)
    local stats_cache = ngx.shared.stats_cache
    local interval = stats_interval()
    local bucket = current_bucket(interval)
    local items = {}
    local site_filter = opts.site_id

    if stats_cache then
        for _, key in ipairs(stats_cache:get_keys(0)) do
            local site_id, captured = key:match(opts.key_pattern)
            if captured and (not site_filter or site_id == site_filter) then
                local count = stats_cache:get(key) or 0
                if count and count > 0 then
                    table.insert(items, opts.build_item(site_id, captured, count, stats_cache))
                end
            end
        end
    end

    table.sort(items, opts.sort_fn)
    local payload = {
        timestamp = bucket,
        [opts.response_key] = items,
    }
    if site_filter then
        payload.site_id = tonumber(site_filter) or 0
    end
    respond_json(payload)
end

local function filter_history_items(encoded, response_key, site_filter)
    if not site_filter then
        return encoded
    end
    local obj = cjson.decode(encoded)
    if type(obj) ~= "table" or type(obj[response_key]) ~= "table" then
        return encoded
    end
    local want = tonumber(site_filter)
    local filtered = {}
    for _, item in ipairs(obj[response_key]) do
        if tonumber(item.site_id) == want then
            table.insert(filtered, item)
        end
    end
    obj[response_key] = filtered
    obj.site_id = want
    return cjson.encode(obj)
end

local function dimension_handler(opts)
    local args = ngx.req.get_uri_args()
    local timestamp = args.timestamp
    opts.site_id = request_site_id_filter()

    if timestamp then
        local history = ngx.shared[opts.history_shm]
        if not history then
            respond_json({ error = opts.shm_missing_error }, ngx.HTTP_INTERNAL_SERVER_ERROR)
            return
        end
        local stats = history:get(tostring(timestamp))
        if not stats then
            respond_json({ error = opts.history_missing_error }, ngx.HTTP_NOT_FOUND)
            return
        end
        ngx.header.content_type = "application/json"
        ngx.say(filter_history_items(stats, opts.response_key, opts.site_id))
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

local DISPATCH_BLOCKLIST = {
    dispatch = true,
    dispatch_timestamps = true,
}

function _M.dispatch()
    local name = ngx.var.stats_endpoint
    local fn = name and _M[name]
    if type(fn) ~= "function" or DISPATCH_BLOCKLIST[name] then
        respond_json({ error = "unknown stats endpoint" }, ngx.HTTP_NOT_FOUND)
        return
    end
    fn()
end

function _M.dispatch_timestamps()
    local name = ngx.var.stats_endpoint
    local fn = name and _M[name .. "_timestamps"]
    if type(fn) ~= "function" then
        respond_json({ error = "unknown stats timestamps endpoint" }, ngx.HTTP_NOT_FOUND)
        return
    end
    fn()
end

function _M.ip_request_stats()
    dimension_handler({
        history_shm = "ip_stats_history",
        shm_missing_error = "ip_stats_history shared dict not available",
        history_missing_error = "No ip_request_stats data for timestamp",
        key_pattern = "^ip_req_count:(%d+):(.+)$",
        response_key = "ip_request_stats",
        build_item = function(site_id, ip, count)
            return { site_id = tonumber(site_id) or 0, ip = ip, request_count = count }
        end,
        sort_fn = function(a, b)
            if a.site_id == b.site_id then
                return a.ip < b.ip
            end
            return a.site_id < b.site_id
        end,
    })
end

function _M.url_request_stats()
    dimension_handler({
        history_shm = "url_stats_history",
        shm_missing_error = "url_stats_history shared dict not available",
        history_missing_error = "No url_request_stats data for timestamp",
        key_pattern = "^url_req_count:(%d+):(.+)$",
        response_key = "url_request_stats",
        build_item = function(site_id, url_path, count)
            return { site_id = tonumber(site_id) or 0, url = url_path, request_count = count }
        end,
        sort_fn = function(a, b)
            if a.site_id == b.site_id then
                return a.url < b.url
            end
            return a.site_id < b.site_id
        end,
    })
end

function _M.useragent_request_stats()
    dimension_handler({
        history_shm = "useragent_stats_history",
        shm_missing_error = "useragent_stats_history shared dict not available",
        history_missing_error = "No useragent_request_stats data for timestamp",
        key_pattern = "^ua_req_count:(%d+):(.+)$",
        response_key = "useragent_request_stats",
        build_item = function(site_id, ua, count)
            return { site_id = tonumber(site_id) or 0, user_agent = ua, request_count = count }
        end,
        sort_fn = function(a, b)
            if a.site_id == b.site_id then
                return a.user_agent < b.user_agent
            end
            return a.site_id < b.site_id
        end,
    })
end

function _M.country_request_stats()
    dimension_handler({
        history_shm = "country_stats_history",
        shm_missing_error = "country_stats_history shared dict not available",
        history_missing_error = "No country_request_stats data for timestamp",
        key_pattern = "^country_req_count:(%d+):(.+)$",
        response_key = "country_request_stats",
        build_item = function(site_id, country_iso, count, stats_cache)
            return {
                site_id = tonumber(site_id) or 0,
                country_iso = country_iso,
                request_count = count,
                block_count = stats_cache:get("block_country_req_count:" .. site_id .. ":" .. country_iso) or 0,
            }
        end,
        sort_fn = function(a, b)
            if a.site_id == b.site_id then
                return a.country_iso < b.country_iso
            end
            return a.site_id < b.site_id
        end,
    })
end

function _M.isp_request_stats()
    dimension_handler({
        history_shm = "isp_stats_history",
        shm_missing_error = "isp_stats_history shared dict not available",
        history_missing_error = "No isp_request_stats data for timestamp",
        key_pattern = "^isp_req_count:(%d+):(.+)$",
        response_key = "isp_request_stats",
        build_item = function(site_id, isp_name, count)
            return { site_id = tonumber(site_id) or 0, isp = isp_name, request_count = count }
        end,
        sort_fn = function(a, b)
            if a.site_id == b.site_id then
                return a.isp < b.isp
            end
            return a.site_id < b.site_id
        end,
    })
end

function _M.referer_request_stats()
    dimension_handler({
        history_shm = "referer_stats_history",
        shm_missing_error = "referer_stats_history shared dict not available",
        history_missing_error = "No referer_request_stats data for timestamp",
        key_pattern = "^referer_req_count:(%d+):(.+)$",
        response_key = "referer_request_stats",
        build_item = function(site_id, referer, count)
            return { site_id = tonumber(site_id) or 0, referer = referer, request_count = count }
        end,
        sort_fn = function(a, b)
            if a.site_id == b.site_id then
                return a.referer < b.referer
            end
            return a.site_id < b.site_id
        end,
    })
end

function _M.domain_request_stats()
    dimension_handler({
        history_shm = "domain_stats_history",
        shm_missing_error = "domain_stats_history shared dict not available",
        history_missing_error = "No domain_request_stats data for timestamp",
        key_pattern = "^domain_req_count:(%d+):(.+)$",
        response_key = "domain_request_stats",
        build_item = function(site_id, domain, count, stats_cache)
            local interval = stats_interval()
            local rx = tonumber(stats_cache:get("domain_rx:" .. site_id .. ":" .. domain)) or 0
            local tx = tonumber(stats_cache:get("domain_tx:" .. site_id .. ":" .. domain)) or 0
            return {
                site_id = tonumber(site_id) or 0,
                domain = domain,
                request_count = count,
                traffic_l7_rx = rx,
                traffic_l7_tx = tx,
                bandwidth_l7_rx = rx * 8 / interval,
                bandwidth_l7_tx = tx * 8 / interval,
            }
        end,
        sort_fn = function(a, b)
            if a.site_id == b.site_id then
                return a.domain < b.domain
            end
            return a.site_id < b.site_id
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

function _M.domain_request_stats_timestamps()
    timestamps_handler("domain_stats_history")
end

local function live_site_traffic_stats(site_filter)
    local stats_worker = require "resty.stats_worker"
    local stats_cache = ngx.shared.stats_cache
    local interval = stats_interval()
    local sites = {}
    if stats_cache then
        for _, key in ipairs(stats_cache:get_keys(0)) do
            local sid, rest = key:match("^s:(%d+):(.+)$")
            if sid and rest and not rest:find("^seen_ip:") and not rest:find("^blocked_ip:") then
                if not site_filter or sid == site_filter then
                    local row = sites[sid]
                    if not row then
                        row = stats_worker.empty_site_row(sid)
                        sites[sid] = row
                    end
                    local val = tonumber(stats_cache:get(key)) or 0
                    if row[rest] ~= nil or rest:match("^code%d+$") then
                        row[rest] = val
                    end
                end
            end
        end
    end

    local items = {}
    for _, row in pairs(sites) do
        local rx = tonumber(row.traffic_l7_rx) or 0
        local tx = tonumber(row.traffic_l7_tx) or 0
        row.traffic_l7_rx = rx
        row.traffic_l7_tx = tx
        row.bandwidth_l7_rx = rx * 8 / interval
        row.bandwidth_l7_tx = tx * 8 / interval
        table.insert(items, row)
    end
    table.sort(items, function(a, b)
        return a.site_id < b.site_id
    end)

    local payload = {
        timestamp = current_bucket(interval),
        site_traffic_stats = items,
    }
    if site_filter then
        payload.site_id = tonumber(site_filter) or 0
    end
    respond_json(payload)
end

function _M.site_traffic_stats()
    local site_filter = request_site_id_filter()
    local args = ngx.req.get_uri_args()
    local timestamp = args.timestamp

    if timestamp then
        local history = ngx.shared.site_stats_history
        if not history then
            respond_json({ error = "site_stats_history shared dict not available" }, ngx.HTTP_INTERNAL_SERVER_ERROR)
            return
        end
        local stats = history:get(tostring(timestamp))
        if not stats then
            respond_json({ error = "No site_traffic_stats data for timestamp" }, ngx.HTTP_NOT_FOUND)
            return
        end
        ngx.header.content_type = "application/json"
        ngx.say(filter_history_items(stats, "site_traffic_stats", site_filter))
        return
    end

    live_site_traffic_stats(site_filter)
end

function _M.site_traffic_stats_timestamps()
    timestamps_handler("site_stats_history")
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
