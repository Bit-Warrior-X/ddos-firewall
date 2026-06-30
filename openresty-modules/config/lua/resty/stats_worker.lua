local ngx = ngx

local _M = { _VERSION = "1.0.0" }

local FIREWALL_CONFIG_PATH = "/usr/local/share/dorian/sparta/firewall.config"
local STATS_INTERVAL = 60

local nic_dev
local last_nic_rx_bytes
local last_nic_tx_bytes

local STATUS_CODES = { 200, 206, 301, 302, 400, 403, 404, 444, 499, 500, 501, 502, 503, 504, 904, 929, 978 }
local HTTP_METHODS = { "get", "post", "delete", "put", "head", "patch", "options", "others" }

local function detect_nic_dev()
    if nic_dev then
        return nic_dev
    end

    local f, err = io.open(FIREWALL_CONFIG_PATH, "r")
    if not f then
        ngx.log(ngx.WARN, "failed to open firewall.config: ", tostring(err))
        return nil
    end

    for line in f:lines() do
        local dev = line:match("^%s*dev%s*=%s*(%S+)")
        if dev then
            nic_dev = dev
            break
        end
    end
    f:close()

    if not nic_dev then
        ngx.log(ngx.WARN, "no dev=... found in firewall.config")
    else
        ngx.log(ngx.INFO, "detected NIC dev from firewall.config: ", nic_dev)
    end

    return nic_dev
end

local function read_nic_bytes(dev)
    if not dev or dev == "" then
        return nil, nil
    end

    local base = "/sys/class/net/" .. dev .. "/statistics/"

    local function read_counter(name)
        local path = base .. name
        local file = io.open(path, "r")
        if not file then
            return nil
        end
        local v = file:read("*l")
        file:close()
        return tonumber(v)
    end

    return read_counter("rx_bytes"), read_counter("tx_bytes")
end

local function collect_dimension_items(stats_cache, pattern, build_item)
    local items = {}
    local keys = stats_cache:get_keys(0)
    for _, key in ipairs(keys) do
        local captured = key:match(pattern)
        if captured then
            local count = stats_cache:get(key) or 0
            if count and count > 0 then
                table.insert(items, build_item(captured, count, stats_cache))
            end
            stats_cache:delete(key)
        end
    end
    return items
end

local function collect_stats(premature)
    if premature then
        return
    end

    local stats_cache = ngx.shared.stats_cache
    local stats_history = ngx.shared.stats_history

    local lock_key = "collect_stats_lock"
    local lock_ttl = 2
    local ok_lock = stats_cache:add(lock_key, 1, lock_ttl)
    if not ok_lock then
        return
    end

    local current_time = ngx.now()
    local interval = STATS_INTERVAL
    local timestamp = math.floor(current_time / interval) * interval

    local nic_rx_delta = 0
    local nic_tx_delta = 0

    local dev = detect_nic_dev()
    if dev then
        local cur_rx, cur_tx = read_nic_bytes(dev)
        if cur_rx and cur_tx then
            if last_nic_rx_bytes and last_nic_tx_bytes then
                if cur_rx >= last_nic_rx_bytes then
                    nic_rx_delta = cur_rx - last_nic_rx_bytes
                end
                if cur_tx >= last_nic_tx_bytes then
                    nic_tx_delta = cur_tx - last_nic_tx_bytes
                end
            end
            last_nic_rx_bytes = cur_rx
            last_nic_tx_bytes = cur_tx
        end
    end

    local bandwidth_l7_rx_total = tonumber(stats_cache:get("bandwidth_l7_rx")) or 0
    local bandwidth_l7_tx_total = tonumber(stats_cache:get("bandwidth_l7_tx")) or 0
    local bandwidth_l7_rx_per_interval = bandwidth_l7_rx_total * 8 / interval
    local bandwidth_l7_tx_per_interval = bandwidth_l7_tx_total * 8 / interval
    local bandwidth_nic_rx_per_interval = nic_rx_delta * 8 / interval
    local bandwidth_nic_tx_per_interval = nic_tx_delta * 8 / interval

    local stats = {
        timestamp = timestamp,
        traffic_nic_rx = nic_rx_delta,
        traffic_nic_tx = nic_tx_delta,
        traffic_l7_rx = stats_cache:get("traffic_l7_rx") or 0,
        traffic_l7_tx = stats_cache:get("traffic_l7_tx") or 0,
        bandwidth_nic_rx = bandwidth_nic_rx_per_interval,
        bandwidth_nic_tx = bandwidth_nic_tx_per_interval,
        bandwidth_l7_rx = bandwidth_l7_rx_per_interval,
        bandwidth_l7_tx = bandwidth_l7_tx_per_interval,
        request_count = stats_cache:get("request_count") or 0,
        response_count = stats_cache:get("response_count") or 0,
        blocked_request_count = stats_cache:get("blocked_request_count") or 0,
        ip_count = stats_cache:get("ip_count") or 0,
        blocked_ip_count = stats_cache:get("blocked_ip_count") or 0,
        code200 = stats_cache:get("code200") or 0,
        code206 = stats_cache:get("code206") or 0,
        code301 = stats_cache:get("code301") or 0,
        code302 = stats_cache:get("code302") or 0,
        code400 = stats_cache:get("code400") or 0,
        code403 = stats_cache:get("code403") or 0,
        code404 = stats_cache:get("code404") or 0,
        code444 = stats_cache:get("code444") or 0,
        code499 = stats_cache:get("code499") or 0,
        code500 = stats_cache:get("code500") or 0,
        code501 = stats_cache:get("code501") or 0,
        code502 = stats_cache:get("code502") or 0,
        code503 = stats_cache:get("code503") or 0,
        code504 = stats_cache:get("code504") or 0,
        code904 = stats_cache:get("code904") or 0,
        code929 = stats_cache:get("code929") or 0,
        code978 = stats_cache:get("code978") or 0,
        get_count = stats_cache:get("get_count") or 0,
        post_count = stats_cache:get("post_count") or 0,
        delete_count = stats_cache:get("delete_count") or 0,
        put_count = stats_cache:get("put_count") or 0,
        head_count = stats_cache:get("head_count") or 0,
        patch_count = stats_cache:get("patch_count") or 0,
        options_count = stats_cache:get("options_count") or 0,
        others_count = stats_cache:get("others_count") or 0,
        http1_0_count = stats_cache:get("http1_0_count") or 0,
        http1_1_count = stats_cache:get("http1_1_count") or 0,
        http2_count = stats_cache:get("http2_count") or 0,
        http3_count = stats_cache:get("http3_count") or 0,
    }

    local ip_items = collect_dimension_items(stats_cache, "^ip_req_count:(.+)$", function(ip, count)
        return { ip = ip, request_count = count }
    end)
    local url_items = collect_dimension_items(stats_cache, "^url_req_count:(.+)$", function(url_path, count)
        return { url = url_path, request_count = count }
    end)
    local ua_items = collect_dimension_items(stats_cache, "^ua_req_count:(.+)$", function(ua, count)
        return { user_agent = ua, request_count = count }
    end)
    local country_items = collect_dimension_items(stats_cache, "^country_req_count:(.+)$", function(country_iso, count)
        return { country_iso = country_iso, request_count = count }
    end)
    local isp_items = collect_dimension_items(stats_cache, "^isp_req_count:(.+)$", function(isp_name, count)
        return { isp = isp_name, request_count = count }
    end)
    local referer_items = collect_dimension_items(stats_cache, "^referer_req_count:(.+)$", function(referer, count)
        return { referer = referer, request_count = count }
    end)

    local ok_j, cjson = pcall(require, "cjson.safe")
    if ok_j and cjson and cjson.encode then
        stats_history:set(tostring(timestamp), cjson.encode(stats))

        local interval_start = timestamp - interval
        local history_payloads = {
            { shm = ngx.shared.ip_stats_history, key = "ip_request_stats", items = ip_items },
            { shm = ngx.shared.url_stats_history, key = "url_request_stats", items = url_items },
            { shm = ngx.shared.useragent_stats_history, key = "useragent_request_stats", items = ua_items },
            { shm = ngx.shared.country_stats_history, key = "country_request_stats", items = country_items },
            { shm = ngx.shared.isp_stats_history, key = "isp_request_stats", items = isp_items },
            { shm = ngx.shared.referer_stats_history, key = "referer_request_stats", items = referer_items },
        }

        for _, payload in ipairs(history_payloads) do
            if payload.shm then
                payload.shm:set(tostring(interval_start), cjson.encode({
                    timestamp = interval_start,
                    [payload.key] = payload.items,
                }))
            end
        end
    end

    stats_cache:set("traffic_nic_rx", 0)
    stats_cache:set("traffic_nic_tx", 0)
    stats_cache:set("traffic_l7_rx", 0)
    stats_cache:set("traffic_l7_tx", 0)
    stats_cache:set("bandwidth_nic_rx", 0)
    stats_cache:set("bandwidth_nic_tx", 0)
    stats_cache:set("bandwidth_l7_rx", 0)
    stats_cache:set("bandwidth_l7_tx", 0)
    stats_cache:set("request_count", 0)
    stats_cache:set("response_count", 0)
    stats_cache:set("blocked_request_count", 0)
    stats_cache:set("ip_count", 0)
    stats_cache:set("blocked_ip_count", 0)

    for _, code in ipairs(STATUS_CODES) do
        stats_cache:set("code" .. code, 0)
    end

    for _, method in ipairs(HTTP_METHODS) do
        stats_cache:set(method .. "_count", 0)
    end

    stats_cache:set("http1_0_count", 0)
    stats_cache:set("http1_1_count", 0)
    stats_cache:set("http2_count", 0)
    stats_cache:set("http3_count", 0)

    local last_count = tonumber(24 * 3600 / STATS_INTERVAL) + 1 or 300
    local history_keys = stats_history:get_keys(last_count)
    local cutoff = current_time - (24 * 3600)
    for _, key in ipairs(history_keys) do
        local ts = tonumber(key)
        if ts and ts < cutoff then
            stats_history:delete(key)
        end
    end
end

function _M.start()
    local stats_cache = ngx.shared.stats_cache
    if stats_cache then
        stats_cache:set("STATS_INTERVAL", STATS_INTERVAL)
    end

    local ok, err = ngx.timer.every(STATS_INTERVAL, collect_stats)
    if not ok then
        ngx.log(ngx.ERR, "Failed to create timer: ", err)
    end
end

return _M
