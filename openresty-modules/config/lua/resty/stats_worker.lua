local ngx = ngx
local req_status = require "resty.req_status"

local _M = { _VERSION = "1.0.0" }

local FIREWALL_CONFIG_PATH = "/usr/local/share/dorian/sparta/firewall.config"
local STATS_INTERVAL = 60

local STATUS_CODES = { 200, 206, 301, 302, 400, 403, 404, 444, 499, 500, 501, 502, 503, 504, 904, 929, 978 }
local HTTP_METHODS = { "get", "post", "delete", "put", "head", "patch", "options", "others" }

local function valid_dev_name(dev)
    return type(dev) == "string" and dev:match("^[%w%._%-]+$") ~= nil
end

local function iface_exists(dev)
    if not valid_dev_name(dev) then
        return false
    end
    local f = io.open("/sys/class/net/" .. dev .. "/statistics/rx_bytes", "r")
    if not f then
        return false
    end
    f:close()
    return true
end

local function iface_up(dev)
    if not valid_dev_name(dev) then
        return false
    end
    local f = io.open("/sys/class/net/" .. dev .. "/operstate", "r")
    if not f then
        return false
    end
    local state = (f:read("*l") or ""):lower()
    f:close()
    return state == "up" or state == "unknown"
end

local function is_bond_slave(dev)
    if not valid_dev_name(dev) then
        return false
    end
    local f = io.open("/sys/class/net/" .. dev .. "/bonding_slave/state", "r")
    if not f then
        return false
    end
    f:close()
    return true
end

local function bond_master_of(slave)
    local f = io.open("/proc/net/dev", "r")
    if not f then
        return nil
    end
    local ifaces = {}
    for line in f:lines() do
        local name = line:match("^%s*([^:%s]+):")
        if name and name ~= "lo" then
            ifaces[#ifaces + 1] = name
        end
    end
    f:close()

    for _, iface in ipairs(ifaces) do
        if valid_dev_name(iface) then
            local slaves = io.open("/sys/class/net/" .. iface .. "/bonding/slaves", "r")
            if slaves then
                local text = slaves:read("*a") or ""
                slaves:close()
                for name in text:gmatch("%S+") do
                    if name == slave then
                        return iface
                    end
                end
            end
        end
    end
    return nil
end

local function default_route_dev()
    local f = io.open("/proc/net/route", "r")
    if not f then
        return nil
    end
    local best, best_metric
    for line in f:lines() do
        local iface, dest, metric = line:match("^(%S+)%s+(%x+)%s+%x+%s+%x+%s+%d+%s+%d+%s+(%d+)")
        if iface and dest == "00000000" and iface ~= "lo" and valid_dev_name(iface) then
            metric = tonumber(metric) or 0
            if not best or metric < best_metric then
                best = iface
                best_metric = metric
            end
        end
    end
    f:close()
    return best
end

local function read_configured_dev()
    local f, err = io.open(FIREWALL_CONFIG_PATH, "r")
    if not f then
        return nil, "failed to open firewall.config: " .. tostring(err)
    end

    local dev
    for line in f:lines() do
        local raw = line:match("^%s*dev%s*=%s*(%S+)")
        if raw then
            dev = raw
            break
        end
    end
    f:close()

    if not dev then
        return nil, "no dev=... found in firewall.config"
    end
    if not valid_dev_name(dev) then
        return nil, "invalid dev name in firewall.config"
    end
    return dev
end

--- Prefer an up firewall dev. A bond slave is reported via its master so member
--- counters are not mistaken for host throughput. A down dev falls back to the
--- default-route interface (the NIC that is actually carrying traffic).
local function resolve_nic_dev()
    local configured, err = read_configured_dev()
    if configured then
        if is_bond_slave(configured) then
            local master = bond_master_of(configured)
            if master and iface_up(master) then
                return configured, master, "firewall dev is a bond slave"
            end
        end
        if iface_up(configured) then
            return configured, configured, nil
        end
    end

    local route_dev = default_route_dev()
    if route_dev and iface_up(route_dev) then
        local reason = err
        if configured then
            reason = "firewall dev " .. configured .. " is down"
        end
        return configured, route_dev, reason
    end

    if configured and iface_exists(configured) then
        return configured, configured, nil
    end
    return configured, nil, err or "no usable NIC"
end

local function note_nic_choice(stats_cache, configured, chosen, reason)
    if not stats_cache or not chosen then
        return
    end
    local marker = chosen .. "|" .. (reason or "")
    if stats_cache:get("nic_dev_logged") == marker then
        return
    end
    stats_cache:set("nic_dev_logged", marker)
    if reason then
        ngx.log(ngx.WARN, "NIC stats using ", chosen, " (", reason, "); firewall.config dev=", tostring(configured))
    else
        ngx.log(ngx.INFO, "NIC stats using ", chosen)
    end
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
        local site_id, captured = key:match(pattern)
        if captured then
            local count = stats_cache:get(key) or 0
            if count and count > 0 then
                table.insert(items, build_item(site_id, captured, count, stats_cache))
            end
            stats_cache:delete(key)
        end
    end
    return items
end

local function collect_domain_items(stats_cache, interval)
    local domain_bw = req_status.domain_bandwidth()
    local domains = {}
    local keys = stats_cache:get_keys(0)
    for _, key in ipairs(keys) do
        local kind, sid, domain = "req_count", key:match("^domain_req_count:(%d+):(.+)$")
        if not domain then
            kind, sid, domain = "rx", key:match("^domain_rx:(%d+):(.+)$")
        end
        if not domain then
            kind, sid, domain = "tx", key:match("^domain_tx:(%d+):(.+)$")
        end
        if domain then
            local row_key = sid .. "\0" .. domain
            local row = domains[row_key]
            if not row then
                row = {
                    site_id = tonumber(sid) or 0,
                    domain = domain,
                    request_count = 0,
                    traffic_l7_rx = 0,
                    traffic_l7_tx = 0,
                }
                domains[row_key] = row
            end
            local val = tonumber(stats_cache:get(key)) or 0
            if kind == "req_count" then
                row.request_count = val
            elseif kind == "rx" then
                row.traffic_l7_rx = val
            else
                row.traffic_l7_tx = val
            end
            stats_cache:delete(key)
        end
    end

    local items = {}
    for _, row in pairs(domains) do
        if row.request_count > 0 or row.traffic_l7_rx > 0 or row.traffic_l7_tx > 0 then
            local host = tostring(row.domain or ""):lower()
            row.bandwidth_l7_rx = row.traffic_l7_rx * 8 / interval
            -- Egress bandwidth from ngx_req_status (bits/s), not interval average.
            row.bandwidth_l7_tx = tonumber(domain_bw[host]) or 0
            table.insert(items, row)
        end
    end
    return items
end

local function empty_site_row(site_id)
    return {
        site_id = tonumber(site_id) or 0,
        traffic_l7_rx = 0,
        traffic_l7_tx = 0,
        bandwidth_l7_rx = 0,
        bandwidth_l7_tx = 0,
        request_count = 0,
        response_count = 0,
        blocked_request_count = 0,
        ip_count = 0,
        blocked_ip_count = 0,
        cache_hit_count = 0,
        cache_miss_count = 0,
        cache_bypass_count = 0,
        cache_hit_ratio = 0,
        code200 = 0, code206 = 0, code301 = 0, code302 = 0,
        code400 = 0, code403 = 0, code404 = 0, code444 = 0, code499 = 0,
        code500 = 0, code501 = 0, code502 = 0, code503 = 0, code504 = 0,
        code904 = 0, code929 = 0, code978 = 0,
        get_count = 0, post_count = 0, delete_count = 0, put_count = 0,
        head_count = 0, patch_count = 0, options_count = 0, others_count = 0,
        http1_0_count = 0, http1_1_count = 0, http2_count = 0, http3_count = 0,
    }
end

--- cache_hit_ratio = hits / (hits + misses); bypass/nocache excluded from denominator.
function _M.apply_cache_hit_ratio(row)
    local hits = tonumber(row.cache_hit_count) or 0
    local misses = tonumber(row.cache_miss_count) or 0
    local denom = hits + misses
    if denom > 0 then
        row.cache_hit_ratio = hits / denom
    else
        row.cache_hit_ratio = 0
    end
    return row
end

function _M.empty_site_row(site_id)
    return empty_site_row(site_id)
end

local function collect_site_traffic_items(stats_cache, interval)
    local site_bw = req_status.site_bandwidth()
    local sites = {}
    local keys = stats_cache:get_keys(0)
    for _, key in ipairs(keys) do
        local sid, rest = key:match("^s:(%d+):(.+)$")
        if sid and rest and not rest:find("^seen_ip:") and not rest:find("^blocked_ip:") then
            local row = sites[sid]
            if not row then
                row = empty_site_row(sid)
                sites[sid] = row
            end
            local val = tonumber(stats_cache:get(key)) or 0
            -- Keep known L7 fields; also accept any HTTP status code counter.
            if row[rest] ~= nil or rest:match("^code%d+$") then
                row[rest] = val
            end
            stats_cache:delete(key)
        end
    end

    for sid, bw in pairs(site_bw) do
        if bw > 0 and not sites[sid] then
            sites[sid] = empty_site_row(sid)
        end
    end

    local items = {}
    for sid, row in pairs(sites) do
        row.bandwidth_l7_rx = (tonumber(row.traffic_l7_rx) or 0) * 8 / interval
        -- Real-time egress bandwidth from ngx_req_status (bits/s per site).
        row.bandwidth_l7_tx = tonumber(site_bw[tostring(sid)]) or 0
        _M.apply_cache_hit_ratio(row)
        table.insert(items, row)
    end
    table.sort(items, function(a, b)
        return a.site_id < b.site_id
    end)
    return items
end

local function collect_stats(premature)
    if premature then
        return
    end

    local stats_cache = ngx.shared.stats_cache
    local stats_history = ngx.shared.stats_history

    local current_time = ngx.now()
    local interval = STATS_INTERVAL
    local timestamp = math.floor(current_time / interval) * interval

    -- One collector per interval. A 2s lock let a later worker overwrite the
    -- snapshot; with a worker-local NIC baseline that second write was 0.
    local ok_lock = stats_cache:add("collect_stats_bucket:" .. timestamp, 1, interval * 2)
    if not ok_lock then
        return
    end

    local nic_rx_delta = 0
    local nic_tx_delta = 0
    local nic_elapsed = interval

    local configured, dev, reason = resolve_nic_dev()
    if dev then
        note_nic_choice(stats_cache, configured, dev, reason)
        local cur_rx, cur_tx = read_nic_bytes(dev)
        if cur_rx and cur_tx then
            local prev_dev = stats_cache:get("last_nic_dev")
            local prev_rx = tonumber(stats_cache:get("last_nic_rx_bytes"))
            local prev_tx = tonumber(stats_cache:get("last_nic_tx_bytes"))
            local prev_ts = tonumber(stats_cache:get("nic_sample_ts"))
            -- Baseline lives in shared memory: any worker may win the bucket lock.
            if prev_dev == dev and prev_rx and prev_tx then
                if cur_rx >= prev_rx then
                    nic_rx_delta = cur_rx - prev_rx
                end
                if cur_tx >= prev_tx then
                    nic_tx_delta = cur_tx - prev_tx
                end
                if prev_ts and current_time > prev_ts then
                    local elapsed = current_time - prev_ts
                    if elapsed >= 1 then
                        nic_elapsed = elapsed
                    end
                end
            end
            stats_cache:set("last_nic_rx_bytes", cur_rx)
            stats_cache:set("last_nic_tx_bytes", cur_tx)
            stats_cache:set("last_nic_dev", dev)
            stats_cache:set("nic_sample_ts", current_time)
        end
    elseif reason then
        ngx.log(ngx.WARN, "NIC stats unavailable: ", reason)
    end

    local bandwidth_l7_rx_total = tonumber(stats_cache:get("bandwidth_l7_rx")) or 0
    local bandwidth_l7_tx_total = tonumber(stats_cache:get("bandwidth_l7_tx")) or 0
    local bandwidth_l7_rx_per_interval = bandwidth_l7_rx_total * 8 / interval
    local bandwidth_l7_tx_per_interval = bandwidth_l7_tx_total * 8 / interval
    local bandwidth_nic_rx_per_interval = nic_rx_delta * 8 / nic_elapsed
    local bandwidth_nic_tx_per_interval = nic_tx_delta * 8 / nic_elapsed

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
        cache_hit_count = tonumber(stats_cache:get("cache_hit_count")) or 0,
        cache_miss_count = tonumber(stats_cache:get("cache_miss_count")) or 0,
        cache_bypass_count = tonumber(stats_cache:get("cache_bypass_count")) or 0,
    }
    _M.apply_cache_hit_ratio(stats)

    local ip_items = collect_dimension_items(stats_cache, "^ip_req_count:(%d+):(.+)$", function(site_id, ip, count)
        return { site_id = tonumber(site_id) or 0, ip = ip, request_count = count }
    end)
    local url_items = collect_dimension_items(stats_cache, "^url_req_count:(%d+):(.+)$", function(site_id, url_path, count)
        return { site_id = tonumber(site_id) or 0, url = url_path, request_count = count }
    end)
    local ua_items = collect_dimension_items(stats_cache, "^ua_req_count:(%d+):(.+)$", function(site_id, ua, count)
        return { site_id = tonumber(site_id) or 0, user_agent = ua, request_count = count }
    end)
    local country_items = collect_dimension_items(stats_cache, "^country_req_count:(%d+):(.+)$", function(site_id, country_iso, count, cache)
        local block_key = "block_country_req_count:" .. site_id .. ":" .. country_iso
        local block_count = tonumber(cache:get(block_key)) or 0
        cache:delete(block_key)
        return {
            site_id = tonumber(site_id) or 0,
            country_iso = country_iso,
            request_count = count,
            block_count = block_count,
        }
    end)
    local isp_items = collect_dimension_items(stats_cache, "^isp_req_count:(%d+):(.+)$", function(site_id, isp_name, count)
        return { site_id = tonumber(site_id) or 0, isp = isp_name, request_count = count }
    end)
    local referer_items = collect_dimension_items(stats_cache, "^referer_req_count:(%d+):(.+)$", function(site_id, referer, count)
        return { site_id = tonumber(site_id) or 0, referer = referer, request_count = count }
    end)
    local domain_items = collect_domain_items(stats_cache, interval)
    local site_items = collect_site_traffic_items(stats_cache, interval)

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
            { shm = ngx.shared.domain_stats_history, key = "domain_request_stats", items = domain_items },
            { shm = ngx.shared.site_stats_history, key = "site_traffic_stats", items = site_items },
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
    stats_cache:set("cache_hit_count", 0)
    stats_cache:set("cache_miss_count", 0)
    stats_cache:set("cache_bypass_count", 0)

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

local function seed_nic_baseline()
    local stats_cache = ngx.shared.stats_cache
    if not stats_cache then
        return
    end
    -- Seed once so the first 60s sample has a previous counter to subtract.
    if not stats_cache:add("nic_baseline_seed_lock", 1, 10) then
        return
    end
    if stats_cache:get("nic_sample_ts") then
        return
    end
    local configured, dev, reason = resolve_nic_dev()
    if not dev then
        if reason then
            ngx.log(ngx.WARN, "NIC stats unavailable: ", reason)
        end
        return
    end
    local rx, tx = read_nic_bytes(dev)
    if not rx or not tx then
        return
    end
    note_nic_choice(stats_cache, configured, dev, reason)
    stats_cache:set("last_nic_rx_bytes", rx)
    stats_cache:set("last_nic_tx_bytes", tx)
    stats_cache:set("last_nic_dev", dev)
    stats_cache:set("nic_sample_ts", ngx.now())
end

function _M.start()
    local stats_cache = ngx.shared.stats_cache
    if stats_cache then
        stats_cache:set("STATS_INTERVAL", STATS_INTERVAL)
    end
    seed_nic_baseline()

    local ok, err = ngx.timer.every(STATS_INTERVAL, collect_stats)
    if not ok then
        ngx.log(ngx.ERR, "Failed to create timer: ", err)
    end
end

return _M
