local ngx = ngx
local request_stats = require "resty.request_stats"

local _M = { _VERSION = "1.3.0" }

local FIREWALL_CONFIG_PATH = "/usr/local/share/dorian/sparta/firewall.config"
local STATS_INTERVAL = 60
local LATENCY_BUCKETS = request_stats.LATENCY_BUCKETS

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

local function read_nic_counter(dev, name)
    if not dev or dev == "" then
        return nil
    end
    local file = io.open("/sys/class/net/" .. dev .. "/statistics/" .. name, "r")
    if not file then
        return nil
    end
    local v = file:read("*l")
    file:close()
    return tonumber(v)
end

--- Cumulative NIC counters. Bytes are required; packet counters are nil when
--- that statistics file is missing. A missing previous sample yields a 0 delta.
local function read_nic_counters(dev)
    local rx_bytes = read_nic_counter(dev, "rx_bytes")
    local tx_bytes = read_nic_counter(dev, "tx_bytes")
    if not rx_bytes or not tx_bytes then
        return nil
    end
    return {
        rx_bytes = rx_bytes,
        tx_bytes = tx_bytes,
        rx_packets = read_nic_counter(dev, "rx_packets"),
        tx_packets = read_nic_counter(dev, "tx_packets"),
    }
end

local function counter_delta(current, previous)
    if current and previous and current >= previous then
        return current - previous
    end
    return 0
end

local function bond_slaves(dev)
    if not valid_dev_name(dev) then
        return nil
    end
    local f = io.open("/sys/class/net/" .. dev .. "/bonding/slaves", "r")
    if not f then
        return nil
    end
    local text = f:read("*a") or ""
    f:close()
    local slaves = {}
    for name in text:gmatch("%S+") do
        if valid_dev_name(name) then
            slaves[#slaves + 1] = name
        end
    end
    if #slaves == 0 then
        return nil
    end
    return slaves
end

-- One ethtool -S pass. Aggregate keys win; per-queue rxN_* lines are used only
-- when that aggregate is absent, so the two are never added together.
local ETHTOOL_RX_KEYS = {
    rx_packets = true,
    rx_discards_phy = true,
    rx_xdp_drop = true,
    rx_xdp_tx_xmit = true,
    rx_xdp_redirect = true,
}

local function ethtool_perq_key(key)
    local rest = key:match("^rx%d+_(.+)$")
    if not rest then
        return nil
    end
    local agg = "rx_" .. rest
    if ETHTOOL_RX_KEYS[agg] then
        return agg
    end
    return nil
end

local function read_ethtool_rx(dev)
    if not valid_dev_name(dev) then
        return nil
    end
    local pipe = io.popen("ethtool -S " .. dev .. " 2>/dev/null")
    if not pipe then
        return nil
    end
    local agg, perq, any = {}, {}, false
    for line in pipe:lines() do
        local key, val = line:match("^%s*([%w_]+):%s*(%d+)%s*$")
        local n = key and tonumber(val)
        if n then
            if ETHTOOL_RX_KEYS[key] then
                agg[key] = n
                any = true
            else
                local base = ethtool_perq_key(key)
                if base then
                    perq[base] = (perq[base] or 0) + n
                    any = true
                end
            end
        end
    end
    pipe:close()
    if not any then
        return nil
    end
    local out = {}
    for key in pairs(ETHTOOL_RX_KEYS) do
        if agg[key] ~= nil then
            out[key] = agg[key]
        else
            out[key] = perq[key]
        end
    end
    return out
end

--- Sum ethtool RX counters across bond slaves. The bond device itself has none.
--- A failed slave fails the whole read so a partial sum cannot move the baseline.
local function read_nic_ethtool_rx(dev)
    local slaves = bond_slaves(dev) or { dev }
    local sum, saw = {}, {}
    for _, name in ipairs(slaves) do
        local part = read_ethtool_rx(name)
        if not part then
            return nil
        end
        for key, val in pairs(part) do
            if val ~= nil then
                sum[key] = (sum[key] or 0) + val
                saw[key] = true
            end
        end
    end
    for key in pairs(ETHTOOL_RX_KEYS) do
        if not saw[key] then
            sum[key] = nil
        end
    end
    return sum
end

local function has_baseline(current, previous)
    return current == nil or previous ~= nil
end

local function max_delta(current_a, previous_a, current_b, previous_b)
    local a = counter_delta(current_a, previous_a)
    local b = counter_delta(current_b, previous_b)
    if a > b then
        return a
    end
    return b
end

-- Scalar L7 counters kept as shm keys "<name>" (edge) and "s:<site>:<name>" (site).
local L7_COUNTER_FIELDS = {
    "traffic_l7_rx", "traffic_l7_tx",
    "request_count", "response_count", "blocked_request_count",
    "ip_count", "blocked_ip_count",
    "code200", "code206", "code301", "code302",
    "code400", "code403", "code404", "code444", "code499",
    "code500", "code501", "code502", "code503", "code504",
    "code904", "code929", "code978",
    "get_count", "post_count", "delete_count", "put_count",
    "head_count", "patch_count", "options_count", "others_count",
    "http1_0_count", "http1_1_count", "http2_count", "http3_count",
    "cache_hit_count", "cache_stale_count", "cache_updating_count", "cache_revalidated_count",
    "cache_miss_count", "cache_expired_count", "cache_bypass_count", "cache_dynamic_count",
    "traffic_cached_tx",
    "origin_request_count", "traffic_origin_rx",
    "origin_code2xx", "origin_code3xx", "origin_code4xx", "origin_code5xx",
    "origin_timeout_count", "origin_error_count",
    "edge_latency_sum_ms", "origin_latency_sum_ms",
}

-- Histogram buckets are stored as "<prefix><1..11>".
local HIST_FIELDS = {
    edge_lat_h = "edge_latency_hist",
    origin_lat_h = "origin_latency_hist",
}

local CACHED_COUNTERS = { "cache_hit_count", "cache_stale_count", "cache_updating_count", "cache_revalidated_count" }

local CACHE_MISS_URL_TOP = 100

local function zero_hist()
    local h = {}
    for i = 1, LATENCY_BUCKETS do
        h[i] = 0
    end
    return h
end

local function empty_l7_row()
    local row = {}
    for _, name in ipairs(L7_COUNTER_FIELDS) do
        row[name] = 0
    end
    row.bandwidth_l7_rx = 0
    row.bandwidth_l7_tx = 0
    row.cache_hit_ratio = 0
    for _, field in pairs(HIST_FIELDS) do
        row[field] = zero_hist()
    end
    return row
end

local function empty_site_row(site_id)
    local row = empty_l7_row()
    row.site_id = tonumber(site_id) or 0
    return row
end

function _M.empty_site_row(site_id)
    return empty_site_row(site_id)
end

--- Store one counter on a row; false when `name` is not an L7 counter.
local function apply_counter(row, name, val)
    local prefix, idx = name:match("^([%a_]+_h)(%d+)$")
    if prefix then
        local field = HIST_FIELDS[prefix]
        idx = tonumber(idx)
        if field and idx >= 1 and idx <= LATENCY_BUCKETS then
            row[field][idx] = val
            return true
        end
        return false
    end
    if type(row[name]) == "number" or name:match("^code%d+$") then
        row[name] = val
        return true
    end
    return false
end

--- (hit + stale + updating + revalidated) / (request_count - blocked_request_count).
function _M.apply_cache_hit_ratio(row)
    local cached = 0
    for _, name in ipairs(CACHED_COUNTERS) do
        cached = cached + (tonumber(row[name]) or 0)
    end
    local denom = (tonumber(row.request_count) or 0) - (tonumber(row.blocked_request_count) or 0)
    if denom > 0 then
        row.cache_hit_ratio = math.min(cached / denom, 1)
    else
        row.cache_hit_ratio = 0
    end
    return row
end

local function finalize_l7_row(row, seconds)
    row.bandwidth_l7_rx = (tonumber(row.traffic_l7_rx) or 0) * 8 / seconds
    row.bandwidth_l7_tx = (tonumber(row.traffic_l7_tx) or 0) * 8 / seconds
    _M.apply_cache_hit_ratio(row)
    return row
end

local function by_site_then(field)
    return function(a, b)
        if a.site_id == b.site_id then
            return tostring(a[field]) < tostring(b[field])
        end
        return a.site_id < b.site_id
    end
end

local function take(stats_cache, key, consume)
    local val = tonumber(stats_cache:get(key)) or 0
    if consume then
        stats_cache:delete(key)
    end
    return val
end

-- Collectors take one get_keys() snapshot. `consume` deletes the keys (bucket flush);
-- the API passes false for a live view of the bucket being filled.

function _M.collect_dimension_items(stats_cache, keys, pattern, build_item, consume, site_filter)
    local items = {}
    for _, key in ipairs(keys) do
        local site_id, captured = key:match(pattern)
        if captured and (not site_filter or site_id == site_filter) then
            local count = tonumber(stats_cache:get(key)) or 0
            if count > 0 then
                table.insert(items, build_item(site_id, captured, count, stats_cache, consume))
            end
            if consume then
                stats_cache:delete(key)
            end
        end
    end
    return items
end

function _M.collect_domain_items(stats_cache, keys, seconds, consume, site_filter)
    local domains = {}
    for _, key in ipairs(keys) do
        local kind, sid, domain = "req_count", key:match("^domain_req_count:(%d+):(.+)$")
        if not domain then
            kind, sid, domain = "rx", key:match("^domain_rx:(%d+):(.+)$")
        end
        if not domain then
            kind, sid, domain = "tx", key:match("^domain_tx:(%d+):(.+)$")
        end
        if domain and (not site_filter or sid == site_filter) then
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
            local val = take(stats_cache, key, consume)
            if kind == "req_count" then
                row.request_count = val
            elseif kind == "rx" then
                row.traffic_l7_rx = val
            else
                row.traffic_l7_tx = val
            end
        end
    end

    local items = {}
    for _, row in pairs(domains) do
        if row.request_count > 0 or row.traffic_l7_rx > 0 or row.traffic_l7_tx > 0 then
            row.bandwidth_l7_rx = row.traffic_l7_rx * 8 / seconds
            row.bandwidth_l7_tx = row.traffic_l7_tx * 8 / seconds
            table.insert(items, row)
        end
    end
    table.sort(items, by_site_then("domain"))
    return items
end

function _M.collect_site_items(stats_cache, keys, seconds, consume, site_filter)
    local sites = {}
    for _, key in ipairs(keys) do
        local sid, rest = key:match("^s:(%d+):(.+)$")
        if sid and not rest:find("^seen_ip:") and not rest:find("^blocked_ip:")
            and (not site_filter or sid == site_filter) then
            local row = sites[sid]
            if not row then
                row = empty_site_row(sid)
                sites[sid] = row
            end
            apply_counter(row, rest, take(stats_cache, key, consume))
        end
    end

    local items = {}
    for _, row in pairs(sites) do
        table.insert(items, finalize_l7_row(row, seconds))
    end
    table.sort(items, function(a, b)
        return a.site_id < b.site_id
    end)
    return items
end

function _M.collect_content_type_items(stats_cache, keys, consume, site_filter)
    local rows = {}
    local fields = {
        ct_req = "request_count",
        ct_tx = "traffic_l7_tx",
        ct_creq = "cached_request_count",
        ct_ctx = "traffic_cached_tx",
    }
    for _, key in ipairs(keys) do
        local kind, sid, family = key:match("^(ct_%a+):(%d+):(.+)$")
        local field = kind and fields[kind]
        if field and (not site_filter or sid == site_filter) then
            local row_key = sid .. ":" .. family
            local row = rows[row_key]
            if not row then
                row = {
                    site_id = tonumber(sid) or 0,
                    content_type = family,
                    request_count = 0,
                    traffic_l7_tx = 0,
                    cached_request_count = 0,
                    traffic_cached_tx = 0,
                }
                rows[row_key] = row
            end
            row[field] = take(stats_cache, key, consume)
        end
    end

    local items = {}
    for _, row in pairs(rows) do
        if row.request_count > 0 then
            local denom = tonumber(row.request_count) or 0
            local cached = tonumber(row.cached_request_count) or 0
            if denom > 0 then
                row.cache_hit_ratio = math.min(cached / denom, 1)
            else
                row.cache_hit_ratio = 0
            end
            table.insert(items, row)
        end
    end
    table.sort(items, function(a, b)
        if a.site_id == b.site_id then
            return a.request_count > b.request_count
        end
        return a.site_id < b.site_id
    end)
    return items
end

function _M.collect_cache_miss_url_items(stats_cache, keys, consume, site_filter)
    local rows = {}
    for _, key in ipairs(keys) do
        local kind, sid, domain, url = key:match("^cmu_(%a+):(%d+):(%S+) (.*)$")
        if (kind == "req" or kind == "miss") and (not site_filter or sid == site_filter) then
            local row_key = sid .. ":" .. domain .. " " .. url
            local row = rows[row_key]
            if not row then
                row = {
                    site_id = tonumber(sid) or 0,
                    domain = domain,
                    url = url,
                    miss_count = 0,
                    request_count = 0,
                }
                rows[row_key] = row
            end
            local val = take(stats_cache, key, consume)
            if kind == "miss" then
                row.miss_count = val
            else
                row.request_count = val
            end
        end
    end

    local per_site = {}
    for _, row in pairs(rows) do
        if row.miss_count > 0 then
            local list = per_site[row.site_id]
            if not list then
                list = {}
                per_site[row.site_id] = list
            end
            table.insert(list, row)
        end
    end

    local site_ids = {}
    for sid in pairs(per_site) do
        table.insert(site_ids, sid)
    end
    table.sort(site_ids)

    local items = {}
    for _, sid in ipairs(site_ids) do
        local list = per_site[sid]
        table.sort(list, function(a, b)
            if a.miss_count == b.miss_count then
                return a.url < b.url
            end
            return a.miss_count > b.miss_count
        end)
        for i = 1, math.min(#list, CACHE_MISS_URL_TOP) do
            table.insert(items, list[i])
        end
    end
    return items
end

function _M.collect_block_reason_items(stats_cache, keys, consume, site_filter)
    local rows = {}
    for _, key in ipairs(keys) do
        local kind, sid, rule_type, rule_id = key:match("^br_(%a+):(%d+):([^|]+)|(.*)$")
        if (kind == "req" or kind == "ip") and (not site_filter or sid == site_filter) then
            local row_key = sid .. ":" .. rule_type .. "|" .. rule_id
            local row = rows[row_key]
            if not row then
                row = {
                    site_id = tonumber(sid) or 0,
                    rule_type = rule_type,
                    rule_id = rule_id ~= "" and rule_id or nil,
                    request_count = 0,
                    ip_count = 0,
                }
                rows[row_key] = row
            end
            local val = take(stats_cache, key, consume)
            if kind == "req" then
                row.request_count = val
            else
                row.ip_count = val
            end
        end
    end

    local items = {}
    for _, row in pairs(rows) do
        if row.request_count > 0 then
            table.insert(items, row)
        end
    end
    table.sort(items, function(a, b)
        if a.site_id == b.site_id then
            return a.request_count > b.request_count
        end
        return a.site_id < b.site_id
    end)
    return items
end

--- Edge-wide L7 counters. Subtracts what was read so concurrent increments survive.
local function collect_server_counters(stats_cache, keys)
    local row = empty_l7_row()
    local names = {}
    for _, name in ipairs(L7_COUNTER_FIELDS) do
        names[name] = true
    end
    for prefix in pairs(HIST_FIELDS) do
        for i = 1, LATENCY_BUCKETS do
            names[prefix .. i] = true
        end
    end
    for _, key in ipairs(keys) do
        if key:match("^code%d+$") then
            names[key] = true
        end
    end

    for name in pairs(names) do
        local val = tonumber(stats_cache:get(name)) or 0
        if val ~= 0 then
            stats_cache:incr(name, -val, 0)
        end
        apply_counter(row, name, val)
    end
    return row
end

local function prune_history(shm, cutoff)
    if not shm then
        return
    end
    for _, key in ipairs(shm:get_keys(0)) do
        local ts = tonumber(key)
        if ts and ts < cutoff then
            shm:delete(key)
        end
    end
end

local HISTORY_RETENTION = 24 * 3600

_M.HISTORY_SHMS = {
    server_traffic_stats = "stats_history",
    site_traffic_stats = "site_stats_history",
    ip_request_stats = "ip_stats_history",
    url_request_stats = "url_stats_history",
    useragent_request_stats = "useragent_stats_history",
    country_request_stats = "country_stats_history",
    isp_request_stats = "isp_stats_history",
    referer_request_stats = "referer_stats_history",
    domain_request_stats = "domain_stats_history",
    content_type_request_stats = "content_type_stats_history",
    cache_miss_url_stats = "cache_miss_url_stats_history",
    block_reason_stats = "block_reason_stats_history",
}

local DIMENSIONS = {
    {
        key = "ip_request_stats",
        field = "ip",
        pattern = "^ip_req_count:(%d+):(.+)$",
        build = function(site_id, ip, count)
            return { site_id = tonumber(site_id) or 0, ip = ip, request_count = count }
        end,
    },
    {
        key = "url_request_stats",
        field = "url",
        pattern = "^url_req_count:(%d+):(.+)$",
        build = function(site_id, url_path, count)
            return { site_id = tonumber(site_id) or 0, url = url_path, request_count = count }
        end,
    },
    {
        key = "useragent_request_stats",
        field = "user_agent",
        pattern = "^ua_req_count:(%d+):(.+)$",
        build = function(site_id, ua, count)
            return { site_id = tonumber(site_id) or 0, user_agent = ua, request_count = count }
        end,
    },
    {
        key = "country_request_stats",
        field = "country_iso",
        pattern = "^country_req_count:(%d+):(.+)$",
        build = function(site_id, country_iso, count, cache, consume)
            local block_key = "block_country_req_count:" .. site_id .. ":" .. country_iso
            return {
                site_id = tonumber(site_id) or 0,
                country_iso = country_iso,
                request_count = count,
                block_count = take(cache, block_key, consume),
            }
        end,
    },
    {
        key = "isp_request_stats",
        field = "isp",
        pattern = "^isp_req_count:(%d+):(.+)$",
        build = function(site_id, isp_name, count)
            return { site_id = tonumber(site_id) or 0, isp = isp_name, request_count = count }
        end,
    },
    {
        key = "referer_request_stats",
        field = "referer",
        pattern = "^referer_req_count:(%d+):(.+)$",
        build = function(site_id, referer, count)
            return { site_id = tonumber(site_id) or 0, referer = referer, request_count = count }
        end,
    },
}
_M.DIMENSIONS = {}
for _, dim in ipairs(DIMENSIONS) do
    _M.DIMENSIONS[dim.key] = dim
end

local function collect_stats()
    local stats_cache = ngx.shared.stats_cache
    local stats_history = ngx.shared.stats_history

    ngx.update_time()
    local current_time = ngx.now()
    local interval = STATS_INTERVAL
    local bucket_end = math.floor(current_time / interval) * interval
    -- The flushed counters cover [bucket_end - interval, bucket_end): label the closed bucket.
    local timestamp = bucket_end - interval

    -- One collector per interval; the NIC baseline lives in shm so any worker may win.
    local ok_lock = stats_cache:add("collect_stats_bucket:" .. bucket_end, 1, interval * 2)
    if not ok_lock then
        return
    end

    local nic_rx_delta = 0
    local nic_tx_delta = 0
    local nic_tx_pkts = 0
    local nic_incoming = 0
    local nic_dropped = 0
    local xdp_incoming = 0
    local xdp_blocked = 0
    local nic_elapsed = interval

    local configured, dev, reason = resolve_nic_dev()
    if dev then
        note_nic_choice(stats_cache, configured, dev, reason)
        local cur = read_nic_counters(dev)
        if cur then
            local prev_dev = stats_cache:get("last_nic_dev")
            local prev_rx = tonumber(stats_cache:get("last_nic_rx_bytes"))
            local prev_tx = tonumber(stats_cache:get("last_nic_tx_bytes"))
            local prev_rx_pkts = tonumber(stats_cache:get("last_nic_rx_packets"))
            local prev_tx_pkts = tonumber(stats_cache:get("last_nic_tx_packets"))
            local prev_ethtool_rx = tonumber(stats_cache:get("last_ethtool_rx_packets"))
            local prev_phy = tonumber(stats_cache:get("last_rx_discards_phy"))
            local prev_xdp_drop = tonumber(stats_cache:get("last_nic_rx_xdp_drop"))
            local prev_xdp_tx = tonumber(stats_cache:get("last_rx_xdp_tx"))
            local prev_xdp_redir = tonumber(stats_cache:get("last_rx_xdp_redirect"))
            local prev_ts = tonumber(stats_cache:get("nic_sample_ts"))
            local eth = read_nic_ethtool_rx(dev)
            if prev_dev == dev then
                nic_rx_delta = counter_delta(cur.rx_bytes, prev_rx)
                nic_tx_delta = counter_delta(cur.tx_bytes, prev_tx)
                nic_tx_pkts = counter_delta(cur.tx_packets, prev_tx_pkts)
                if prev_ts and current_time > prev_ts then
                    local elapsed = current_time - prev_ts
                    if elapsed >= 1 then
                        nic_elapsed = elapsed
                    end
                end
                -- Publish the four RX layers only once every part has a baseline.
                -- Otherwise the first sample would mix a real delta with a zero.
                -- A stored 0 is a real baseline (Lua treats 0 as false).
                if eth
                    and (cur.rx_packets ~= nil or eth.rx_packets ~= nil)
                    and has_baseline(cur.rx_packets, prev_rx_pkts)
                    and has_baseline(eth.rx_packets, prev_ethtool_rx)
                    and has_baseline(eth.rx_discards_phy, prev_phy)
                    and has_baseline(eth.rx_xdp_drop, prev_xdp_drop)
                    and has_baseline(eth.rx_xdp_tx_xmit, prev_xdp_tx)
                    and has_baseline(eth.rx_xdp_redirect, prev_xdp_redir)
                then
                    local passed = max_delta(cur.rx_packets, prev_rx_pkts, eth.rx_packets, prev_ethtool_rx)
                    nic_dropped = counter_delta(eth.rx_discards_phy, prev_phy)
                    xdp_blocked = counter_delta(eth.rx_xdp_drop, prev_xdp_drop)
                    local xdp_tx = counter_delta(eth.rx_xdp_tx_xmit, prev_xdp_tx)
                    local xdp_redir = counter_delta(eth.rx_xdp_redirect, prev_xdp_redir)
                    -- XDP saw PASS + DROP + TX + REDIRECT. NIC also saw PHY discards.
                    xdp_incoming = passed + xdp_blocked + xdp_tx + xdp_redir
                    nic_incoming = xdp_incoming + nic_dropped
                end
            end
            stats_cache:set("last_nic_rx_bytes", cur.rx_bytes)
            stats_cache:set("last_nic_tx_bytes", cur.tx_bytes)
            if cur.rx_packets ~= nil then
                stats_cache:set("last_nic_rx_packets", cur.rx_packets)
            end
            if cur.tx_packets ~= nil then
                stats_cache:set("last_nic_tx_packets", cur.tx_packets)
            end
            if eth then
                if eth.rx_packets ~= nil then
                    stats_cache:set("last_ethtool_rx_packets", eth.rx_packets)
                end
                if eth.rx_discards_phy ~= nil then
                    stats_cache:set("last_rx_discards_phy", eth.rx_discards_phy)
                end
                if eth.rx_xdp_drop ~= nil then
                    stats_cache:set("last_nic_rx_xdp_drop", eth.rx_xdp_drop)
                end
                if eth.rx_xdp_tx_xmit ~= nil then
                    stats_cache:set("last_rx_xdp_tx", eth.rx_xdp_tx_xmit)
                end
                if eth.rx_xdp_redirect ~= nil then
                    stats_cache:set("last_rx_xdp_redirect", eth.rx_xdp_redirect)
                end
            end
            stats_cache:set("last_nic_dev", dev)
            stats_cache:set("nic_sample_ts", current_time)
        end
    elseif reason then
        ngx.log(ngx.WARN, "NIC stats unavailable: ", reason)
    end

    local keys = stats_cache:get_keys(0)

    local stats = finalize_l7_row(collect_server_counters(stats_cache, keys), interval)
    stats.timestamp = timestamp
    stats.traffic_nic_rx = nic_rx_delta
    stats.traffic_nic_tx = nic_tx_delta
    stats.bandwidth_nic_rx = nic_rx_delta * 8 / nic_elapsed
    stats.bandwidth_nic_tx = nic_tx_delta * 8 / nic_elapsed
    stats.packets_nic_tx = nic_tx_pkts
    stats.pps_nic_tx = nic_tx_pkts / nic_elapsed
    -- Four RX layers for this bucket. pps_* divides by seconds since the previous sample.
    --   NIC incoming  = XDP incoming + NIC-level discards
    --   XDP incoming  = passed to the stack + XDP_DROP + XDP_TX + XDP_REDIRECT
    --   NIC dropped   = rx_discards_phy (never reached XDP)
    --   XDP blocked   = rx_xdp_drop
    stats.packets_nic_rx = nic_incoming
    stats.pps_nic_rx = nic_incoming / nic_elapsed
    stats.packets_nic_dropped = nic_dropped
    stats.pps_nic_dropped = nic_dropped / nic_elapsed
    stats.packets_xdp_rx = xdp_incoming
    stats.pps_xdp_rx = xdp_incoming / nic_elapsed
    stats.packets_xdp_blocked = xdp_blocked
    stats.pps_xdp_blocked = xdp_blocked / nic_elapsed

    local payloads = {}
    for _, dim in ipairs(DIMENSIONS) do
        payloads[dim.key] = _M.collect_dimension_items(stats_cache, keys, dim.pattern, dim.build, true)
    end
    payloads.domain_request_stats = _M.collect_domain_items(stats_cache, keys, interval, true)
    payloads.site_traffic_stats = _M.collect_site_items(stats_cache, keys, interval, true)
    payloads.content_type_request_stats = _M.collect_content_type_items(stats_cache, keys, true)
    payloads.cache_miss_url_stats = _M.collect_cache_miss_url_items(stats_cache, keys, true)
    payloads.block_reason_stats = _M.collect_block_reason_items(stats_cache, keys, true)

    local ok_j, cjson = pcall(require, "cjson.safe")
    if not (ok_j and cjson and cjson.encode) then
        return
    end

    local label = tostring(timestamp)
    stats_history:set(label, cjson.encode(stats))
    for name, items in pairs(payloads) do
        local shm = ngx.shared[_M.HISTORY_SHMS[name]]
        if shm then
            local ok_set, err = shm:set(label, cjson.encode({
                timestamp = timestamp,
                [name] = #items > 0 and items or cjson.empty_array,
            }))
            if not ok_set then
                ngx.log(ngx.ERR, "failed to store ", name, " for ", label, ": ", tostring(err))
            end
        end
    end

    local cutoff = current_time - HISTORY_RETENTION
    for _, shm_name in pairs(_M.HISTORY_SHMS) do
        prune_history(ngx.shared[shm_name], cutoff)
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
    local cur = read_nic_counters(dev)
    if not cur then
        return
    end
    note_nic_choice(stats_cache, configured, dev, reason)
    stats_cache:set("last_nic_rx_bytes", cur.rx_bytes)
    stats_cache:set("last_nic_tx_bytes", cur.tx_bytes)
    if cur.rx_packets ~= nil then
        stats_cache:set("last_nic_rx_packets", cur.rx_packets)
    end
    if cur.tx_packets ~= nil then
        stats_cache:set("last_nic_tx_packets", cur.tx_packets)
    end
    local eth = read_nic_ethtool_rx(dev)
    if eth then
        if eth.rx_packets ~= nil then
            stats_cache:set("last_ethtool_rx_packets", eth.rx_packets)
        end
        if eth.rx_discards_phy ~= nil then
            stats_cache:set("last_rx_discards_phy", eth.rx_discards_phy)
        end
        if eth.rx_xdp_drop ~= nil then
            stats_cache:set("last_nic_rx_xdp_drop", eth.rx_xdp_drop)
        end
        if eth.rx_xdp_tx_xmit ~= nil then
            stats_cache:set("last_rx_xdp_tx", eth.rx_xdp_tx_xmit)
        end
        if eth.rx_xdp_redirect ~= nil then
            stats_cache:set("last_rx_xdp_redirect", eth.rx_xdp_redirect)
        end
    end
    stats_cache:set("last_nic_dev", dev)
    stats_cache:set("nic_sample_ts", ngx.now())
end

-- Fire just after each wall-clock minute so a bucket holds exactly its own minute.
local COLLECT_DELAY = 0.2

local schedule_collect

local function on_collect_timer(premature)
    if premature then
        return
    end
    local ok, err = pcall(collect_stats)
    if not ok then
        ngx.log(ngx.ERR, "collect_stats failed: ", tostring(err))
    end
    schedule_collect()
end

schedule_collect = function()
    ngx.update_time()
    local now = ngx.now()
    local next_edge = (math.floor(now / STATS_INTERVAL) + 1) * STATS_INTERVAL
    local ok, err = ngx.timer.at(next_edge - now + COLLECT_DELAY, on_collect_timer)
    if not ok then
        ngx.log(ngx.ERR, "Failed to create stats timer: ", err)
    end
end

function _M.start()
    local stats_cache = ngx.shared.stats_cache
    if stats_cache then
        stats_cache:set("STATS_INTERVAL", STATS_INTERVAL)
    end
    seed_nic_baseline()
    schedule_collect()
end

return _M
