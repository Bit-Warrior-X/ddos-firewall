-- L7 attack incident detector (server-wide episodes, like the L4 DETECT engine).
--
-- Every request (log phase) gets exactly one outcome, so
-- requests = passed + blocked + malformed + rapid_reset:
--   blocked      444 (limit_req / limit_conn / temporary-block / WAF drop) or
--                WAF deny / captcha ($acl_blocked = 1)
--   rapid_reset  499 with ~0 request_time and no upstream (client reset)
--   malformed    400/408 without a request line
--   passed       everything else (let through to the site)
-- Detection vectors: flood (all requests), blocked, rapid_reset, malformed.
-- passed is tracked for reporting (totals, peaks, timeline, top lists, sites).
-- Worker 0 evaluates them once per second against a learned per-vector
-- baseline: enter = max(floor, mean + 6*sigma, 3*mean), exit = max(1.5*mean,
-- enter/2). A vector enters ATTACK after attack_confirm_seconds at/above enter
-- (immediately on a 3x surge) and leaves after attack_exit_seconds below exit
-- (10s when traffic is near idle).
--
-- An incident (one id) opens when the first vector enters ATTACK and closes
-- once every vector has been normal for attack_cooldown_seconds. While open,
-- requests are also aggregated by IP / URL / user agent / country / site /
-- status / protocol / block rule in the l7_attack_detail shm (sampled above
-- DETAIL_BUDGET req/s; sampled requests count as `sample`, so totals stay
-- unbiased estimates). Snapshots are served on the internal stats listener
-- (GET /l7_attack) and collected by angelos (core/l7_attack_sync.py).

local ngx = ngx
local cjson = require "cjson.safe"

local _M = { _VERSION = "1.0.0" }

local SHM = "l7_attack"
local DETAIL = "l7_attack_detail"

local VECTORS = { "flood", "rapid_reset", "malformed", "blocked" }
local FLOOR_KEYS = {
    flood = "attack_floor_flood",
    rapid_reset = "attack_floor_reset",
    malformed = "attack_floor_malformed",
    blocked = "attack_floor_blocked",
}

local COUNTER_TTL = 30
local BASE_ALPHA = 1 / 1800
local BASE_K, BASE_M, SURGE = 6, 3, 3
local DETAIL_BUDGET = 3000
local TOP_N = 50
local SITES_N = 100
local ESC_IPS_N = 2000
local TIMELINE_STEP = 10
local TIMELINE_MAX = 4320
local SNAPSHOT_INTERVAL = 30
local INCIDENT_TTL = 172800
local RECENT_MAX = 200
local ESC_PRE_WINDOW = 60
local DETAIL_KEYS_MAX = 300000
local CATCH_UP_MAX = 5

-- ---------------------------------------------------------------------------
-- Request path (all workers)
-- ---------------------------------------------------------------------------

local flags_at, active_cached, sample_cached = 0, false, 1

local function flags(dict)
    local now = ngx.now()
    if now - flags_at >= 1 then
        active_cached = dict:get("active") ~= nil
        sample_cached = dict:get("sample") or 1
        flags_at = now
    end
    return active_cached, sample_cached
end

--- Exactly one outcome per request: blocked | rapid_reset | malformed | passed.
local function classify(status)
    -- 444: limit_req / limit_conn / temporary-block / WAF drop; acl_blocked also
    -- covers WAF deny / captcha (403).
    if status == "444" or ngx.var.acl_blocked == "1" then
        return "blocked"
    end
    if status == "499" then
        local addr = ngx.var.upstream_addr
        if (addr == nil or addr == "" or addr == "-")
            and (tonumber(ngx.var.request_time) or 1) < 0.005 then
            return "rapid_reset"
        end
        return "passed"
    end
    if status == "400" or status == "408" then
        local method = ngx.var.request_method
        if method == nil or method == "" then
            return "malformed"
        end
    end
    return "passed"
end

local function trunc(s, n)
    if #s > n then
        return s:sub(1, n)
    end
    return s
end

local function record_detail(cls, status, is_error, sample)
    if sample > 1 and math.random(sample) ~= 1 then
        return
    end
    local d = ngx.shared[DETAIL]
    if not d then
        return
    end
    local var = ngx.var
    local ip = var.remote_addr or "-"
    local host = var.host or "-"
    -- $site_id is never set for requests rejected before the rewrite phase.
    local sid = "0"
    if cls ~= "malformed" then
        sid = var.site_id
        if not sid or sid == "" then
            sid = "0"
        end
    end
    local site_prefix = "site:" .. sid .. "|" .. host .. "|"
    -- "<dim>:" counts all requests, "<dim>b:" blocked, "<dim>p:" passed.
    local split = (cls == "blocked" and "b:") or (cls == "passed" and "p:") or nil

    d:incr("ip:" .. ip, sample, 0)
    if split then
        d:incr("ip" .. split .. ip, sample, 0)
    end
    d:incr("st:" .. status, sample, 0)
    d:incr(site_prefix .. "requests", sample, 0)
    d:incr(site_prefix .. cls, sample, 0)
    if is_error then
        d:incr(site_prefix .. "errors", sample, 0)
    end
    if cls == "malformed" then
        return
    end

    local url = host .. trunc(var.uri or "/", 200)
    d:incr("url:" .. url, sample, 0)
    local cc = var.stats_country
    cc = (cc and cc ~= "") and cc or "-"
    d:incr("cc:" .. cc, sample, 0)
    if split then
        d:incr("url" .. split .. url, sample, 0)
        d:incr("cc" .. split .. cc, sample, 0)
    end
    d:incr("ua:" .. trunc(var.http_user_agent or "-", 200), sample, 0)
    d:incr("proto:" .. (var.server_protocol or "-"), sample, 0)
    d:incr("method:" .. (var.request_method or "-"), sample, 0)

    local rule = var.waf_rule_type
    if rule and rule ~= "" then
        local rid = var.waf_rule_id
        d:incr("rule:" .. rule .. ((rid and rid ~= "") and ("|" .. rid) or ""), sample, 0)
    elseif var.limit_req_status == "REJECTED" then
        d:incr("rule:limit_req", sample, 0)
    elseif var.limit_conn_status == "REJECTED" then
        d:incr("rule:limit_conn", sample, 0)
    end
end

--- log_by_lua entry point (every request, before l7_guard).
function _M.record()
    local dict = ngx.shared[SHM]
    if not dict then
        return
    end
    local suffix = ":" .. ngx.time()
    local status = ngx.var.status or "0"

    dict:incr("s:flood" .. suffix, 1, 0, COUNTER_TTL)
    local cls = classify(status)
    dict:incr("s:" .. cls .. suffix, 1, 0, COUNTER_TTL)
    local code = tonumber(status) or 0
    local is_error = code >= 500 and code < 600
    if is_error then
        dict:incr("s:err" .. suffix, 1, 0, COUNTER_TTL)
    end

    local active, sample = flags(dict)
    if active then
        record_detail(cls, status, is_error, sample)
    end
end

--- Called by l7_guard when it blocks an IP.
function _M.on_escalate(ip, reason, ttl)
    local dict = ngx.shared[SHM]
    if not dict then
        return
    end
    local now = ngx.time()
    dict:incr("s:esc:" .. now, 1, 0, COUNTER_TTL)
    local entry = now .. "|" .. reason .. "|" .. ttl
    if flags(dict) then
        local d = ngx.shared[DETAIL]
        if d then
            d:set("esc:" .. ip, entry)
        end
    else
        -- Replayed into the incident if one opens within ESC_PRE_WINDOW.
        dict:rpush("esc_log", ip .. "|" .. entry)
    end
end

-- ---------------------------------------------------------------------------
-- Detector (worker 0)
-- ---------------------------------------------------------------------------

local S

local function new_state()
    local st = { base = {}, vec = {}, inc = nil, last_sec = nil }
    for _, v in ipairs(VECTORS) do
        st.base[v] = { mean = 0, var = 0, n = 0 }
        st.vec[v] = { state = "normal", above = 0, below = 0 }
    end
    return st
end

local function load_state(dict)
    local raw = dict:get("det")
    local st = raw and cjson.decode(raw)
    if type(st) ~= "table" or type(st.base) ~= "table" or type(st.vec) ~= "table" then
        return new_state()
    end
    for _, v in ipairs(VECTORS) do
        st.base[v] = st.base[v] or { mean = 0, var = 0, n = 0 }
        st.vec[v] = st.vec[v] or { state = "normal", above = 0, below = 0 }
    end
    if st.inc == cjson.null then
        st.inc = nil
    end
    return st
end

local function update_base(b, rate)
    b.n = b.n + 1
    local a = math.max(BASE_ALPHA, 1 / b.n)
    local d = rate - b.mean
    b.mean = b.mean + a * d
    b.var = (1 - a) * (b.var + a * d * d)
end

local function thresholds(b, floor)
    local sigma = math.sqrt(b.var > 0 and b.var or 0)
    local t_enter = math.max(floor, b.mean + BASE_K * sigma, BASE_M * b.mean)
    local t_exit = math.max(1.5 * b.mean, 0.5 * t_enter)
    return math.floor(t_enter + 0.5), math.floor(t_exit + 0.5)
end

local function sorted_top(map, n, key_name, blocked, passed)
    local arr = {}
    for k, c in pairs(map) do
        local row = { [key_name] = k, requests = c }
        if blocked then
            row.blocked = blocked[k] or 0
            row.passed = passed[k] or 0
        end
        arr[#arr + 1] = row
    end
    table.sort(arr, function(a, b) return a.requests > b.requests end)
    local out = setmetatable({}, cjson.array_mt)
    for i = 1, math.min(n, #arr) do
        out[i] = arr[i]
    end
    return out, #arr
end

local function collect_detail()
    local d = ngx.shared[DETAIL]
    local buckets = {
        ip = {}, ipb = {}, ipp = {}, url = {}, urlb = {}, urlp = {}, cc = {}, ccb = {}, ccp = {},
        ua = {}, st = {}, proto = {}, method = {}, rule = {},
    }
    local sites, esc = {}, setmetatable({}, cjson.array_mt)
    if not d then
        return buckets, sites, esc
    end

    for _, key in ipairs(d:get_keys(DETAIL_KEYS_MAX)) do
        local prefix, rest = key:match("^(%a+):(.*)$")
        local val = prefix and d:get(key)
        if val then
            if prefix == "site" then
                local sid, host, cls = rest:match("^([^|]*)|(.*)|([%a_]+)$")
                if sid then
                    local sk = sid .. "|" .. host
                    local row = sites[sk]
                    if not row then
                        row = { site_id = tonumber(sid) or 0, host = host, requests = 0, passed = 0,
                                blocked = 0, rapid_reset = 0, malformed = 0, errors = 0 }
                        sites[sk] = row
                    end
                    row[cls] = (row[cls] or 0) + val
                end
            elseif prefix == "esc" then
                local at, reason, ttl = tostring(val):match("^(%d+)|([^|]*)|(%d+)$")
                esc[#esc + 1] = { ip = rest, at = tonumber(at), reason = reason, ttl = tonumber(ttl) }
            elseif buckets[prefix] then
                buckets[prefix][rest] = val
            end
        end
    end
    return buckets, sites, esc
end

local function counts_map(map)
    local out = {}
    for k, v in pairs(map) do
        out[k] = v
    end
    return out
end

local function read_timeline(dict, id)
    local items = {}
    local key = "tl:" .. id
    local n = dict:llen(key) or 0
    for _ = 1, n do
        local raw = dict:lpop(key)
        if raw then
            items[#items + 1] = raw
        end
    end
    for _, raw in ipairs(items) do
        dict:rpush(key, raw)
    end
    local out = setmetatable({}, cjson.array_mt)
    for i, raw in ipairs(items) do
        out[i] = cjson.decode(raw)
    end
    return out
end

local function build_snapshot(dict, cfg, inc, status, now)
    local buckets, sites_map, esc = collect_detail()

    local top_ips, unique_ips = sorted_top(buckets.ip, TOP_N, "ip", buckets.ipb, buckets.ipp)
    local top_urls = sorted_top(buckets.url, TOP_N, "url", buckets.urlb, buckets.urlp)
    local top_uas = sorted_top(buckets.ua, TOP_N, "user_agent")
    local top_ccs = sorted_top(buckets.cc, TOP_N, "country_iso", buckets.ccb, buckets.ccp)
    local blocked_ips = 0
    for _ in pairs(buckets.ipb) do
        blocked_ips = blocked_ips + 1
    end

    local sites = setmetatable({}, cjson.array_mt)
    for _, row in pairs(sites_map) do
        sites[#sites + 1] = row
    end
    table.sort(sites, function(a, b) return a.requests > b.requests end)
    for i = #sites, SITES_N + 1, -1 do
        sites[i] = nil
    end

    table.sort(esc, function(a, b) return (a.at or 0) < (b.at or 0) end)
    local by_reason = {}
    for _, e in ipairs(esc) do
        by_reason[e.reason] = (by_reason[e.reason] or 0) + 1
    end
    local esc_total = #esc
    for i = #esc, ESC_IPS_N + 1, -1 do
        esc[i] = nil
    end

    local timeline = read_timeline(dict, inc.id)
    if inc.tb then
        timeline[#timeline + 1] = inc.tb
    end

    local vector_list = {}
    for v, info in pairs(inc.vectors) do
        vector_list[#vector_list + 1] = { name = v, first_at = info.first_at or 0 }
    end
    table.sort(vector_list, function(a, b) return a.first_at < b.first_at end)
    local names = setmetatable({}, cjson.array_mt)
    for i, item in ipairs(vector_list) do
        names[i] = item.name
    end

    local ended_at = status == "ended" and inc.ended_at or cjson.null
    local last = status == "ended" and inc.ended_at or now
    return {
        id = inc.id,
        status = status,
        started_at = inc.started_at,
        ended_at = ended_at,
        updated_at = now,
        duration = math.max(1, last - inc.started_at + 1),
        vector_list = names,
        vectors = inc.vectors,
        peak_rps = inc.peak_rps,
        peak_rps_at = inc.peak_rps_at,
        peak_blocked_rps = inc.peak_blocked_rps or 0,
        peak_blocked_rps_at = inc.peak_blocked_rps_at or inc.started_at,
        peak_passed_rps = inc.peak_passed_rps or 0,
        peak_passed_rps_at = inc.peak_passed_rps_at or inc.started_at,
        totals = inc.totals,
        blocked_ratio = inc.totals.requests > 0
            and math.floor(10000 * inc.totals.blocked / inc.totals.requests + 0.5) / 10000 or 0,
        unique_ips = unique_ips,
        blocked_ips = blocked_ips,
        sampling = { max_factor = inc.sample_max, estimated = inc.sample_max > 1 },
        top_ips = top_ips,
        top_urls = top_urls,
        top_user_agents = top_uas,
        top_countries = top_ccs,
        status_codes = counts_map(buckets.st),
        protocols = counts_map(buckets.proto),
        methods = counts_map(buckets.method),
        block_rules = counts_map(buckets.rule),
        sites = sites,
        escalations = { total = esc_total, by_reason = by_reason, ips = esc, xdp = cfg.xdp },
        timeline = timeline,
        detector = {
            floors = {
                flood = cfg.attack_floor_flood,
                rapid_reset = cfg.attack_floor_reset,
                malformed = cfg.attack_floor_malformed,
                blocked = cfg.attack_floor_blocked,
            },
            confirm_seconds = cfg.attack_confirm_seconds,
            exit_seconds = cfg.attack_exit_seconds,
            cooldown_seconds = cfg.attack_cooldown_seconds,
        },
    }
end

local function save_snapshot(dict, cfg, inc, status, now)
    local snap = build_snapshot(dict, cfg, inc, status, now)
    local encoded = cjson.encode(snap)
    if not encoded then
        ngx.log(ngx.ERR, "l7_attack: snapshot encode failed for ", inc.id)
        return
    end
    local ok, err = dict:set("inc:" .. inc.id, encoded, INCIDENT_TTL)
    if not ok then
        ngx.log(ngx.ERR, "l7_attack: snapshot store failed for ", inc.id, ": ", err)
    end
    return snap
end

local function vector_rates_str(rates)
    local parts = {}
    for _, v in ipairs(VECTORS) do
        parts[#parts + 1] = v .. "=" .. rates[v]
    end
    return table.concat(parts, " ")
end

local function replay_escalations(dict, since)
    local d = ngx.shared[DETAIL]
    while true do
        local raw = dict:lpop("esc_log")
        if not raw then
            break
        end
        local ip, at, rest = raw:match("^([^|]+)|(%d+)|(.*)$")
        if ip and tonumber(at) >= since and d then
            d:set("esc:" .. ip, at .. "|" .. rest)
        end
    end
end

local function trim_esc_log(dict, cutoff)
    while true do
        local raw = dict:lpop("esc_log")
        if not raw then
            return
        end
        local at = tonumber(raw:match("^[^|]+|(%d+)|"))
        if at and at >= cutoff then
            dict:lpush("esc_log", raw)
            return
        end
    end
end

local function open_incident(dict, cfg, s, entered, rates)
    local started_at = s
    for _, v in ipairs(entered) do
        local since = S.vec[v].since or s
        if since < started_at then
            started_at = since
        end
    end
    local seq = dict:incr("seq", 1, 0) or 0
    local id = string.format("%.0f", started_at * 1048576 + (seq % 1048576))

    local d = ngx.shared[DETAIL]
    if d then
        d:flush_all()
        d:flush_expired()
    end
    replay_escalations(dict, started_at - ESC_PRE_WINDOW)

    local thr = {}
    for _, v in ipairs(VECTORS) do
        thr[v] = { enter = S.vec[v].t_enter, exit = S.vec[v].t_exit, baseline = S.base[v].mean }
    end

    S.inc = {
        id = id,
        started_at = started_at,
        vectors = {},
        totals = { requests = 0, passed = 0, blocked = 0, rapid_reset = 0, malformed = 0,
                   errors_5xx = 0, escalations = 0 },
        peak_blocked_rps = 0,
        peak_passed_rps = 0,
        peak_rps = 0,
        peak_rps_at = s,
        sample_max = 1,
        thresholds = thr,
        snap_at = 0,
    }
    dict:set("active", id)
    dict:set("current", id)
    dict:set("sample", 1)

    ngx.log(ngx.WARN, "l7_attack: attack START id=", id, " vectors=", table.concat(entered, ","),
        " ", vector_rates_str(rates))
end

local function push_recent(dict, entry)
    local recent = setmetatable(cjson.decode(dict:get("recent") or "[]") or {}, cjson.array_mt)
    recent[#recent + 1] = entry
    while #recent > RECENT_MAX do
        table.remove(recent, 1)
    end
    dict:set("recent", cjson.encode(recent))
end

local function close_incident(dict, cfg, now, why)
    local inc = S.inc
    inc.ended_at = inc.last_attack_at or now
    if inc.tb then
        dict:rpush("tl:" .. inc.id, cjson.encode(inc.tb))
        inc.tb = nil
    end
    local snap = save_snapshot(dict, cfg, inc, "ended", now)
    dict:delete("tl:" .. inc.id)
    dict:delete("active")
    dict:delete("current")
    dict:set("sample", 1)
    push_recent(dict, { id = inc.id, started_at = inc.started_at, ended_at = inc.ended_at })

    ngx.log(ngx.WARN, "l7_attack: attack END id=", inc.id, " why=", why,
        " duration=", inc.ended_at - inc.started_at + 1, "s peak_rps=", inc.peak_rps,
        " requests=", inc.totals.requests, " unique_ips=", snap and snap.unique_ips or "?",
        " escalations=", snap and snap.escalations.total or "?")
    S.inc = nil
    for _, v in ipairs(VECTORS) do
        S.vec[v].state = "normal"
        S.vec[v].above, S.vec[v].below = 0, 0
    end
end

local function read_second(dict, s)
    local rates = {}
    for _, v in ipairs(VECTORS) do
        rates[v] = dict:get("s:" .. v .. ":" .. s) or 0
    end
    -- Not a detection vector; tracked for blocked-vs-passed reporting.
    rates.passed = dict:get("s:passed:" .. s) or 0
    return rates, dict:get("s:err:" .. s) or 0, dict:get("s:esc:" .. s) or 0
end

local function accumulate(dict, inc, s, rates, err, esc)
    for v, info in pairs(inc.vectors) do
        info.total = info.total + rates[v]
        if rates[v] > info.peak then
            info.peak, info.peak_at = rates[v], s
        end
    end

    local t = inc.totals
    t.requests = t.requests + rates.flood
    t.rapid_reset = t.rapid_reset + rates.rapid_reset
    t.malformed = t.malformed + rates.malformed
    t.blocked = t.blocked + rates.blocked
    t.passed = (t.passed or 0) + rates.passed
    t.errors_5xx = t.errors_5xx + err
    t.escalations = t.escalations + esc
    if rates.flood > inc.peak_rps then
        inc.peak_rps, inc.peak_rps_at = rates.flood, s
    end
    if rates.blocked > (inc.peak_blocked_rps or 0) then
        inc.peak_blocked_rps, inc.peak_blocked_rps_at = rates.blocked, s
    end
    if rates.passed > (inc.peak_passed_rps or 0) then
        inc.peak_passed_rps, inc.peak_passed_rps_at = rates.passed, s
    end

    local t0 = s - s % TIMELINE_STEP
    if inc.tb and inc.tb.t ~= t0 then
        local key = "tl:" .. inc.id
        dict:rpush(key, cjson.encode(inc.tb))
        if (dict:llen(key) or 0) > TIMELINE_MAX then
            dict:lpop(key)
        end
        inc.tb = nil
    end
    if not inc.tb then
        inc.tb = { t = t0, requests = 0, passed = 0, blocked = 0, rapid_reset = 0, malformed = 0,
                   errors_5xx = 0, escalations = 0 }
    end
    local tb = inc.tb
    tb.requests = tb.requests + rates.flood
    tb.passed = (tb.passed or 0) + rates.passed
    tb.rapid_reset = tb.rapid_reset + rates.rapid_reset
    tb.malformed = tb.malformed + rates.malformed
    tb.blocked = tb.blocked + rates.blocked
    tb.errors_5xx = tb.errors_5xx + err
    tb.escalations = tb.escalations + esc
end

local function step(dict, cfg, s)
    local rates, err, esc = read_second(dict, s)
    S.last_rates = { requests = rates.flood, passed = rates.passed, blocked = rates.blocked }

    local any_attack, entered = false, {}
    for _, v in ipairs(VECTORS) do
        local b, st = S.base[v], S.vec[v]
        local t_enter, t_exit = thresholds(b, cfg[FLOOR_KEYS[v]])
        st.t_enter, st.t_exit, st.rate = t_enter, t_exit, rates[v]
        local rate = rates[v]

        if st.state ~= "attack" then
            if rate >= t_enter then
                st.above = st.above + 1
                st.since = st.since or s
                if st.above >= cfg.attack_confirm_seconds or rate >= SURGE * t_enter then
                    st.state = "attack"
                    st.below = 0
                    entered[#entered + 1] = v
                end
            else
                st.above, st.since = 0, nil
                if not S.inc then
                    update_base(b, rate)
                end
            end
        else
            if rate < t_exit then
                st.below = st.below + 1
                local need = cfg.attack_exit_seconds
                if rate <= math.max(t_exit / 8, 1) then
                    need = math.min(10, need)
                end
                if st.below >= need then
                    st.state = "normal"
                    st.above, st.below, st.since = 0, 0, nil
                end
            else
                st.below = 0
            end
        end
        if st.state == "attack" then
            any_attack = true
        end
    end

    local opened_now = false
    if any_attack and not S.inc then
        open_incident(dict, cfg, s, entered, rates)
        opened_now = true
    end

    local inc = S.inc
    if not inc then
        return
    end

    for _, v in ipairs(VECTORS) do
        local st = S.vec[v]
        local info = inc.vectors[v]
        if st.state == "attack" and not info then
            info = { first_at = st.since or s, peak = 0, peak_at = s, total = 0,
                     enter = st.t_enter, exit = st.t_exit }
            inc.vectors[v] = info
            if not opened_now then
                ngx.log(ngx.WARN, "l7_attack: id=", inc.id, " vector ", v, " joined rate=", rates[v])
            end
        end
        if info then
            info.active = st.state == "attack"
            if info.active then
                info.last_at = s
            end
        end
    end

    -- Seconds spent confirming the attack are still in the counters.
    if opened_now then
        for back = inc.started_at, s - 1 do
            accumulate(dict, inc, back, read_second(dict, back))
        end
    end
    accumulate(dict, inc, s, rates, err, esc)

    local sample = math.max(1, math.ceil(rates.flood / DETAIL_BUDGET))
    dict:set("sample", sample)
    if sample > inc.sample_max then
        inc.sample_max = sample
    end

    if any_attack then
        inc.closing_since = nil
        inc.last_attack_at = s
    elseif not inc.closing_since then
        inc.closing_since = s
    end
end

local function publish_view(dict, now)
    local view = { at = now, incident = S.inc and S.inc.id or cjson.null, vectors = {},
                   rates = S.last_rates or { requests = 0, passed = 0, blocked = 0 } }
    for _, v in ipairs(VECTORS) do
        local st, b = S.vec[v], S.base[v]
        view.vectors[v] = {
            state = st.state, rate = st.rate or 0, enter = st.t_enter or 0,
            exit = st.t_exit or 0, baseline = math.floor(b.mean * 100 + 0.5) / 100,
        }
    end
    dict:set("view", cjson.encode(view))
end

local function tick(premature)
    if premature or ngx.worker.exiting() then
        return
    end
    local dict = ngx.shared[SHM]
    if not dict then
        return
    end
    local cfg = require("resty.l7_guard").get_config()
    S = S or load_state(dict)

    local now = ngx.time()
    local last = now - 1
    if S.last_sec and last <= S.last_sec then
        return
    end

    if not cfg.attack_detect then
        if S.inc then
            close_incident(dict, cfg, now, "disabled")
        end
        S.last_sec = last
        dict:set("det", cjson.encode(S))
        return
    end

    local from = S.last_sec and math.max(S.last_sec + 1, last - CATCH_UP_MAX) or last
    for s = from, last do
        step(dict, cfg, s)
    end
    S.last_sec = last

    local inc = S.inc
    if inc then
        if inc.closing_since and last - inc.closing_since >= cfg.attack_cooldown_seconds then
            close_incident(dict, cfg, now, "normal")
        else
            -- Refresh quickly while the first detail accumulates, then every SNAPSHOT_INTERVAL.
            local snaps = inc.snaps or 0
            local interval = snaps < 4 and 5 or SNAPSHOT_INTERVAL
            if last - inc.snap_at >= interval then
                inc.snap_at, inc.snaps = last, snaps + 1
                save_snapshot(dict, cfg, inc, "active", now)
            end
        end
    else
        trim_esc_log(dict, now - ESC_PRE_WINDOW)
    end

    publish_view(dict, now)
    dict:set("det", cjson.encode(S))
end

local function safe_tick(premature)
    local ok, err = pcall(tick, premature)
    if not ok then
        ngx.log(ngx.ERR, "l7_attack: detector tick failed: ", tostring(err))
    end
end

--- init_worker: worker 0 runs the detector.
function _M.start()
    if ngx.worker.id() ~= 0 then
        return
    end
    local ok, err = ngx.timer.every(1, safe_tick)
    if not ok then
        ngx.log(ngx.ERR, "l7_attack: failed to start detector: ", tostring(err))
    end
end

-- ---------------------------------------------------------------------------
-- Internal API (stats listener, localhost only)
--   GET    /l7_attack            detector view, current incident, recent ids
--   GET    /l7_attack?id=<id>    full incident snapshot
--   DELETE /l7_attack?id=<id>    drop a closed incident from shm
-- ---------------------------------------------------------------------------

function _M.api()
    local dict = ngx.shared[SHM]
    if not dict then
        return ngx.exit(503)
    end
    ngx.header["Content-Type"] = "application/json"
    local args = ngx.req.get_uri_args()
    local id = args.id
    if type(id) == "table" then
        id = id[1]
    end

    if ngx.req.get_method() == "DELETE" then
        if not id or id == dict:get("current") then
            ngx.status = 400
            ngx.say('{"status":"error","message":"id of a closed incident required"}')
            return
        end
        dict:delete("inc:" .. id)
        local recent = cjson.decode(dict:get("recent") or "[]") or {}
        local kept = setmetatable({}, cjson.array_mt)
        for _, r in ipairs(recent) do
            if r.id ~= id then
                kept[#kept + 1] = r
            end
        end
        dict:set("recent", cjson.encode(kept))
        ngx.say('{"status":"success"}')
        return
    end

    if id then
        local raw = dict:get("inc:" .. id)
        if not raw then
            ngx.status = 404
            ngx.say('{"status":"error","message":"incident not found"}')
            return
        end
        ngx.say(raw)
        return
    end

    -- Stored JSON is spliced in as-is: a decode/encode round trip would turn
    -- empty arrays ([]) into objects ({}).
    local current = dict:get("current")
    ngx.say('{"current_id":', cjson.encode(current or cjson.null),
        ',"current":', current and dict:get("inc:" .. current) or "null",
        ',"recent":', dict:get("recent") or "[]",
        ',"detector":', dict:get("view") or "null", '}')
end

return _M
