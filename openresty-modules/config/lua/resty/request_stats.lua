local ngx = ngx
local site_resolver = require "resty.site_resolver"

local _M = { _VERSION = "1.3.0" }

local UNKNOWN_SITE = "0"

local EXCLUDED_RESPONSE_STATUSES = {
    [444] = true, [499] = true, [408] = true,
    [500] = true, [501] = true, [502] = true, [503] = true, [504] = true,
    [904] = true, [929] = true, [978] = true,
}

local METHOD_COUNTERS = {
    GET = "get_count",
    POST = "post_count",
    DELETE = "delete_count",
    PUT = "put_count",
    HEAD = "head_count",
    PATCH = "patch_count",
    OPTIONS = "options_count",
}

-- $upstream_cache_status → counter; empty / "-" / unknown is cache_dynamic_count.
local CACHE_STATUS_COUNTERS = {
    HIT = "cache_hit_count",
    STALE = "cache_stale_count",
    UPDATING = "cache_updating_count",
    REVALIDATED = "cache_revalidated_count",
    MISS = "cache_miss_count",
    EXPIRED = "cache_expired_count",
    BYPASS = "cache_bypass_count",
}
local CACHE_CACHED_STATUS = {
    HIT = true,
    STALE = true,
    UPDATING = true,
    REVALIDATED = true,
}
local CACHE_MISS_STATUS = {
    MISS = true,
    EXPIRED = true,
}

-- Upper bounds (ms) of the 11 non-cumulative latency buckets; the last is +Inf.
local LATENCY_BOUNDS_MS = { 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000 }
_M.LATENCY_BUCKETS = #LATENCY_BOUNDS_MS + 1

local CONTENT_TYPE_EXACT = {
    ["text/html"] = "html",
    ["application/xhtml+xml"] = "html",
    ["text/css"] = "css",
    ["application/vnd.apple.mpegurl"] = "video",
    ["application/x-mpegurl"] = "video",
    ["application/dash+xml"] = "video",
    ["application/pdf"] = "document",
    ["application/xml"] = "document",
    ["text/xml"] = "document",
    ["text/plain"] = "document",
    ["application/octet-stream"] = "binary",
    ["application/zip"] = "binary",
    ["application/wasm"] = "binary",
}
local CONTENT_TYPE_PREFIX = {
    image = "image",
    video = "video",
    audio = "audio",
    font = "font",
}
_M.CONTENT_TYPE_FAMILIES = {
    "html", "css", "js", "json", "image", "video", "audio", "font", "document", "binary", "other",
}

function _M.content_type_family(content_type)
    if not content_type or content_type == "" then
        return "other"
    end
    local mime = content_type:match("^%s*([^;%s]+)")
    if not mime then
        return "other"
    end
    mime = mime:lower()

    local exact = CONTENT_TYPE_EXACT[mime]
    if exact then
        return exact
    end
    local major, minor = mime:match("^([^/]+)/(.+)$")
    if not major then
        return "other"
    end
    if minor == "javascript" or minor == "ecmascript" or minor == "x-javascript" then
        return "js"
    end
    if minor == "json" or minor:sub(-5) == "+json" then
        return "json"
    end
    if major == "application" and minor:sub(1, 5) == "font-" then
        return "font"
    end
    return CONTENT_TYPE_PREFIX[major] or "other"
end

local function latency_bucket(ms)
    for i, bound in ipairs(LATENCY_BOUNDS_MS) do
        if ms <= bound then
            return i
        end
    end
    return #LATENCY_BOUNDS_MS + 1
end

-- nginx upstream lists look like "502, 200" or "-, 0.004 : 0.010" (retries / redirects).
local function last_token(list)
    local last
    if list then
        for tok in list:gmatch("[^,:%s]+") do
            last = tok
        end
    end
    return last
end

local function sum_tokens(list)
    local total, seen = 0, false
    if list then
        for tok in list:gmatch("[^,:%s]+") do
            local v = tonumber(tok)
            if v then
                total = total + v
                seen = true
            end
        end
    end
    return total, seen
end

_M.last_token = last_token
_M.sum_tokens = sum_tokens

function _M.upstream_contacted()
    local addr = ngx.var.upstream_addr
    return addr ~= nil and addr ~= "" and addr ~= "-"
end

--- Final origin status, or nil when no response header came back from origin.
function _M.final_upstream_status()
    local header_time = last_token(ngx.var.upstream_header_time)
    if not header_time or header_time == "-" then
        return nil
    end
    return tonumber(last_token(ngx.var.upstream_status))
end

function _M.upstream_response_time_ms()
    local secs, seen = sum_tokens(ngx.var.upstream_response_time)
    if not seen then
        return nil
    end
    return secs * 1000
end

function _M.upstream_bytes_received()
    return (sum_tokens(ngx.var.upstream_bytes_received))
end

local function request_domain()
    local host = ngx.var.host
    if not host or host == "" then
        return "-"
    end
    if #host > 253 then
        return host:sub(1, 253)
    end
    return host
end

--- Site id string used in shm keys. Unmapped Hosts are "0".
function _M.current_site_id()
    if ngx.ctx._stats_site_id then
        return ngx.ctx._stats_site_id
    end

    -- Survives ngx.exec (ctx does not). Empty means access phase has not resolved yet.
    local var_id = ngx.var.site_id
    if var_id and var_id ~= "" then
        ngx.ctx._stats_site_id = var_id
        return var_id
    end

    -- Cosockets (Redis) are disabled in log_by_lua.
    local id
    if ngx.get_phase() == "log" then
        id = site_resolver.lookup_site_id_cached()
    else
        id = site_resolver.lookup_site_id()
    end
    local sid = id and tostring(id) or UNKNOWN_SITE
    ngx.ctx._stats_site_id = sid
    ngx.var.site_id = sid
    return sid
end

local function incr(stats_cache, sid, name, n)
    n = n or 1
    stats_cache:incr(name, n, 0)
    stats_cache:incr("s:" .. sid .. ":" .. name, n, 0)
end

local function log_origin(stats_cache, sid)
    incr(stats_cache, sid, "origin_request_count", 1)
    incr(stats_cache, sid, "traffic_origin_rx", _M.upstream_bytes_received())

    local status = _M.final_upstream_status()
    if not status then
        if tonumber(last_token(ngx.var.upstream_status)) == 504 then
            incr(stats_cache, sid, "origin_timeout_count", 1)
        else
            incr(stats_cache, sid, "origin_error_count", 1)
        end
    elseif status >= 200 and status < 300 then
        incr(stats_cache, sid, "origin_code2xx", 1)
    elseif status >= 300 and status < 400 then
        incr(stats_cache, sid, "origin_code3xx", 1)
    elseif status >= 400 and status < 500 then
        incr(stats_cache, sid, "origin_code4xx", 1)
    elseif status >= 500 and status < 600 then
        incr(stats_cache, sid, "origin_code5xx", 1)
    else
        incr(stats_cache, sid, "origin_error_count", 1)
    end

    local origin_ms = _M.upstream_response_time_ms() or 0
    incr(stats_cache, sid, "origin_lat_h" .. latency_bucket(origin_ms), 1)
    incr(stats_cache, sid, "origin_latency_sum_ms", origin_ms)
end

function _M.log_response()
    local stats_cache = ngx.shared.stats_cache
    local sid = _M.current_site_id()
    local domain = request_domain()

    local response_size = tonumber(ngx.var.bytes_sent) or 0
    incr(stats_cache, sid, "traffic_l7_tx", response_size)
    stats_cache:incr("domain_tx:" .. sid .. ":" .. domain, response_size, 0)

    local status = ngx.status
    if status >= 200 and status < 600 and not EXCLUDED_RESPONSE_STATUSES[status] then
        incr(stats_cache, sid, "response_count", 1)
    end

    incr(stats_cache, sid, "code" .. status, 1)

    local method_counter = METHOD_COUNTERS[ngx.var.request_method]
    if method_counter then
        incr(stats_cache, sid, method_counter, 1)
    else
        incr(stats_cache, sid, "others_count", 1)
    end

    local proto = ngx.var.server_protocol or ""
    if proto == "HTTP/1.0" then
        incr(stats_cache, sid, "http1_0_count", 1)
    elseif proto == "HTTP/1.1" then
        incr(stats_cache, sid, "http1_1_count", 1)
    elseif proto:sub(1, 6) == "HTTP/2" then
        incr(stats_cache, sid, "http2_count", 1)
    elseif proto:sub(1, 6) == "HTTP/3" then
        incr(stats_cache, sid, "http3_count", 1)
    else
        incr(stats_cache, sid, "http1_1_count", 1)
    end

    if _M.upstream_contacted() then
        log_origin(stats_cache, sid)
    end

    -- Blocked requests are excluded so the cache counters sum to request_count - blocked.
    if ngx.var.acl_blocked == "1" then
        return
    end

    local request_ms = (tonumber(ngx.var.request_time) or 0) * 1000
    incr(stats_cache, sid, "edge_lat_h" .. latency_bucket(request_ms), 1)
    incr(stats_cache, sid, "edge_latency_sum_ms", request_ms)

    -- Available in log phase after proxy_cache; empty on nocache locations.
    local cache_status = ngx.var.upstream_cache_status or ""
    incr(stats_cache, sid, CACHE_STATUS_COUNTERS[cache_status] or "cache_dynamic_count", 1)
    local cached = CACHE_CACHED_STATUS[cache_status] == true
    if cached then
        incr(stats_cache, sid, "traffic_cached_tx", response_size)
    end

    local family = _M.content_type_family(ngx.var.sent_http_content_type)
    local ct_suffix = sid .. ":" .. family
    stats_cache:incr("ct_req:" .. ct_suffix, 1, 0)
    stats_cache:incr("ct_tx:" .. ct_suffix, response_size, 0)
    if cached then
        stats_cache:incr("ct_creq:" .. ct_suffix, 1, 0)
        stats_cache:incr("ct_ctx:" .. ct_suffix, response_size, 0)
    end

    local uri = ngx.var.uri or "/"
    if uri == "" then
        uri = "/"
    end
    local url_suffix = sid .. ":" .. domain .. " " .. uri
    stats_cache:incr("cmu_req:" .. url_suffix, 1, 0)
    if CACHE_MISS_STATUS[cache_status] then
        stats_cache:incr("cmu_miss:" .. url_suffix, 1, 0)
    end
end

function _M.track_request()
    local stats_cache = ngx.shared.stats_cache
    local interval = (stats_cache and stats_cache:get("STATS_INTERVAL")) or 60
    local sid = _M.current_site_id()
    local domain = request_domain()

    incr(stats_cache, sid, "request_count", 1)

    local request_size = tonumber(ngx.var.request_length) or 0
    incr(stats_cache, sid, "traffic_l7_rx", request_size)

    stats_cache:incr("domain_req_count:" .. sid .. ":" .. domain, 1, 0)
    stats_cache:incr("domain_rx:" .. sid .. ":" .. domain, request_size, 0)

    -- Seen markers carry the bucket start so "unique in the interval" follows bucket edges.
    local ip = ngx.var.remote_addr
    local bucket = math.floor(ngx.now() / interval) * interval
    if stats_cache:add("seen_ip:" .. bucket .. ":" .. ip, true, interval * 2) then
        stats_cache:incr("ip_count", 1, 0)
    end
    if stats_cache:add("seen_site_ip:" .. bucket .. ":" .. sid .. ":" .. ip, true, interval * 2) then
        stats_cache:incr("s:" .. sid .. ":ip_count", 1, 0)
    end

    stats_cache:incr("ip_req_count:" .. sid .. ":" .. ip, 1, 0)

    local uri = ngx.var.uri or "/"
    if uri == "" then
        uri = "/"
    end
    stats_cache:incr("url_req_count:" .. sid .. ":" .. uri, 1, 0)

    local ua = ngx.var.http_user_agent or "-"
    if #ua > 256 then
        ua = ua:sub(1, 256)
    end
    stats_cache:incr("ua_req_count:" .. sid .. ":" .. ua, 1, 0)

    local country, isp = "-", "-"
    local ok_geo, geo_lookup = pcall(require, "resty.geo_lookup")
    if ok_geo and geo_lookup and geo_lookup.get then
        local c, _, i = geo_lookup.get(ip)
        country = c or "-"
        isp = i or "-"
    end
    stats_cache:incr("country_req_count:" .. sid .. ":" .. country, 1, 0)
    ngx.var.stats_country = country ~= "-" and country or ""

    if #isp > 256 then
        isp = isp:sub(1, 256)
    end
    stats_cache:incr("isp_req_count:" .. sid .. ":" .. isp, 1, 0)

    local referer = ngx.var.http_referer or "-"
    if #referer > 512 then
        referer = referer:sub(1, 512)
    end
    stats_cache:incr("referer_req_count:" .. sid .. ":" .. referer, 1, 0)
end

return _M
