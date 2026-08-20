local ngx = ngx
local geo_lookup = require "resty.geo_lookup"
local site_resolver = require "resty.site_resolver"

local _M = { _VERSION = "1.2.0" }

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

    local id = site_resolver.lookup_site_id()
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

function _M.log_response()
    local stats_cache = ngx.shared.stats_cache
    local sid = _M.current_site_id()
    local domain = request_domain()

    local response_size = tonumber(ngx.var.bytes_sent) or 0
    incr(stats_cache, sid, "bandwidth_l7_tx", response_size)
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
end

function _M.track_request()
    local stats_cache = ngx.shared.stats_cache
    local interval = (stats_cache and stats_cache:get("STATS_INTERVAL")) or 60
    local sid = _M.current_site_id()
    local domain = request_domain()

    incr(stats_cache, sid, "request_count", 1)

    local request_size = tonumber(ngx.var.request_length) or 0
    incr(stats_cache, sid, "traffic_l7_rx", request_size)
    incr(stats_cache, sid, "bandwidth_l7_rx", request_size)

    stats_cache:incr("domain_req_count:" .. sid .. ":" .. domain, 1, 0)
    stats_cache:incr("domain_rx:" .. sid .. ":" .. domain, request_size, 0)

    local ip = ngx.var.remote_addr
    local ip_key = "ip:" .. ip
    if not stats_cache:get(ip_key) then
        stats_cache:set(ip_key, true, interval)
        stats_cache:incr("ip_count", 1, 0)
    end
    local site_ip_key = "s:" .. sid .. ":seen_ip:" .. ip
    if not stats_cache:get(site_ip_key) then
        stats_cache:set(site_ip_key, true, interval)
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

    local country, _, isp = geo_lookup.get(ip)
    stats_cache:incr("country_req_count:" .. sid .. ":" .. country, 1, 0)

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
