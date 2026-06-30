local ngx = ngx

local _M = { _VERSION = "1.0.0" }

local EXCLUDED_RESPONSE_STATUSES = {
    [444] = true, [499] = true, [408] = true,
    [500] = true, [501] = true, [502] = true, [503] = true, [504] = true,
    [904] = true, [929] = true, [978] = true,
}

function _M.log_response()
    local stats_cache = ngx.shared.stats_cache

    local response_size = tonumber(ngx.var.bytes_sent) or 0
    stats_cache:incr("bandwidth_l7_tx", response_size, 0)
    stats_cache:incr("traffic_l7_tx", response_size, 0)

    local status = ngx.status
    if status >= 200 and status < 600 and not EXCLUDED_RESPONSE_STATUSES[status] then
        stats_cache:incr("response_count", 1, 0)
    end

    stats_cache:incr("code" .. status, 1, 0)

    local method = ngx.var.request_method
    if method == "GET" then
        stats_cache:incr("get_count", 1, 0)
    elseif method == "POST" then
        stats_cache:incr("post_count", 1, 0)
    elseif method == "DELETE" then
        stats_cache:incr("delete_count", 1, 0)
    elseif method == "PUT" then
        stats_cache:incr("put_count", 1, 0)
    elseif method == "HEAD" then
        stats_cache:incr("head_count", 1, 0)
    elseif method == "PATCH" then
        stats_cache:incr("patch_count", 1, 0)
    elseif method == "OPTIONS" then
        stats_cache:incr("options_count", 1, 0)
    else
        stats_cache:incr("others_count", 1, 0)
    end

    local proto = ngx.var.server_protocol or ""
    if proto == "HTTP/1.0" then
        stats_cache:incr("http1_0_count", 1, 0)
    elseif proto == "HTTP/1.1" then
        stats_cache:incr("http1_1_count", 1, 0)
    elseif proto:sub(1, 6) == "HTTP/2" then
        stats_cache:incr("http2_count", 1, 0)
    elseif proto:sub(1, 6) == "HTTP/3" then
        stats_cache:incr("http3_count", 1, 0)
    else
        stats_cache:incr("http1_1_count", 1, 0)
    end
end

function _M.track_request()
    local stats_cache = ngx.shared.stats_cache
    local interval = (stats_cache and stats_cache:get("STATS_INTERVAL")) or 60

    stats_cache:incr("request_count", 1, 0)

    local request_size = tonumber(ngx.var.request_length) or 0
    stats_cache:incr("traffic_l7_rx", request_size, 0)
    stats_cache:incr("bandwidth_l7_rx", request_size, 0)

    local ip = ngx.var.remote_addr
    local ip_key = "ip:" .. ip
    if not stats_cache:get(ip_key) then
        stats_cache:set(ip_key, true, interval)
        stats_cache:incr("ip_count", 1, 0)
    end

    stats_cache:incr("ip_req_count:" .. ip, 1, 0)

    local uri = ngx.var.uri or "/"
    if uri == "" then
        uri = "/"
    end
    stats_cache:incr("url_req_count:" .. uri, 1, 0)

    local ua = ngx.var.http_user_agent or "-"
    if #ua > 256 then
        ua = ua:sub(1, 256)
    end
    stats_cache:incr("ua_req_count:" .. ua, 1, 0)

    local country = "-"
    local isp = "-"
    do
        local ok_mm, maxminddb = pcall(require, "resty.maxminddb")
        if ok_mm and maxminddb and maxminddb.initted and maxminddb.initted() then
            local c = maxminddb.lookup_iso_code(ip)
            if c and c ~= "" then
                country = c
            end
            local isp_name = maxminddb.lookup_isp and maxminddb.lookup_isp(ip)
            if isp_name and isp_name ~= "" then
                isp = isp_name
            end
        end
    end

    stats_cache:incr("country_req_count:" .. country, 1, 0)

    if #isp > 256 then
        isp = isp:sub(1, 256)
    end
    stats_cache:incr("isp_req_count:" .. isp, 1, 0)

    local referer = ngx.var.http_referer or "-"
    if #referer > 512 then
        referer = referer:sub(1, 512)
    end
    stats_cache:incr("referer_req_count:" .. referer, 1, 0)
end

return _M
