-- Fetch real-time per-Host egress bandwidth from ngx_req_status (/req-status)
-- and aggregate it by site_id via Redis domain:{host} mapping.

local cjson = require "cjson.safe"
local site_resolver = require "resty.site_resolver"

local _M = { _VERSION = "1.0.0" }

local REQ_STATUS_HOST = "127.0.0.1"
local REQ_STATUS_PORT = 9000
local REQ_STATUS_URI = "/req-status?zone_name=host"
local CONNECT_TIMEOUT_MS = 500
local IO_TIMEOUT_MS = 1000

local function normalize_host(host)
    if not host or host == "" then
        return ""
    end
    host = tostring(host)
    host = host:match("^([^:]+)") or host
    return host:lower()
end

local function host_to_site_map()
    local map = {}
    local site_domains = site_resolver.list_site_domains() or {}
    for sid, domains in pairs(site_domains) do
        if type(domains) == "table" then
            for _, host in ipairs(domains) do
                local h = normalize_host(host)
                if h ~= "" then
                    map[h] = tostring(sid)
                end
            end
        end
    end
    return map
end

local function decode_body(body)
    if not body or body == "" then
        return nil, "empty body"
    end
    local obj, decode_err = cjson.decode(body)
    if type(obj) ~= "table" then
        return nil, "json decode failed: " .. tostring(decode_err or "invalid")
    end
    return obj
end

local function fetch_via_capture()
    local phase = ngx.get_phase()
    if phase ~= "content" and phase ~= "rewrite" and phase ~= "access" then
        return nil, "capture unavailable in phase " .. tostring(phase)
    end
    local res = ngx.location.capture("/req-status", {
        args = { zone_name = "host" },
    })
    if not res or res.status ~= 200 then
        return nil, "capture status " .. tostring(res and res.status)
    end
    return decode_body(res.body)
end

local function fetch_via_cosocket()
    local sock = ngx.socket.tcp()
    sock:settimeout(CONNECT_TIMEOUT_MS)

    local ok, err = sock:connect(REQ_STATUS_HOST, REQ_STATUS_PORT)
    if not ok then
        return nil, "connect failed: " .. tostring(err)
    end

    sock:settimeout(IO_TIMEOUT_MS)

    local req = table.concat({
        "GET ", REQ_STATUS_URI, " HTTP/1.0\r\n",
        "Host: ", REQ_STATUS_HOST, "\r\n",
        "Connection: close\r\n",
        "\r\n",
    })

    local bytes, send_err = sock:send(req)
    if not bytes then
        sock:close()
        return nil, "send failed: " .. tostring(send_err)
    end

    local chunks = {}
    while true do
        local data, read_err, partial = sock:receive(8192)
        if data then
            chunks[#chunks + 1] = data
        elseif partial and partial ~= "" then
            chunks[#chunks + 1] = partial
        end
        if read_err == "closed" then
            break
        end
        if read_err and read_err ~= "closed" then
            sock:close()
            return nil, "read failed: " .. tostring(read_err)
        end
        if not data and not partial then
            break
        end
    end
    sock:close()

    local raw = table.concat(chunks)
    local body = raw:match("\r\n\r\n(.*)$") or raw:match("\n\n(.*)$")
    return decode_body(body)
end

--- HTTP GET /req-status (capture in request phases; cosocket in timers).
function _M.fetch()
    local obj, err = fetch_via_capture()
    if obj then
        return obj
    end
    return fetch_via_cosocket()
end

--- Return { [domain_lower] = bandwidth_bits_per_sec } from ngx_req_status.
function _M.domain_bandwidth()
    local obj, err = _M.fetch()
    if not obj then
        ngx.log(ngx.WARN, "req_status: fetch failed: ", tostring(err))
        return {}, err
    end

    local out = {}
    local data = obj.data
    if type(data) ~= "table" then
        return out
    end

    for _, item in ipairs(data) do
        if type(item) == "table" and item.domain then
            local domain = normalize_host(item.domain)
            if domain ~= "" then
                local bw = tonumber(item.bandwidth) or 0
                out[domain] = (out[domain] or 0) + bw
            end
        end
    end
    return out
end

--- Return { [site_id_str] = bandwidth_bits_per_sec } summed across a site's Hosts.
--- Unmapped Hosts are attributed to site "0".
function _M.site_bandwidth()
    local by_domain, err = _M.domain_bandwidth()
    local by_site = {}
    if not next(by_domain) and err then
        return by_site, err
    end

    local host_map = host_to_site_map()
    for domain, bw in pairs(by_domain) do
        local sid = host_map[domain] or "0"
        by_site[sid] = (by_site[sid] or 0) + bw
    end
    return by_site, err
end

return _M
