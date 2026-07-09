-- Shared per-request geo lookup (stored in ngx.ctx).

local maxminddb = require "resty.maxminddb"
local ngx = ngx

local _M = { _VERSION = "1.0.0" }

function _M.get(ip)
    if ngx.ctx._geo then
        return ngx.ctx._geo.country, ngx.ctx._geo.city, ngx.ctx._geo.isp
    end

    ip = ip or ngx.var.remote_addr or ""
    local country = "-"
    local city = "-"
    local isp = "-"

    if ip ~= "" and maxminddb.initted and maxminddb.initted() then
        local c = maxminddb.lookup_iso_code(ip)
        if c and c ~= "" then
            country = c
        else
            c = maxminddb.lookup_country and select(1, maxminddb.lookup_country(ip))
            if c and c ~= "" then
                country = c
            end
        end

        local city_name = maxminddb.lookup_city and select(1, maxminddb.lookup_city(ip))
        if city_name and city_name ~= "" then
            city = city_name
        end

        local isp_name = maxminddb.lookup_isp and maxminddb.lookup_isp(ip)
        if isp_name and isp_name ~= "" then
            isp = isp_name
        end
    end

    ngx.ctx._geo = {
        country = country,
        city = city,
        isp = isp,
    }

    return country, city, isp
end

function _M.country(ip)
    return select(1, _M.get(ip))
end

return _M
