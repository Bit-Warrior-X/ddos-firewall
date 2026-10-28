-- Dynamic upstream list from Redis key upstreamservers:{site_id}.
-- Expected JSON: [ { "ip_port": "192.168.1.199:100", "description": "weight=4 ..." }, ... ]
--
-- Per-port pools from originroutes:{site_id} take precedence:
--   { "http":  [ { "ports": [80], "upstreams": [ { ip_port, protocol, description } ] } ],
--     "https": [ ... ] }
-- A request on (scheme, server_port) listed in a rule uses that rule's pool.
-- When a site has routes, any other port has no origin (502). Sites without
-- routes use the flat upstreamservers pool for every port.

local redis  = require "resty.redis"
local cjson  = require "cjson.safe"
local site_resolver = require "resty.site_resolver"
local ngx    = ngx
local log    = ngx.log
local ERR    = ngx.ERR
local WARN   = ngx.WARN
local INFO   = ngx.INFO
local timer  = ngx.timer.at
local worker = ngx.worker
local shd    = ngx.shared

local _M = { _VERSION = "2.0.0" }

local REDIS_SOCK      = "unix:/tmp/redis.sock"
local SHM_NAME        = "upstream_servers"
local REFRESH_SEC     = 5
-- Never proxy to the internal :9000 stats server — that returns
-- "Welcome to Default Server" and leaks onto customer Hosts.
-- Callers must treat nil as "no upstream" (typically HTTP 502).
local DEFAULT_BACKEND = nil

-- Per-worker L1: { [site_id] = { list=..., version=... } }
local l1 = {}
-- Per-worker L1 for routes: { [site_id] = { routes=table|false, version=... } }
local l1_routes = {}
local ROUTE_SCHEMES = { "http", "https" }

local function parse_description(desc)
    if not desc or type(desc) ~= "string" then
        return { weight = 1, max_fails = 3, fail_timeout = 30 }
    end
    local weight = 1
    local max_fails = 3
    local fail_timeout = 30
    for k, v in desc:gmatch("(%w+)=([%d]+)") do
        if k == "weight" then
            weight = tonumber(v) or 1
        elseif k == "max_fails" then
            max_fails = tonumber(v) or 3
        elseif k == "fail_timeout" then
            fail_timeout = tonumber(v) or 30
        end
    end
    return { weight = weight, max_fails = max_fails, fail_timeout = fail_timeout }
end

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 2000)
    -- Dedicated pool so DB-2 cache_purge connections never poison site upstream reads.
    local ok, err = red:connect(REDIS_SOCK, { pool = "athens_redis_db0" })
    if not ok then
        log(ERR, "upstream_redis: redis connect failed: ", tostring(err))
        return nil, err
    end
    local ok_sel, sel_err = red:select(0)
    if not ok_sel then
        red:close()
        return nil, sel_err or "select_0_failed"
    end
    return red
end

local function normalize_list(list)
    local out = {}
    if type(list) ~= "table" then
        return out
    end
    for _, item in ipairs(list) do
        if type(item) == "table" and item.ip_port and item.ip_port ~= "" then
            local desc = parse_description(item.description)
            table.insert(out, {
                host_port = item.ip_port,
                weight    = desc.weight
            })
        end
    end
    return out
end

local function load_from_redis(site_id)
    local red, err = get_redis()
    if not red then return nil, err end
    local key = "upstreamservers:" .. tostring(site_id)
    local raw, rerr = red:get(key)
    red:set_keepalive(10000, 100)
    if rerr then
        return nil, rerr
    end
    if not raw or raw == ngx.null or raw == "" then
        -- Distinguish "no config" from Redis errors; empty is a real miss.
        return {}, nil
    end
    local list, jerr = cjson.decode(raw)
    if not list or type(list) ~= "table" then
        log(WARN, "upstream_redis: invalid JSON for ", key, " ", tostring(jerr))
        return nil, "invalid_json"
    end
    return normalize_list(list)
end

-- { http = { ["80"] = { "http://10.0.0.1:8080", ... } }, https = { ... } } or nil.
-- Each pool is pre-expanded by weight; upstream protocol defaults to the route scheme.
local function compile_routes(routes)
    if type(routes) ~= "table" then
        return nil
    end
    local out, any = { http = {}, https = {} }, false
    for _, scheme in ipairs(ROUTE_SCHEMES) do
        local rules = routes[scheme]
        if type(rules) == "table" then
            for _, rule in ipairs(rules) do
                if type(rule) == "table" and type(rule.ports) == "table"
                        and type(rule.upstreams) == "table" then
                    local urls = {}
                    for _, u in ipairs(rule.upstreams) do
                        if type(u) == "table" and type(u.ip_port) == "string" and u.ip_port ~= "" then
                            local proto = (u.protocol == "http" or u.protocol == "https")
                                and u.protocol or scheme
                            local w = math.max(1, math.floor(parse_description(u.description).weight or 1))
                            for _ = 1, w do
                                urls[#urls + 1] = proto .. "://" .. u.ip_port
                            end
                        end
                    end
                    if #urls > 0 then
                        for _, p in ipairs(rule.ports) do
                            local port = tonumber(p)
                            if port then
                                out[scheme][tostring(math.floor(port))] = urls
                                any = true
                            end
                        end
                    end
                end
            end
        end
    end
    return any and out or nil
end

-- Returns compiled routes, or nil when the site has none (key absent / empty).
local function load_routes_from_redis(site_id)
    local red, err = get_redis()
    if not red then return nil, err end
    local raw, rerr = red:get("originroutes:" .. tostring(site_id))
    red:set_keepalive(10000, 100)
    if rerr then
        return nil, rerr
    end
    if not raw or raw == ngx.null or raw == "" then
        return nil, nil
    end
    local routes, jerr = cjson.decode(raw)
    if not routes then
        log(WARN, "upstream_redis: invalid JSON for originroutes:", tostring(site_id), " ", tostring(jerr))
        return nil, "invalid_json"
    end
    return compile_routes(routes), nil
end

-- Version is a shared counter (not ngx.time) so two publishes in the same
-- second still invalidate other workers' L1.
local function publish_routes(dict, site_id, routes)
    local sid = tostring(site_id)
    if routes then
        dict:set("routes:" .. sid, cjson.encode(routes), 0)
    else
        dict:delete("routes:" .. sid)
    end
    local version = dict:incr("routes_gen", 1, 0) or ngx.now()
    dict:set("routes_updated:" .. sid, version, 0)
    l1_routes[sid] = { routes = routes or false, version = version }
    return version
end

local function publish_list(dict, site_id, list, version)
    if not dict or not list or #list == 0 then
        return false
    end
    local sid = tostring(site_id)
    dict:set("list:" .. sid, cjson.encode(list), 0)
    dict:set("updated:" .. sid, version or ngx.time(), 0)
    l1[sid] = { list = list, version = version or ngx.time() }
    return true
end

local function expand_by_weight(list)
    local expanded = {}
    for _, s in ipairs(list) do
        local w = math.max(1, math.floor(s.weight or 1))
        for _ = 1, w do
            expanded[#expanded + 1] = s.host_port
        end
    end
    return expanded
end

local function refresh_shm()
    local dict = shd[SHM_NAME]
    if not dict then return end

    local site_domains = site_resolver.list_site_domains()
    local version = ngx.time()
    local site_ids = {}

    for site_id, _ in pairs(site_domains) do
        local routes, route_err = load_routes_from_redis(site_id)
        if route_err then
            -- Keep last-known-good routes on transient Redis errors.
            log(WARN, "upstream_redis: route load failed for site ", site_id, ": ", tostring(route_err))
        else
            publish_routes(dict, site_id, routes)
        end

        local list, err = load_from_redis(site_id)
        if err then
            -- Keep last-known-good upstreams on transient Redis errors.
            log(WARN, "upstream_redis: load failed for site ", site_id, ": ", tostring(err))
            if dict:get("list:" .. tostring(site_id)) then
                site_ids[#site_ids + 1] = tostring(site_id)
            end
        else
            local expanded = expand_by_weight(list)
            if #expanded > 0 then
                publish_list(dict, site_id, expanded, version)
                site_ids[#site_ids + 1] = tostring(site_id)
            else
                -- Keep last-known-good; only warn when we had nothing cached
                -- (otherwise a transient empty read would spam every refresh).
                local prev = dict:get("list:" .. tostring(site_id))
                if prev and prev ~= "" and prev ~= "[]" then
                    site_ids[#site_ids + 1] = tostring(site_id)
                else
                    log(WARN, "upstream_redis: empty upstream list for site ",
                        site_id, " (no previous cache)")
                end
            end
        end
    end

    dict:set("sites", table.concat(site_ids, ","), 0)
    dict:set("updated", version, 0)
end

-- Returns (origin_url, site_has_routes). A routed site with no pool for this
-- (scheme, server_port) gets (nil, true): the port is not served.
local function route_backend(dict, site_id, sid)
    local version = dict:get("routes_updated:" .. sid)
    if not version then
        -- Refresh has not seen this site yet: load once and remember "none" too.
        local routes, err = load_routes_from_redis(site_id)
        if err then
            return nil
        end
        version = publish_routes(dict, site_id, routes)
    end

    local entry = l1_routes[sid]
    if not entry or entry.version ~= version then
        local raw = dict:get("routes:" .. sid)
        entry = { routes = (raw and cjson.decode(raw)) or false, version = version }
        l1_routes[sid] = entry
    end
    if not entry.routes then
        return nil
    end

    local scheme = ngx.var.scheme
    local port = ngx.var.server_port
    local by_port = entry.routes[scheme]
    local pool = by_port and port and by_port[port]
    if type(pool) ~= "table" or #pool == 0 then
        return nil, true
    end
    local rr_key = "round_robin:" .. sid .. ":" .. scheme .. ":" .. port
    local idx = dict:incr(rr_key, 1, 0) or 1
    return pool[(idx - 1) % #pool + 1], true
end

function _M.get_backend(site_id)
    site_id = site_id or site_resolver.lookup_site_id()
    if not site_id then
        return DEFAULT_BACKEND
    end

    local sid = tostring(site_id)
    local dict = shd[SHM_NAME]
    if not dict then
        return DEFAULT_BACKEND
    end

    local routed, has_routes = route_backend(dict, site_id, sid)
    if has_routes then
        -- Strict: the flat upstream_servers union must not serve unrouted ports.
        return routed or DEFAULT_BACKEND
    end

    local version = dict:get("updated:" .. sid) or 0
    local entry = l1[sid]
    local list = entry and entry.list
    if not list or not entry or entry.version ~= version then
        local raw = dict:get("list:" .. sid)
        if not raw or raw == "" or raw == "[]" then
            -- Lazy load once if refresh has not populated this site yet.
            local loaded, lerr = load_from_redis(site_id)
            if lerr then
                log(WARN, "upstream_redis: lazy load failed for site ", sid, ": ", tostring(lerr))
                return DEFAULT_BACKEND
            end
            list = expand_by_weight(loaded or {})
            if #list > 0 then
                publish_list(dict, site_id, list, ngx.time())
            else
                return DEFAULT_BACKEND
            end
        else
            list = cjson.decode(raw)
            if not list or #list == 0 then
                return DEFAULT_BACKEND
            end
            l1[sid] = { list = list, version = version }
        end
    end

    if not list or #list == 0 then
        return DEFAULT_BACKEND
    end

    local rr_key = "round_robin:" .. sid
    local idx = dict:incr(rr_key, 1, 0)
    if idx == nil then
        dict:set(rr_key, 1, 0)
        idx = 1
    end
    local host_port = list[(idx - 1) % #list + 1]
    if type(host_port) ~= "string" or host_port == "" then
        return DEFAULT_BACKEND
    end
    return "http://" .. host_port
end

function _M.start_refresh()
    local function run(premature)
        if premature or worker.exiting() then return end
        refresh_shm()
        timer(REFRESH_SEC, run)
    end
    local ok, err = timer(0.5, run)
    if not ok then
        log(ERR, "upstream_redis: failed to start refresh timer: ", tostring(err))
    else
        log(INFO, "upstream_redis: refresh timer started for upstreamservers:{site_id}")
    end
end

return _M
