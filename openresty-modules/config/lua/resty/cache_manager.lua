-- Dynamic cache rules from Redis key cache:{site_id}.
-- Rule fields: rule_name, rule_type (url|file), caching_time, url, file_types,
-- priority, cache_slice (megabytes, float e.g. 10.21 = 10.21 MB), without_parameter (yes|no), cache_mode (origin|force)
--
-- cache_mode origin: follow upstream Cache-Control (no-store/private/no-cache => no cache;
--   max-age/s-maxage => min(origin, caching_time); public without max-age => caching_time;
--   no Cache-Control header => caching_time).
-- cache_mode force: ignore Cache-Control and always cache for caching_time seconds.

local redis = require "resty.redis"
local cjson = require "cjson.safe"
local handle_slice = require "resty.handle_slice"
local site_resolver = require "resty.site_resolver"
local ngx = ngx

local _M = { _VERSION = "2.0.0" }

-- Per-worker L1 cache: { [site_id] = { rules=..., version=... } }
local l1 = {}

local REDIS_SOCK  = "unix:/tmp/redis.sock"
local SHM_NAME    = "cache_rules"
local REFRESH_SEC = 5
local SLICE_MB_BYTES = 1024 * 1024

local function slice_mb_to_bytes(slice_mb)
    local mb = tonumber(slice_mb) or 0
    if mb <= 0 then
        return 0
    end
    return math.floor(mb * SLICE_MB_BYTES)
end

local function log_err(msg)
    ngx.log(ngx.ERR, "cache_manager: ", msg)
end

local function log_debug(msg)
    ngx.log(ngx.DEBUG, "cache_manager: ", msg)
end

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 2000)
    local ok, err = red:connect(REDIS_SOCK)
    if not ok then
        return nil, err
    end
    return red
end

local function normalize_rule(item)
    if type(item) ~= "table" then
        return nil
    end

    local rule_name = tostring(item.rule_name or ""):match("^%s*(.-)%s*$")
    if rule_name == "" then
        return nil
    end

    local rule_type = tostring(item.rule_type or "file"):lower()
    if rule_type ~= "url" and rule_type ~= "file" then
        rule_type = "file"
    end

    local caching_time = tonumber(item.caching_time) or 0
    if caching_time < 0 then
        caching_time = 0
    end

    local priority = tonumber(item.priority) or 1000
    local cache_slice = tonumber(item.cache_slice) or 0
    if cache_slice < 0 then
        cache_slice = 0
    end
    -- Stored as megabytes (float); converted to bytes when applied to ngx_slice.

    local without_parameter = tostring(item.without_parameter or "no"):lower()
    without_parameter = (without_parameter == "yes" or without_parameter == "true" or without_parameter == "1")

    local cache_mode = tostring(item.cache_mode or "origin"):lower()
    if cache_mode ~= "force" then
        cache_mode = "origin"
    end

    local url = tostring(item.url or "")
    local file_types = tostring(item.file_types or "")

    local extensions = {}
    for ext in file_types:gmatch("[^,%s]+") do
        ext = ext:lower():gsub("^%.", "")
        if ext ~= "" then
            extensions[ext] = true
        end
    end

    return {
        rule_name = rule_name,
        rule_type = rule_type,
        caching_time = caching_time,
        url = url,
        file_types = file_types,
        extensions = extensions,
        priority = priority,
        cache_slice = cache_slice,
        without_parameter = without_parameter,
        cache_mode = cache_mode,
    }
end

local function load_from_redis(site_id)
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local key = "cache:" .. tostring(site_id)
    local raw = red:get(key)
    red:set_keepalive(10000, 100)

    if not raw or raw == ngx.null or raw == "" then
        return {}
    end

    local list, jerr = cjson.decode(raw)
    if type(list) ~= "table" then
        log_err("invalid JSON for " .. key .. ": " .. tostring(jerr))
        return {}
    end

    local rules = {}
    for _, item in ipairs(list) do
        local rule = normalize_rule(item)
        if rule then
            rules[#rules + 1] = rule
        end
    end

    table.sort(rules, function(a, b)
        if a.priority == b.priority then
            return a.rule_name < b.rule_name
        end
        return a.priority < b.priority
    end)

    return rules
end

local function refresh_shm()
    local dict = ngx.shared[SHM_NAME]
    if not dict then
        return
    end

    local site_domains = site_resolver.list_site_domains()
    local now = ngx.time()
    local site_ids = {}

    for site_id, _ in pairs(site_domains) do
        local rules, err = load_from_redis(site_id)
        if err then
            ngx.log(ngx.WARN, "cache_manager: load failed for site ", site_id, ": ", tostring(err))
        else
            local sid = tostring(site_id)
            dict:set("rules:" .. sid, cjson.encode(rules), 0)
            dict:set("updated:" .. sid, now, 0)
            l1[sid] = { rules = rules, version = now }
            site_ids[#site_ids + 1] = sid
            log_debug("loaded " .. tostring(#rules) .. " cache rule(s) for site " .. sid)
        end
    end

    dict:set("sites", table.concat(site_ids, ","), 0)
    dict:set("updated", now, 0)
end

local function get_rules(site_id)
    site_id = site_id or site_resolver.lookup_site_id()
    if not site_id then
        return {}
    end

    local sid = tostring(site_id)
    local dict = ngx.shared[SHM_NAME]
    local shm_version = dict and (dict:get("updated:" .. sid) or 0) or 0
    local entry = l1[sid]

    if entry and entry.version == shm_version and shm_version > 0 then
        return entry.rules
    end

    if dict then
        local raw = dict:get("rules:" .. sid)
        if raw and raw ~= "" then
            local decoded = cjson.decode(raw)
            if type(decoded) == "table" then
                l1[sid] = { rules = decoded, version = shm_version }
                return decoded
            end
        end
    end

    local loaded, err = load_from_redis(site_id)
    if loaded then
        local now = ngx.time()
        if dict then
            dict:set("rules:" .. sid, cjson.encode(loaded), 0)
            dict:set("updated:" .. sid, now, 0)
        end
        l1[sid] = { rules = loaded, version = now }
        return loaded
    end

    if err then
        log_err("redis load failed for site " .. sid .. ": " .. tostring(err))
    end
    return (entry and entry.rules) or {}
end

local function get_extension(uri)
    local ext = uri:match("%.([^%.%/]+)$")
    return ext and ext:lower() or nil
end

local function match_file_rule(rule, uri)
    local ext = get_extension(uri)
    if not ext then
        return false
    end
    return rule.extensions[ext] == true
end

local function match_url_rule(rule, uri)
    local pattern = rule.url
    if pattern == "" then
        return false
    end

    if pattern == ".*" or pattern == "^.*$" then
        return true
    end

    local ok, matched = pcall(ngx.re.find, uri, pattern, "jo")
    return ok and matched ~= nil
end

local function match_rule(rules, uri)
    for _, rule in ipairs(rules) do
        if rule.rule_type == "file" then
            if match_file_rule(rule, uri) then
                return rule
            end
        elseif rule.rule_type == "url" then
            if match_url_rule(rule, uri) then
                return rule
            end
        end
    end
    return nil
end

local function find_rule_by_name(name)
    if not name or name == "" then
        return nil
    end
    for _, rule in ipairs(get_rules()) do
        if rule.rule_name == name then
            return rule
        end
    end
    return nil
end

-- ngx.ctx is cleared across ngx.exec(); recover the matched rule from variables.
local function get_active_rule()
    if ngx.ctx.cache_rule then
        return ngx.ctx.cache_rule
    end

    local rule = find_rule_by_name(ngx.var.cache_rule_name)
    if rule then
        ngx.ctx.cache_rule = rule
    end
    return rule
end

local function disable_cache()
    ngx.var.cache_enabled = "0"
    ngx.var.cache_rule_name = ""
    ngx.var.cache_slice_size = "0"
    ngx.var.cache_inactive_ttl = "0"
    ngx.ctx.cache_rule = nil
end

local function enable_cache(rule, uri)
    ngx.ctx.cache_rule = rule
    ngx.var.cache_rule_name = rule.rule_name or ""
    ngx.var.cache_slice_size = tostring(slice_mb_to_bytes(rule.cache_slice))

    if rule.without_parameter then
        ngx.var.cache_key_uri = uri
    else
        local args = ngx.var.args
        if args and args ~= "" then
            ngx.var.cache_key_uri = uri .. "?" .. args
        else
            ngx.var.cache_key_uri = uri
        end
    end

    ngx.var.cache_enabled = "1"

    local caching_time = tonumber(rule.caching_time) or 0
    if caching_time > 0 then
        -- Must be set in access phase so ngx_cache_purge C indexer reads the
        -- rule TTL (not proxy_cache_path inactive=60m) when registering in Redis.
        ngx.var.cache_inactive_ttl = tostring(math.floor(caching_time))
    end
end

local function apply_slice(rule)
    local slice_size = slice_mb_to_bytes(rule.cache_slice)
    if slice_size <= 0 then
        return false
    end

    local set_ok, err = handle_slice.set_slice(slice_size)
    if not set_ok then
        log_err("set_slice(" .. slice_size .. ") failed: " .. tostring(err))
        return false
    end

    ngx.ctx.cache_slice = slice_size
    return true
end

function _M.setup_slice()
    local rule = get_active_rule()
    if not rule then
        log_err("setup_slice: no active cache rule")
        return
    end
    apply_slice(rule)
end

local function wants_slice(rule)
    return (tonumber(rule.cache_slice) or 0) > 0
end

local function exec_cache_location(rule, use_slice)
    if rule.cache_mode == "force" then
        if use_slice then
            return ngx.exec("@proxy_cache_force_slice")
        end
        return ngx.exec("@proxy_cache_force")
    end

    if use_slice then
        return ngx.exec("@proxy_cache_origin_slice")
    end
    return ngx.exec("@proxy_cache_origin")
end

function _M.start_refresh()
    local function run(premature)
        if premature or ngx.worker.exiting() then
            return
        end
        refresh_shm()
        ngx.timer.at(REFRESH_SEC, run)
    end

    -- Defer first Redis load: cosockets are not allowed in init_worker_by_lua.
    local ok, err = ngx.timer.at(0, run)
    if not ok then
        log_err("failed to start refresh timer: " .. tostring(err))
    else
        log_debug("refresh timer started for key cache:{site_id}")
    end
end

function _M.apply()
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then
        disable_cache()
        return
    end

    local uri = ngx.var.uri or "/"
    if uri == "" then
        uri = "/"
    end

    local site_id = site_resolver.lookup_site_id()
    local rules = get_rules(site_id)
    local rule = match_rule(rules, uri)
    if not rule or rule.caching_time <= 0 then
        disable_cache()
        return
    end

    enable_cache(rule, uri)
    return exec_cache_location(rule, wants_slice(rule))
end

local function cap_ttl(ttl, rule)
    if ttl > rule.caching_time then
        return rule.caching_time
    end
    return ttl
end

local function set_cache_lifetime(ttl)
    local seconds = tonumber(ttl) or 0
    if seconds < 0 then
        seconds = 0
    end
    seconds = math.floor(seconds)
    ngx.var.cache_inactive_ttl = tostring(seconds)
    ngx.header["X-Accel-Expires"] = tostring(seconds)
end

local function set_origin_cache_ttl(rule)
    local cc = ngx.header["Cache-Control"]

    -- No Cache-Control: cache using the CDN rule TTL.
    if not cc or cc == "" then
        set_cache_lifetime(rule.caching_time)
        return
    end

    local lower = string.lower(tostring(cc))

    -- Origin mode must respect non-cacheable directives.
    if lower:find("no%-store") or lower:find("private") or lower:find("no%-cache") then
        set_cache_lifetime(0)
        return
    end

    local max_age = lower:match("max%-age=(%d+)")
    if max_age then
        local ttl = tonumber(max_age) or 0
        set_cache_lifetime(ttl > 0 and cap_ttl(ttl, rule) or 0)
        return
    end

    local s_maxage = lower:match("s%-maxage=(%d+)")
    if s_maxage then
        local ttl = tonumber(s_maxage) or 0
        set_cache_lifetime(ttl > 0 and cap_ttl(ttl, rule) or 0)
        return
    end

    -- public without max-age/s-maxage: use CDN configured TTL.
    if lower:find("public") then
        set_cache_lifetime(rule.caching_time)
        return
    end

    -- Unrecognized / non-cacheable Cache-Control.
    set_cache_lifetime(0)
end

local function set_force_cache_ttl(rule)
    -- Force mode ignores upstream cache directives entirely.
    ngx.header["Set-Cookie"] = nil
    ngx.header["Cache-Control"] = nil
    ngx.header["Expires"] = nil
    set_cache_lifetime(rule.caching_time)
end

function _M.set_cache_headers()
    local rule = get_active_rule()
    if not rule then
        return
    end

    if ngx.status ~= 200 and ngx.status ~= 304 and ngx.status ~= 206 then
        set_cache_lifetime(0)
        return
    end

    if rule.cache_mode == "force" then
        set_force_cache_ttl(rule)
        return
    end

    set_origin_cache_ttl(rule)
end

return _M
