local ngx = ngx
local handle_acl = require "resty.handle_acl"
local geo_lookup = require "resty.geo_lookup"
local temp_blacklist = require "resty.temp_blacklist"
local redis = require "resty.redis"
local cjson = require "cjson.safe"
local upstream_redis = require "resty.upstream_redis"
local site_resolver = require "resty.site_resolver"
local acl_manager = require "resty.acl_manager"

local _M = { _VERSION = "2.0.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local DEFAULT_TEMP_BLACKLIST_TTL = 180

local ACL_RETURN_INTERNAL_ERROR = 0
local ACL_RETURN_ALLOW_RULE     = 1
local ACL_RETURN_DROP           = 2
local ACL_RETURN_DENY           = 3
local ACL_RETURN_DROP_BLOCK     = 4
local ACL_RETURN_CAPTCHA_START  = 5
local ACL_RETURN_ALLOW_NO_RULE  = 6
local ACL_RETURN_NO_LICENSE     = 7

local RULE_NAMES = {
    [1] = "whitelist",
    [2] = "blacklist",
    [3] = "geo",
    [4] = "antiheader",
    [5] = "intervalfreqlimit",
    [6] = "secondfreqlimit",
    [7] = "responsefreq",
    [8] = "useragent",
    [9] = "anticc",
}

-- API WafRuleType per ACL id; anything else (whitelist, license, engine errors) is "other".
local WAF_RULE_TYPES = {
    [2] = "blacklist",
    [3] = "geo",
    [4] = "anti-header",
    [5] = "interval-freq-limit",
    [6] = "second-freq-limit",
    [7] = "response-freq",
    [8] = "user-agent",
    [9] = "anti-cc",
}
local WAF_RULE_TYPE_TEMP_BLOCK = "temporary-block"
local WAF_RULE_TYPE_OTHER = "other"

-- acl_manager offsets each site's priorities by this; the remainder is the Angelos rule id.
local SITE_PRIORITY_STRIDE = 100000

local function stats_interval()
    local stats_cache = ngx.shared.stats_cache
    return (stats_cache and stats_cache:get("STATS_INTERVAL")) or 60
end

local function matched_rule_id()
    local prio = handle_acl.matched_priority()
    if not prio then
        return nil
    end
    return tostring(prio % SITE_PRIORITY_STRIDE)
end

local function mark_once(stats_cache, key, interval)
    return stats_cache:add(key, true, interval * 2)
end

local function mark_blocked_ip(stats_cache, interval, country, site_id, rule_type, rule_id)
    local sid = site_id and tostring(site_id) or "0"
    local bucket = math.floor(ngx.now() / interval) * interval
    stats_cache:incr("blocked_request_count", 1, 0)
    stats_cache:incr("s:" .. sid .. ":blocked_request_count", 1, 0)

    ngx.var.waf_rule_type = rule_type
    ngx.var.waf_rule_id = rule_id or ""

    local ip = ngx.var.remote_addr
    if mark_once(stats_cache, "seen_blocked_ip:" .. bucket .. ":" .. ip, interval) then
        stats_cache:incr("blocked_ip_count", 1, 0)
    end
    if mark_once(stats_cache, "seen_site_blocked_ip:" .. bucket .. ":" .. sid .. ":" .. ip, interval) then
        stats_cache:incr("s:" .. sid .. ":blocked_ip_count", 1, 0)
        stats_cache:incr("block_country_req_count:" .. sid .. ":" .. country, 1, 0)
    end

    local reason = rule_type .. "|" .. (rule_id or "")
    stats_cache:incr("br_req:" .. sid .. ":" .. reason, 1, 0)
    if mark_once(stats_cache, "seen_br_ip:" .. bucket .. ":" .. sid .. ":" .. reason .. ":" .. ip, interval) then
        stats_cache:incr("br_ip:" .. sid .. ":" .. reason, 1, 0)
    end
end

local function check_temporaryblacklist()
    local ip = ngx.var.remote_addr
    if not ip or ip == "" then
        return false
    end

    local uri = ngx.var.request_uri or ngx.var.uri or ""
    if not temp_blacklist.check(ip, uri) then
        return false
    end

    ngx.var.acl_blocked = 1
    ngx.var.acl_rule_id = "temporaryblacklist"
    ngx.var.acl_ret = "temporaryblacklist"
    return true
end

local function persist_temporaryblacklist(premature, item_key, json_str, ttl)
    if premature or site_resolver.redis_down() then
        return
    end

    local red = redis:new()
    red:set_timeout(2000)
    local ok_conn, err_conn = red:connect(REDIS_SOCK, { pool = "athens_redis_db0" })
    if not ok_conn then
        ngx.log(ngx.ERR, "temporaryblacklist redis connect failed: ", tostring(err_conn))
        site_resolver.mark_redis_down(err_conn)
        return
    end

    red:init_pipeline()
    red:set(item_key, json_str)
    red:expire(item_key, ttl)
    red:publish("temporaryblacklist:added", json_str)
    local _, perr = red:commit_pipeline()
    if perr then
        ngx.log(ngx.ERR, "temporaryblacklist redis write failed: ", tostring(perr))
        red:close()
        return
    end
    red:set_keepalive(10000, 100)
end

--- Block locally (shm, all workers) right away; persist + publish to Redis
--- asynchronously so the request path never waits on Redis.
--- all_sites: omit site_id so the entry applies to every site.
function _M.add_temporaryblacklist(rule_id, ip, url, trigger_rule, ttl, all_sites)
    if not ip or ip == "" then
        return
    end

    local country, city = geo_lookup.get(ip)
    ttl = ttl or DEFAULT_TEMP_BLACKLIST_TTL
    local blocked_at = tostring(ngx.time())
    local site_id = not all_sites and site_resolver.lookup_site_id_cached() or nil
    local entry = {
        ip = ip,
        url = url,
        country = country,
        city = city,
        blocked_at = blocked_at,
        ttl = ttl,
        trigger_rule = trigger_rule or RULE_NAMES[rule_id] or tostring(rule_id),
    }
    if site_id then
        entry.site_id = site_id
    end
    local json_str = cjson.encode(entry)
    if not json_str then
        return
    end

    temp_blacklist.on_entry_added(entry)

    local item_key = "temporaryblacklist:" .. ip .. ":" .. blocked_at
    if site_id then
        item_key = item_key .. ":" .. tostring(site_id)
    end
    local ok, err = ngx.timer.at(0, persist_temporaryblacklist, item_key, json_str, ttl)
    if not ok then
        ngx.log(ngx.WARN, "temporaryblacklist: persist timer failed: ", tostring(err))
    end
end

local add_temporaryblacklist = _M.add_temporaryblacklist

function _M.run()
    local stats_cache = ngx.shared.stats_cache
    local interval = stats_interval()

    ngx.var.acl_blocked = 0
    ngx.var.acl_ret = "0"
    ngx.var.acl_rule_id = "-"

    -- Resolve site early; used by temp blacklist, upstream, ACL, and stats.
    local site_id = site_resolver.lookup_site_id()
    ngx.var.site_id = site_id and tostring(site_id) or "0"

    if check_temporaryblacklist() then
        local country = geo_lookup.country()
        mark_blocked_ip(stats_cache, interval, country, site_id, WAF_RULE_TYPE_TEMP_BLOCK, nil)
        return ngx.exit(444)
    end

    -- Merge Host-scoped site WAF rules into ngx_acl when Redis config changes.
    pcall(acl_manager.ensure_applied)

    local function mark_block(rule_id, ret, action)
        local country = geo_lookup.country()
        ngx.var.acl_blocked = 1
        ngx.var.acl_rule_id = RULE_NAMES[rule_id] or tostring(rule_id)
        ngx.var.acl_ret = action

        local rule_type = WAF_RULE_TYPE_OTHER
        local waf_rule_id
        if action ~= "internal_error" and action ~= "no_license" and action ~= "unknown" then
            rule_type = WAF_RULE_TYPES[rule_id] or WAF_RULE_TYPE_OTHER
            waf_rule_id = matched_rule_id()
        end
        mark_blocked_ip(stats_cache, interval, country, site_id, rule_type, waf_rule_id)

        if action == "drop_block" then
            add_temporaryblacklist(
                rule_id,
                ngx.var.remote_addr or "",
                ngx.var.request_uri or ngx.var.uri or "",
                RULE_NAMES[rule_id]
            )
        end
    end

    local function handle_result(rule_id, ret)
        if ret == ACL_RETURN_ALLOW_RULE then
            return true
        elseif ret == ACL_RETURN_INTERNAL_ERROR then
            mark_block(rule_id, ret, "internal_error")
            return ngx.exit(501)
        elseif ret == ACL_RETURN_NO_LICENSE then
            mark_block(rule_id, ret, "no_license")
            return ngx.exit(444)
        elseif ret == ACL_RETURN_DROP then
            mark_block(rule_id, ret, "drop")
            return ngx.exit(444)
        elseif ret == ACL_RETURN_DROP_BLOCK then
            mark_block(rule_id, ret, "drop_block")
            return ngx.exit(444)
        elseif ret == ACL_RETURN_DENY then
            mark_block(rule_id, ret, "deny")
            return ngx.exit(403)
        elseif ret == ACL_RETURN_CAPTCHA_START then
            mark_block(rule_id, ret, "captcha_start")
            return ngx.exit(403)
        elseif ret == ACL_RETURN_ALLOW_NO_RULE then
            return "no_rule"
        else
            mark_block(rule_id, ret, "unknown")
            return ngx.exit(501)
        end
    end

    for rule_id = 1, 9 do
        local ret = handle_acl.process_acl_id(rule_id)
        local res = handle_result(rule_id, ret)
        if res ~= "no_rule" then
            return
        end
    end

    -- Resolve per-site origin. Never fall back to :9000 (stats "Welcome" page).
    local backend
    if upstream_redis.get_backend then
        backend = upstream_redis.get_backend(site_id)
    end
    if type(backend) ~= "string" or backend == "" or backend:find("127%.0%.0%.1:9000", 1, false) then
        ngx.log(ngx.ERR, "acl_access: no origin upstream for site_id=",
            tostring(site_id), " host=", tostring(ngx.var.http_host or ngx.var.host))
        return ngx.exit(502)
    end
    ngx.var.backend = backend
end

return _M
