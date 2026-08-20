local redis      = require "resty.redis"
local cjson      = require "cjson.safe"
local mlcache    = require "resty.mlcache"
local handle_acl = require "resty.handle_acl"
local site_resolver = require "resty.site_resolver"
local ngx        = ngx

local log       = ngx.log
local ERR       = ngx.ERR
local WARN      = ngx.WARN
local INFO      = ngx.INFO
local DEBUG     = ngx.DEBUG
local timer_at  = ngx.timer.at
local worker    = ngx.worker
local shared    = ngx.shared
local sleep     = ngx.sleep
local null      = ngx.null

local _M = { _VERSION = "2.0.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local VERSION_KEY = "acl_config_version"

-- Names match Angelos waf:{site_id}:{name} keys.
local acl_rules = {
    { id = 1, name = "whitelist" },
    { id = 2, name = "blacklist" },
    { id = 3, name = "geo" },
    { id = 4, name = "antiheader" },
    { id = 5, name = "intervalfreqlimit" },
    { id = 6, name = "secondfreqlimit" },
    { id = 7, name = "responsefreq" },
    { id = 8, name = "useragent" },
    { id = 9, name = "anticc" },
}

local acl_rules_by_id = {}
local acl_rules_by_name = {}
for _, rule in ipairs(acl_rules) do
    acl_rules_by_id[rule.id] = rule
    acl_rules_by_name[rule.name] = rule
end

local cache
local cache_opts = {
    ttl      = 3600,
    neg_ttl  = 30,
    lru_size = 2000,
    ipc_shm  = "ipc_shared_dict",
}

-- Per-worker: last applied config version
local applied_version = 0

local function get_redis_connection(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 2000)
    local ok, err = red:connect(REDIS_SOCK)
    if not ok then
        log(ERR, "redis connect failed: ", tostring(err))
        return nil, err
    end
    return red
end

local function pubsub_keepalive_ping(premature)
    if premature or worker.exiting() then
        return
    end

    local red, err = get_redis_connection(2000)
    if red then
        local ok, perr = red:ping()
        if not ok then
            log(WARN, "pubsub_keepalive_ping PING failed: ", tostring(perr))
        end
        pcall(function() red:set_keepalive(10000, 100) end)
    else
        log(WARN, "pubsub_keepalive_ping failed to connect Redis: ", tostring(err))
    end

    if not worker.exiting() then
        local ok, terr = timer_at(30, pubsub_keepalive_ping)
        if not ok then
            log(ERR, "pubsub_keepalive_ping: failed to schedule next timer: ", tostring(terr))
        end
    end
end

local function redis_key(site_id, rule_name)
    return "waf:" .. tostring(site_id) .. ":" .. rule_name
end

local function loader_rule(key)
    local red, err = get_redis_connection()
    if not red then
        return nil, "redis_conn_failed"
    end

    local val, gerr = red:get(key)
    red:set_keepalive(10000, 100)

    if not val or val == null then
        return nil, gerr or "not_found"
    end

    local parsed, perr = cjson.decode(val)
    if not parsed then
        return nil, "json_decode_failed"
    end

    return parsed
end

local function bump_version()
    local state = shared.acl_init_state
    if not state then
        return
    end
    local v = state:incr(VERSION_KEY, 1, 0)
    if not v then
        state:set(VERSION_KEY, 1, 0)
    end
    site_resolver.invalidate_domain_cache()
end

local function current_version()
    local state = shared.acl_init_state
    if not state then
        return 0
    end
    return tonumber(state:get(VERSION_KEY)) or 0
end

local function wrap_rule_with_hosts(rule_body, domains)
    if not domains or #domains == 0 then
        return nil
    end
    local host_list = table.concat(domains, ",")
    local host_clause = '["Header","Host","is in","' .. host_list .. '"]'
    if not rule_body or rule_body == "" then
        return host_clause
    end
    return host_clause .. " \nAND \n" .. rule_body
end

--- Build merged { id, rules } for one ACL type across all sites (Host-scoped).
local function build_merged_cfg(rule_meta)
    local site_domains = site_resolver.list_site_domains()
    local merged = {}
    local priority_base = 0

    for site_id, domains in pairs(site_domains) do
        if type(domains) == "table" and #domains > 0 then
            local key = redis_key(site_id, rule_meta.name)
            local cfg
            if cache then
                local err
                cfg, err = cache:get(key, nil, loader_rule, key)
                if not cfg and err and err ~= "not_found" then
                    log(WARN, "failed loading ", key, ": ", tostring(err))
                end
            else
                cfg = loader_rule(key)
            end

            if type(cfg) == "table" and type(cfg.rules) == "table" then
                for _, r in ipairs(cfg.rules) do
                    if type(r) == "table" then
                        local wrapped = wrap_rule_with_hosts(r.rule, domains)
                        if wrapped then
                            local prio = tonumber(r.priority) or 0
                            merged[#merged + 1] = {
                                action = tonumber(r.action) or 3,
                                priority = priority_base + prio,
                                rule = wrapped,
                            }
                        end
                    end
                end
            end
            priority_base = priority_base + 100000
        end
    end

    return {
        id = rule_meta.id,
        rules = merged,
    }
end

function _M.init()
    if cache then
        return true
    end

    local c, err = mlcache.new("acl_cache_instance", "acl_cache", cache_opts)
    if not c then
        log(ERR, "mlcache.new failed: ", tostring(err))
        return nil, err
    end

    cache = c
    log(INFO, "mlcache initialized for site-scoped ACLs")
    return true
end

--- Prefetch all waf:{site}:* keys into mlcache (no ngx_acl apply; needs request ctx).
function _M.load_all_rules()
    if not cache then
        local ok, err = _M.init()
        if not ok then
            return nil, err
        end
    end

    local site_domains = site_resolver.list_site_domains()
    local n = 0
    for site_id, _ in pairs(site_domains) do
        for _, rule in ipairs(acl_rules) do
            local key = redis_key(site_id, rule.name)
            cache:delete(key)
            local cfg, err = cache:get(key, nil, loader_rule, key)
            if cfg then
                n = n + 1
            elseif err and err ~= "not_found" then
                log(WARN, "failed loading ACL key '", key, "': ", tostring(err))
            end
        end
    end

    bump_version()
    log(INFO, "load_all_rules: prefetched ", n, " site ACL payload(s)")
    return true
end

--- Apply merged site ACLs into ngx_acl. Must run in request context.
function _M.apply_to_engine()
    if not cache then
        local ok, err = _M.init()
        if not ok then
            return nil, err
        end
    end

    for _, rule in ipairs(acl_rules) do
        local cfg = build_merged_cfg(rule)
        local ok_set, set_err = pcall(handle_acl.set_acl_rule, cfg)
        if not ok_set then
            log(ERR, "failed to apply ACL '", rule.name, "': ", tostring(set_err))
        end
    end

    applied_version = current_version()
    return true
end

--- Ensure ngx_acl matches latest Redis site configs (request context).
function _M.ensure_applied()
    local ver = current_version()
    if applied_version == ver and ver > 0 then
        return true
    end
    return _M.apply_to_engine()
end

local function parse_waf_payload(payload)
    -- waf:{site_id}:{rule_type} or waf_deleted:{site_id}:{rule_type}
    if type(payload) ~= "string" then
        return nil
    end

    local deleted, site_id, rule_type = payload:match("^waf_(deleted):(%d+):([%w_]+)$")
    if deleted then
        return "delete", tonumber(site_id), rule_type
    end

    site_id, rule_type = payload:match("^waf:(%d+):([%w_]+)$")
    if site_id then
        return "update", tonumber(site_id), rule_type
    end

    -- Legacy global key name
    if acl_rules_by_name[payload] then
        return "legacy", nil, payload
    end

    return nil
end

function _M.update_rule(rule_id, site_id)
    local rule = acl_rules_by_id[rule_id]
    if not rule then
        log(WARN, "update_rule: unknown rule_id: ", tostring(rule_id))
        return
    end

    if not cache then
        local ok, err = _M.init()
        if not ok then
            log(ERR, "update_rule: init failed: ", tostring(err))
            return
        end
    end

    if site_id then
        local key = redis_key(site_id, rule.name)
        cache:delete(key)
        cache:get(key, nil, loader_rule, key)
    else
        -- Invalidate all sites for this rule type
        local site_domains = site_resolver.list_site_domains()
        for sid, _ in pairs(site_domains) do
            cache:delete(redis_key(sid, rule.name))
        end
    end

    bump_version()
end

function _M.delete_rule(rule_id, site_id)
    local rule = acl_rules_by_id[rule_id]
    if not rule then
        log(WARN, "delete_rule: unknown rule_id: ", tostring(rule_id))
        return
    end

    if cache and site_id then
        cache:delete(redis_key(site_id, rule.name))
    elseif cache then
        local site_domains = site_resolver.list_site_domains()
        for sid, _ in pairs(site_domains) do
            cache:delete(redis_key(sid, rule.name))
        end
    end

    bump_version()
end

function _M.start_redis_subscriber(premature)
    if premature then
        return
    end

    log(INFO, "Starting Redis subscriber for site-scoped ACL updates...")

    local backoff = 1

    local ok_k, err_k = timer_at(0, pubsub_keepalive_ping)
    if not ok_k then
        log(ERR, "start_redis_subscriber: failed to start keepalive timer: ", tostring(err_k))
    end

    while not worker.exiting() do
        local red, err = get_redis_connection(2000)
        if not red then
            log(ERR, "start_redis_subscriber: redis conn failed: ", tostring(err))
            sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        pcall(function() red:set_timeout(5000) end)

        local ok_sub, perr1 = red:subscribe("acl:updates")
        if not ok_sub then
            log(ERR, "start_redis_subscriber: subscribe acl:updates failed: ", tostring(perr1))
            pcall(red.close, red)
            sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        local ok_psub, perr2 = red:psubscribe("__keyevent@0__:*")
        if not ok_psub then
            log(WARN, "start_redis_subscriber: psubscribe __keyevent@0__:* failed: ", tostring(perr2))
        end

        log(INFO, "start_redis_subscriber: subscribed to acl:updates")
        backoff = 1

        while not worker.exiting() do
            local msg, read_err = red:read_reply()
            if not msg then
                if read_err ~= "timeout" then
                    log(ERR, "start_redis_subscriber: pubsub read_reply failed: ", tostring(read_err))
                    break
                end
            elseif type(msg) == "table" then
                local payload
                if msg[1] == "message" and msg[2] == "acl:updates" then
                    payload = msg[3]
                elseif msg[1] == "pmessage" then
                    local channel = msg[3]
                    payload = msg[4]
                    if channel ~= "__keyevent@0__:set"
                        and channel ~= "__keyevent@0__:hset"
                        and channel ~= "__keyevent@0__:del"
                        and channel ~= "__keyevent@0__:expired" then
                        payload = nil
                    end
                end

                if type(payload) == "string" then
                    log(DEBUG, "acl update payload=", payload)
                    local action, site_id, rule_type = parse_waf_payload(payload)
                    if action and rule_type then
                        local rule = acl_rules_by_name[rule_type]
                        if rule then
                            if action == "delete" then
                                _M.delete_rule(rule.id, site_id)
                            else
                                _M.update_rule(rule.id, site_id)
                            end
                        end
                    elseif payload:match("^domain:") then
                        bump_version()
                    end
                end
            end
        end

        pcall(function()
            pcall(red.unsubscribe, red, "acl:updates")
            pcall(red.punsubscribe, red, "__keyevent@0__:*")
            pcall(red.quit, red)
            pcall(red.close, red)
        end)

        if worker.exiting() then
            break
        end

        sleep(backoff)
        backoff = math.min(backoff * 2, 30)
        ::continue::
    end

    log(INFO, "start_redis_subscriber: exiting")
end

_M.acl_rules = acl_rules
_M.acl_rules_by_name = acl_rules_by_name

return _M
