local redis      = require "resty.redis"
local cjson      = require "cjson.safe"
local mlcache    = require "resty.mlcache"
local handle_acl = require "resty.handle_acl"
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

local _M = { _VERSION = "1.0.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"

local acl_rules = {
    { id = 1, name = "whitelist" },
    { id = 2, name = "blacklist" },
    { id = 3, name = "geo" },
    { id = 4, name = "antiheader" },
    { id = 5, name = "intervalfreqlimit" },
    { id = 6, name = "secondaryfreqlimit" },
    { id = 7, name = "responsefreq" },
    { id = 8, name = "useragent" },
}

-- quick lookup by id/name
local acl_rules_by_id = {}
local acl_rules_by_name = {}
for _, rule in ipairs(acl_rules) do
    acl_rules_by_id[rule.id] = rule
    acl_rules_by_name[rule.name] = rule
end

-- module-level mlcache object (initialized in init())
local cache -- mlcache instance
local cache_opts = {
    ttl     = 3600,            -- 1h ttl for hits
    neg_ttl = 30,              -- 30s ttl for misses
    lru_size = 2000,           -- size of the L1 (Lua VM) cache
    ipc_shm = "ipc_shared_dict"
}

-- Redis connection helpers
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

-- Keepalive ping for general Redis connections
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

-- Loader helpers
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

-- mlcache init
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
    log(INFO, "mlcache initialized for ACLs")
    return true
end

-- Load all rules
function _M.load_all_rules()
    if not cache then
        local ok, err = _M.init()
        if not ok then
            return nil, err
        end
    end

    for _, rule in ipairs(acl_rules) do
        local rule_cfg, err = cache:get(rule.name, nil, loader_rule, rule.name)
        if rule_cfg then
            local ok_set, set_err = pcall(handle_acl.set_acl_rule, rule_cfg)
            if not ok_set then
                log(ERR, "failed to apply ACL rule '", rule.name, "': ", tostring(set_err))
            end
        elseif err and err ~= "not_found" then
            log(WARN, "failed loading ACL rule '", rule.name, "': ", tostring(err))
        end
    end

    return true
end

function _M.initialize_on_first_request()
    local state = shared.acl_init_state
    if state:get("initialized") then
        return
    end

    local ok, err = _M.load_all_rules()
    if ok then
        state:set("initialized", true, 60)
    else
        log(ERR, "initialize_on_first_request: load_all_rules failed: ", tostring(err))
    end
end

-- Update/delete rule
function _M.update_rule(rule_id)
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

    cache:delete(rule.name)

    local rule_cfg, err = cache:get(rule.name, nil, loader_rule, rule.name)
    if rule_cfg then
        local ok_set, set_err = pcall(handle_acl.set_acl_rule, rule_cfg)
        if not ok_set then
            log(ERR, "update_rule: failed to apply ACL rule '", rule.name, "': ", tostring(set_err))
        end
    elseif err and err ~= "not_found" then
        log(WARN, "update_rule: failed to reload rule '", rule.name, "': ", tostring(err))
    end
end

function _M.delete_rule(rule_id)
    local rule = acl_rules_by_id[rule_id]
    if not rule then
        log(WARN, "delete_rule: unknown rule_id: ", tostring(rule_id))
        return
    end

    if cache then
        cache:delete(rule.name)
    end
end

-- Redis subscriber: listens to key event notifications and invalidates / reloads cache
function _M.start_redis_subscriber(premature)
    if premature then
        return
    end

    log(INFO, "Starting Redis subscriber for ACL rule updates...")

    local backoff = 1

    -- spawn keepalive timer (safe)
    local ok_k, err_k = timer_at(0, pubsub_keepalive_ping)
    if not ok_k then
        log(ERR, "start_redis_subscriber: failed to start keepalive timer: ", tostring(err_k))
    end

    while not worker.exiting() do
        -- try to connect
        local red, err = get_redis_connection(2000)
        if not red then
            log(ERR, "start_redis_subscriber: redis conn failed: ", tostring(err))
            sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        -- use a finite blocking timeout so we can wake up periodically to check exiting()
        local ok_set, set_err = pcall(function() red:set_timeout(5000) end)
        if not ok_set then
            log(WARN, "start_redis_subscriber: set_timeout failed: ", tostring(set_err))
        end

        -- subscribe to channel and pattern (ignore subscribe ack table)
        local ok_sub, perr1 = red:subscribe("acl:updates")
        if not ok_sub then
            log(ERR, "start_redis_subscriber: subscribe acl:updates failed: ", tostring(perr1))
            pcall(red.close, red)
            sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        -- psubscribe optional: if it fails we'll continue with explicit channel
        local ok_psub, perr2 = red:psubscribe("__keyevent@0__:*")
        if not ok_psub then
            log(WARN, "start_redis_subscriber: psubscribe __keyevent@0__:* failed: ", tostring(perr2))
        end

        log(INFO, "start_redis_subscriber: subscribed to acl:updates and __keyevent@0__:* (if available)")
        backoff = 1

        -- inner read loop: timed read so we can break on worker exit
        while not worker.exiting() do
            local msg, read_err = red:read_reply()
            if not msg then
                if read_err ~= "timeout" then
                    log(ERR, "start_redis_subscriber: pubsub read_reply failed: ", tostring(read_err))
                    break
                end
            else
                if type(msg) == "table" then
                    if msg[1] == "message" then
                        local channel, payload = msg[2], msg[3]
                        log(DEBUG, "pubsub message channel=", tostring(channel), " payload=", tostring(payload))
                        if channel == "acl:updates" and type(payload) == "string" then
                            local rule = acl_rules_by_name[payload]
                            if rule then
                                _M.update_rule(rule.id)
                            end
                        end
                    elseif msg[1] == "pmessage" then
                        local pattern, channel, payload = msg[2], msg[3], msg[4]
                        log(DEBUG, "pubsub pmessage pattern=", tostring(pattern),
                            " channel=", tostring(channel), " payload=", tostring(payload))

                        if type(payload) == "string" then
                            if channel == "__keyevent@0__:set" or channel == "__keyevent@0__:hset" then
                                local rule = acl_rules_by_name[payload]
                                if rule then
                                    _M.update_rule(rule.id)
                                end
                            elseif channel == "__keyevent@0__:del" or channel == "__keyevent@0__:expired" then
                                local rule = acl_rules_by_name[payload]
                                if rule then
                                    _M.delete_rule(rule.id)
                                end
                            end
                        end
                    end
                end
            end
        end -- inner while

        -- clean up subscription and connection before reconnect or exit
        pcall(function()
            pcall(red.unsubscribe, red, "acl:updates")
            pcall(red.punsubscribe, red, "__keyevent@0__:*")
            pcall(red.quit, red)
            pcall(red.close, red)
        end)

        if worker.exiting() then
            log(INFO, "start_redis_subscriber: worker exiting, subscriber stopped")
            break
        end

        -- reconnect with backoff on errors
        sleep(backoff)
        backoff = math.min(backoff * 2, 30)
        ::continue::
    end -- outer while

    log(INFO, "start_redis_subscriber: exiting")
end

return _M