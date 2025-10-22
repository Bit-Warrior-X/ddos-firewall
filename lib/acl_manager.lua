local redis = require "resty.redis"
local cjson = require "cjson.safe"
local mlcache = require "resty.mlcache"
local ngx = ngx
local handle_acl = require "resty.handle_acl"

local _M = { _VERSION = "1.0.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local APPLY_RULES_KEY = "acl_apply_rules"
local RULE_IDS_KEY = "acl_rule_ids"
local RULE_KEY_PREFIX = "acl_rule:"     -- full key = acl_rule:<id>

local acl_rules = {} -- Cache for ACL rules

-- module-level mlcache object (initialized in init())
local cache      -- mlcache instance
local cache_opts = {
    ttl = 3600,          -- 1h ttl for hits
    neg_ttl = 30,        -- 30s ttl for misses
    lru_size = 2000,     -- size of the L1 (Lua VM) cache
    ipc_shm = "ipc_shared_dict"
}

-- Redis connection helpers
local function get_redis_connection(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 2000)
    local ok, err = red:connect(REDIS_SOCK)
    if not ok then
        ngx.log(ngx.ERR, "redis connect failed: ", tostring(err))
        return nil, err
    end
    return red
end

-- Keepalive ping for general Redis connections
local function pubsub_keepalive_ping(premature)
    if premature then return end
    local red, err = get_redis_connection(2000)
    if red then
        local ok, perr = red:ping()
        if not ok then
            ngx.log(ngx.WARN, "pubsub_keepalive_ping PING failed: ", tostring(perr))
        end
        pcall(function() red:set_keepalive(10000, 100) end)
    else
        ngx.log(ngx.WARN, "pubsub_keepalive_ping failed to connect Redis")
    end
    -- Repeat every 30s
    ngx.timer.at(30, pubsub_keepalive_ping)
end

-- Loader helpers
local function loader_rule(key)
    local red, err = get_redis_connection()
    if not red then return nil, "redis_conn_failed" end
    local val, err = red:get(key)
    red:set_keepalive(10000, 100)
    if not val or val == ngx.null then return nil, err or "not_found" end
    local parsed, perr = cjson.decode(val)
    if not parsed then return nil, "json_decode_failed" end
    return parsed
end

local function loader_apply_rules(_key)
    local red, err = get_redis_connection()
    if not red then return nil, "redis_conn_failed" end
    local val, err = red:get(_key)
    red:set_keepalive(10000, 100)
    if not val or val == ngx.null then return nil, err or "not_found" end
    local parsed, perr = cjson.decode(val)
    if not parsed then return nil, "loader_apply_rules() json_decode_failed" end
    return parsed
end

local function loader_rule_ids(_key)
    local red, err = get_redis_connection()
    if not red then return nil, "redis_conn_failed" end
    local ids, err = red:smembers(_key)
    red:set_keepalive(10000, 100)
    if not ids then return nil, err end
    return ids
end

-- mlcache init
function _M.init()
    if cache then return true end
    local c, err = mlcache.new("acl_cache_instance", "acl_cache", cache_opts)
    if not c then
        ngx.log(ngx.ERR, "mlcache.new failed: ", tostring(err))
        return nil, err
    end
    cache = c
    ngx.log(ngx.INFO, "mlcache initialized for ACLs")
    return true
end

-- Load all rules
function _M.load_all_rules()
    if not cache then _M.init() end
    local ids, err = cache:get(RULE_IDS_KEY, nil, loader_rule_ids, RULE_IDS_KEY)
    if not ids then return nil, err end
    for _, id in ipairs(ids) do
        local key = RULE_KEY_PREFIX .. id
        local rule_cfg, rerr = cache:get(key, nil, loader_rule, key)
        if rule_cfg then
            acl_rules[tostring(id)] = rule_cfg
            pcall(handle_acl.set_acl_rule, rule_cfg)
        end
    end
    local val, err = cache:get(APPLY_RULES_KEY, nil, loader_apply_rules, APPLY_RULES_KEY)
    if not val then return nil, err end
    return true
end

-- Get apply rules
function _M.get_apply_rules()
    if not cache then _M.init() end
    return cache:get(APPLY_RULES_KEY, nil, loader_apply_rules)
end

function _M.initialize_on_first_request()
    if ngx.shared.acl_init_state:get("initialized") then return end
    local ok, err = _M.load_all_rules()
    if ok then ngx.shared.acl_init_state:set("initialized", true, 60) end
end

-- Update/delete rule
function _M.update_rule(rule_id)
    if not cache then _M.init() end
    local key = RULE_KEY_PREFIX .. tostring(rule_id)
    cache:delete(key)
    local rule_cfg, err = cache:get(key, nil, loader_rule, key)
    if rule_cfg then
        acl_rules[tostring(rule_id)] = rule_cfg
        pcall(handle_acl.set_acl_rule, rule_cfg)
    end
end

function _M.delete_rule(rule_id)
    acl_rules[tostring(rule_id)] = nil
    if cache then cache:delete(RULE_KEY_PREFIX .. tostring(rule_id)) end
end

function _M.load_apply_rules()
    if not cache then _M.init() end
    cache:delete(APPLY_RULES_KEY)
    return cache:get(APPLY_RULES_KEY, nil, loader_apply_rules, APPLY_RULES_KEY)
end

-- Redis subscriber
-- Redis subscriber: listens to key event notifications and invalidates / reloads cache
function _M.start_redis_subscriber(premature)
    if premature then return end
    ngx.log(ngx.INFO, "Starting Redis subscriber for ACL rule updates...")

    -- spawn a background timer to keep Redis connections from being idle
    local ok_k, err_k = ngx.timer.at(0, pubsub_keepalive_ping)
    if not ok_k then
        ngx.log(ngx.ERR, "start_redis_subscriber: failed to start keepalive timer: ", tostring(err_k))
    end

    while true do
        -- get pubsub connection (helper sets timeout=0)
        local red, err = get_redis_connection(0)
        if not red then
            ngx.log(ngx.ERR, "start_redis_subscriber: redis conn failed: ", tostring(err))
            ngx.sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        -- Ensure blocking read on this connection
        pcall(function() red:set_timeout(0) end)

        -- Subscribe to explicit updates (recommended) and keyevents
        -- subscribe returns a result; some servers return subscribe ack tables — ignore
        local ok_sub, perr1 = red:subscribe("acl:updates")
        if not ok_sub then
            ngx.log(ngx.ERR, "start_redis_subscriber: subscribe acl:updates failed: ", tostring(perr1))
            pcall(red.close, red)
            ngx.sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        local ok_psub, perr2 = red:psubscribe("__keyevent@0__:*")
        if not ok_psub then
            ngx.log(ngx.ERR, "start_redis_subscriber: psubscribe __keyevent@0__:* failed: ", tostring(perr2))
            -- it's okay to continue with only acl:updates; do not require keyevent to exist
            -- but close and reconnect if subscription returns fatal error
            -- we will keep the acl:updates subscription active; proceed
        end

        ngx.log(ngx.INFO, "start_redis_subscriber: subscribed to acl:updates and __keyevent@0__:* (if available)")
        backoff = 1

        -- main read loop
        while true do
            local msg, read_err = red:read_reply()
            if not msg then
                if read_err == "timeout" then
                    ngx.log(ngx.WARN, "start_redis_subscriber: pubsub read timeout (server closed idle connection); reconnecting after backoff")
                else
                    ngx.log(ngx.ERR, "start_redis_subscriber: pubsub read_reply failed: ", tostring(read_err))
                end
                -- Close and break to reconnect (avoid spinning)
                pcall(red.close, red)
                ngx.sleep(backoff)
                backoff = math.min(backoff * 2, 30)
                break
            end

            -- msg is table: e.g. {"message", channel, payload}
            -- or {"pmessage", pattern, channel, payload}
            if type(msg) ~= "table" then
                goto inner_continue
            end

            -- handle explicit publish messages
            if msg[1] == "message" then
                local channel = msg[2]
                local payload = msg[3]
                ngx.log(ngx.DEBUG, "pubsub message channel=", tostring(channel), " payload=", tostring(payload))
                if channel == "acl:updates" and type(payload) == "string" then
                    -- payload can be "acl_rule:1" or "apply_rules" or JSON; adapt accordingly
                    if string.find(payload, "^acl_rule:") then
                        local rule_id = string.match(payload, "^acl_rule:(.+)")
                        if rule_id then _M.update_rule(rule_id) end
                    elseif payload == "acl_apply_rules" or payload == "reload_apply_rules" then
                        _M.load_apply_rules()
                    elseif payload == "reload_all" then
                        _M.load_all_rules()
                    else
                        -- if payload is JSON with full rule, try decode and apply directly
                        local ok, decoded = pcall(cjson.decode, payload)
                        if ok and decoded and decoded.id then
                            -- update mlcache and apply immediately
                            local key = RULE_KEY_PREFIX .. tostring(decoded.id)
                            if cache then
                                local uok, uerr = cache:update(key, decoded)
                                if not uok then ngx.log(ngx.WARN, "cache:update failed: ", tostring(uerr)) end
                            end
                            pcall(handle_acl.set_acl_rule, decoded)
                        end
                    end
                end

            -- handle pattern messages (keyevents)
            elseif msg[1] == "pmessage" then
                local pattern = msg[2]
                local channel = msg[3]  -- e.g. "__keyevent@0__:set"
                local payload = msg[4]  -- key name
                ngx.log(ngx.DEBUG, "pubsub pmessage pattern=", tostring(pattern),
                            " channel=", tostring(channel), " payload=", tostring(payload))

                if type(payload) ~= "string" then goto inner_continue end

                local key = payload
                if string.find(key, "^acl_rule:") then
                    local id = string.match(key, "^acl_rule:(.+)")
                    if channel == "__keyevent@0__:set" or channel == "__keyevent@0__:hset" then
                        _M.update_rule(id)
                    elseif channel == "__keyevent@0__:del" or channel == "__keyevent@0__:expired" then
                        _M.delete_rule(id)
                    end
                elseif key == APPLY_RULES_KEY then
                    _M.load_apply_rules()
                elseif key == RULE_IDS_KEY then
                    if cache then cache:delete(RULE_IDS_KEY) end
                    _M.load_all_rules()
                end
            end

            ::inner_continue::
        end

        ::continue::
    end
end

return _M