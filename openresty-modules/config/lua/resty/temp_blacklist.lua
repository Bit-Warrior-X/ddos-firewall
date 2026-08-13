-- Temporary blacklist with shm cache and Redis pub/sub sync.
-- Hot path: shm lookup only (no Redis SCAN per request).

local redis = require "resty.redis"
local cjson = require "cjson.safe"
local ngx = ngx

local _M = { _VERSION = "1.0.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local SHM_NAME = "temp_blacklist"
local NEG_TTL = 15
local CHANNEL_ADDED = "temporaryblacklist:added"
local NEG_SENTINEL = "-"

local function shm()
    return ngx.shared[SHM_NAME]
end

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 1000)
    local ok, err = red:connect(REDIS_SOCK)
    if not ok then
        return nil, err
    end
    return red
end

local function match_uri(uri, url_pat)
    if not url_pat or url_pat == "" then
        return false
    end
    local ok, matched = pcall(ngx.re.find, uri, url_pat, "jo")
    return ok and matched ~= nil
end

local function entry_applies_to_site(item, site_id)
    local item_site = tonumber(item.site_id)
    if not item_site or item_site == 0 then
        -- L4 / global entries apply to every site.
        return true
    end
    if not site_id then
        return false
    end
    return item_site == tonumber(site_id)
end

local function rules_match(rules, uri, site_id)
    if type(rules) ~= "table" then
        return false
    end
    for _, item in ipairs(rules) do
        if type(item) == "table"
            and entry_applies_to_site(item, site_id)
            and match_uri(uri, item.url) then
            return true
        end
    end
    return false
end

local function min_remaining_ttl(rules, now)
    local ttl = NEG_TTL
    now = now or ngx.time()
    for _, item in ipairs(rules) do
        if type(item) == "table" then
            local blocked_at = tonumber(item.blocked_at) or 0
            local item_ttl = tonumber(item.ttl) or 0
            local remaining = blocked_at + item_ttl - now
            if remaining > ttl then
                ttl = remaining
            end
        end
    end
    return ttl
end

local function load_rules_from_redis(ip)
    local red, err = get_redis(1000)
    if not red then
        ngx.log(ngx.WARN, "temp_blacklist: redis connect failed: ", tostring(err))
        return nil
    end

    local rules = {}
    local cursor = "0"
    local pattern = "temporaryblacklist:" .. ip .. ":*"
    repeat
        local res, scan_err = red:scan(cursor, "MATCH", pattern, "COUNT", 50)
        if not res or scan_err then
            break
        end
        cursor = res[1]
        local keys = res[2]
        if keys and #keys > 0 then
            for _, key in ipairs(keys) do
                local raw = red:get(key)
                if raw and raw ~= ngx.null and raw ~= "" then
                    local item = cjson.decode(raw)
                    if type(item) == "table" then
                        rules[#rules + 1] = item
                    end
                end
            end
        end
    until cursor == "0"

    red:set_keepalive(10000, 100)
    return rules
end

local function cache_key(ip)
    return "b:" .. ip
end

function _M.cache_rules(ip, rules)
    local dict = shm()
    if not dict or not ip or ip == "" then
        return
    end

    if not rules or #rules == 0 then
        dict:set(cache_key(ip), NEG_SENTINEL, NEG_TTL)
        return
    end

    local ttl = min_remaining_ttl(rules)
    if ttl < 1 then
        dict:delete(cache_key(ip))
        return
    end

    dict:set(cache_key(ip), cjson.encode(rules), ttl)
end

function _M.on_entry_added(item)
    if type(item) ~= "table" then
        return
    end

    local ip = item.ip
    if not ip or ip == "" then
        return
    end

    local dict = shm()
    if not dict then
        return
    end

    local key = cache_key(ip)
    local rules = {}
    local existing = dict:get(key)
    if existing and existing ~= NEG_SENTINEL then
        local decoded = cjson.decode(existing)
        if type(decoded) == "table" then
            rules = decoded
        end
    end

    rules[#rules + 1] = item
    _M.cache_rules(ip, rules)
end

function _M.lookup_site_id()
    if ngx.ctx._temp_bl_site_id ~= nil then
        local cached = ngx.ctx._temp_bl_site_id
        if cached == false then
            return nil
        end
        return cached
    end

    local host = ngx.var.host or ngx.var.http_host or ""
    host = host:match("^([^:]+)") or host
    if host == "" then
        ngx.ctx._temp_bl_site_id = false
        return nil
    end

    local red, err = get_redis(500)
    if not red then
        ngx.log(ngx.WARN, "temp_blacklist: site_id lookup redis failed: ", tostring(err))
        ngx.ctx._temp_bl_site_id = false
        return nil
    end

    local val = red:get("domain:" .. host)
    red:set_keepalive(10000, 100)
    if not val or val == ngx.null or val == "" then
        ngx.ctx._temp_bl_site_id = false
        return nil
    end

    local site_id = tonumber(val)
    ngx.ctx._temp_bl_site_id = site_id or false
    return site_id
end

function _M.check(ip, uri)
    if not ip or ip == "" then
        return false
    end

    local dict = shm()
    if not dict then
        return false
    end

    local site_id = _M.lookup_site_id()
    local key = cache_key(ip)
    local cached = dict:get(key)
    if cached == NEG_SENTINEL then
        return false
    end

    if cached and cached ~= "" then
        local rules = cjson.decode(cached)
        return rules_match(rules, uri or "", site_id)
    end

    local rules = load_rules_from_redis(ip)
    if not rules then
        return false
    end

    _M.cache_rules(ip, rules)
    return rules_match(rules, uri or "", site_id)
end

function _M.start_subscriber(premature)
    if premature or ngx.worker.exiting() then
        return
    end

    local backoff = 1
    while not ngx.worker.exiting() do
        local red, err = get_redis(2000)
        if not red then
            ngx.log(ngx.ERR, "temp_blacklist: subscriber redis connect failed: ", tostring(err))
            ngx.sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        red:set_timeout(5000)
        local ok_sub, sub_err = red:subscribe(CHANNEL_ADDED)
        if not ok_sub then
            ngx.log(ngx.ERR, "temp_blacklist: subscribe failed: ", tostring(sub_err))
            pcall(red.close, red)
            ngx.sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        backoff = 1
        ngx.log(ngx.INFO, "temp_blacklist: subscribed to ", CHANNEL_ADDED)

        while not ngx.worker.exiting() do
            local msg, read_err = red:read_reply()
            if not msg then
                if read_err ~= "timeout" then
                    ngx.log(ngx.ERR, "temp_blacklist: read_reply failed: ", tostring(read_err))
                    break
                end
            elseif type(msg) == "table" and msg[1] == "message" and msg[2] == CHANNEL_ADDED then
                local payload = msg[3]
                if type(payload) == "string" and payload ~= "" then
                    local item = cjson.decode(payload)
                    if item then
                        _M.on_entry_added(item)
                    end
                end
            end
        end

        pcall(function()
            pcall(red.unsubscribe, red, CHANNEL_ADDED)
            pcall(red.quit, red)
            pcall(red.close, red)
        end)

        if ngx.worker.exiting() then
            break
        end

        ngx.sleep(backoff)
        backoff = math.min(backoff * 2, 30)
        ::continue::
    end
end

function _M.start()
    local ok, err = ngx.timer.at(0, _M.start_subscriber)
    if not ok then
        ngx.log(ngx.ERR, "temp_blacklist: failed to start subscriber: ", tostring(err))
    end
end

return _M
