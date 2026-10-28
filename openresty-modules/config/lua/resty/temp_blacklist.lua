-- Temporary blacklist with shm cache and Redis pub/sub sync.
-- Hot path: shm lookup only (never Redis). Entries arrive via pub/sub
-- (temporaryblacklist:added), local adds (acl_access / l7_guard), and a
-- periodic bulk sync of temporaryblacklist:* run by worker 0.

local redis = require "resty.redis"
local cjson = require "cjson.safe"
local site_resolver = require "resty.site_resolver"
local ngx = ngx

local _M = { _VERSION = "1.2.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local SHM_NAME = "temp_blacklist"
local CHANNEL_ADDED = "temporaryblacklist:added"
local SYNC_INTERVAL = 30
local SYNC_SCAN_COUNT = 1000
local SYNC_MGET_BATCH = 200

local function shm()
    return ngx.shared[SHM_NAME]
end

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 1000)
    local ok, err = red:connect(REDIS_SOCK, { pool = "athens_redis_db0" })
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

--- Seconds left for an entry; nil means no expiry (ttl <= 0).
local function remaining_ttl(item, now)
    local item_ttl = tonumber(item.ttl) or 0
    if item_ttl <= 0 then
        return nil
    end
    local blocked_at = tonumber(item.blocked_at) or 0
    return blocked_at + item_ttl - now
end

local function rules_match(rules, uri, site_id)
    if type(rules) ~= "table" then
        return false
    end
    local now = ngx.time()
    for _, item in ipairs(rules) do
        if type(item) == "table" then
            local left = remaining_ttl(item, now)
            if (left == nil or left > 0)
                and entry_applies_to_site(item, site_id)
                and match_uri(uri, item.url) then
                return true
            end
        end
    end
    return false
end

local function cache_key(ip)
    return "b:" .. ip
end

local function entry_id(item)
    return tostring(item.blocked_at) .. "|" .. tostring(item.url) .. "|" .. tostring(item.site_id)
end

--- Store rules for ip; shm TTL follows the longest-living entry (0 = no expiry).
function _M.cache_rules(ip, rules)
    local dict = shm()
    if not dict or not ip or ip == "" then
        return
    end

    local now = ngx.time()
    local live, ttl, forever = {}, 0, false
    for _, item in ipairs(rules or {}) do
        if type(item) == "table" then
            local left = remaining_ttl(item, now)
            if left == nil then
                forever = true
                live[#live + 1] = item
            elseif left >= 1 then
                live[#live + 1] = item
                if left > ttl then
                    ttl = left
                end
            end
        end
    end

    if #live == 0 then
        dict:delete(cache_key(ip))
        return
    end

    local ok, err = dict:set(cache_key(ip), cjson.encode(live), forever and 0 or ttl)
    if not ok then
        ngx.log(ngx.WARN, "temp_blacklist: shm set failed for ", ip, ": ", tostring(err))
    end
end

--- Merge new entries for ip into the cached list (dedupes identical entries).
function _M.merge_entries(ip, items)
    local dict = shm()
    if not dict or not ip or ip == "" then
        return
    end

    local rules, seen = {}, {}
    local existing = dict:get(cache_key(ip))
    if existing then
        local decoded = cjson.decode(existing)
        if type(decoded) == "table" then
            for _, item in ipairs(decoded) do
                if type(item) == "table" then
                    seen[entry_id(item)] = true
                    rules[#rules + 1] = item
                end
            end
        end
    end

    for _, item in ipairs(items) do
        if type(item) == "table" and not seen[entry_id(item)] then
            seen[entry_id(item)] = true
            rules[#rules + 1] = item
        end
    end

    _M.cache_rules(ip, rules)
end

function _M.on_entry_added(item)
    if type(item) ~= "table" then
        return
    end
    local ip = item.ip
    if not ip or ip == "" then
        return
    end
    _M.merge_entries(ip, { item })
end

function _M.lookup_site_id()
    return site_resolver.lookup_site_id()
end

function _M.check(ip, uri)
    if not ip or ip == "" then
        return false
    end

    local dict = shm()
    if not dict then
        return false
    end

    local cached = dict:get(cache_key(ip))
    if not cached or cached == "" then
        return false
    end

    local rules = cjson.decode(cached)
    return rules_match(rules, uri or "", site_resolver.lookup_site_id())
end

--- Load every temporaryblacklist:* entry from Redis into shm (one pass).
local function sync_from_redis()
    if site_resolver.redis_down() then
        return
    end

    local red, err = get_redis(5000)
    if not red then
        ngx.log(ngx.WARN, "temp_blacklist: sync redis connect failed: ", tostring(err))
        site_resolver.mark_redis_down(err)
        return
    end

    local by_ip, total = {}, 0
    local cursor = "0"
    repeat
        local res, scan_err = red:scan(cursor, "MATCH", "temporaryblacklist:*", "COUNT", SYNC_SCAN_COUNT)
        if not res then
            ngx.log(ngx.WARN, "temp_blacklist: sync scan failed: ", tostring(scan_err))
            red:close()
            return
        end
        cursor = res[1]
        local keys = res[2] or {}
        for i = 1, #keys, SYNC_MGET_BATCH do
            local batch = {}
            for j = i, math.min(i + SYNC_MGET_BATCH - 1, #keys) do
                batch[#batch + 1] = keys[j]
            end
            local vals, merr = red:mget(unpack(batch))
            if not vals then
                ngx.log(ngx.WARN, "temp_blacklist: sync mget failed: ", tostring(merr))
                red:close()
                return
            end
            for _, raw in ipairs(vals) do
                if raw and raw ~= ngx.null and raw ~= "" then
                    local item = cjson.decode(raw)
                    if type(item) == "table" and item.ip and item.ip ~= "" then
                        local list = by_ip[item.ip]
                        if not list then
                            list = {}
                            by_ip[item.ip] = list
                        end
                        list[#list + 1] = item
                        total = total + 1
                    end
                end
            end
        end
    until cursor == "0"

    red:set_keepalive(10000, 100)

    for ip, items in pairs(by_ip) do
        _M.merge_entries(ip, items)
    end
    ngx.log(ngx.INFO, "temp_blacklist: synced ", total, " entries from redis")
end

local function sync_loop(premature)
    if premature or ngx.worker.exiting() then
        return
    end
    local ok, err = pcall(sync_from_redis)
    if not ok then
        ngx.log(ngx.ERR, "temp_blacklist: sync failed: ", tostring(err))
    end
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

    -- shm is shared, so one worker is enough for the bulk sync.
    if ngx.worker.id() == 0 then
        ok, err = ngx.timer.at(0, sync_loop)
        if ok then
            ok, err = ngx.timer.every(SYNC_INTERVAL, sync_loop)
        end
        if not ok then
            ngx.log(ngx.ERR, "temp_blacklist: failed to start sync timer: ", tostring(err))
        end
    end
end

return _M
