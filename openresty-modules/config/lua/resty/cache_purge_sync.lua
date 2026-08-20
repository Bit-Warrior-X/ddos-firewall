-- Sync nginx cache files when Redis cache-index keys expire or are deleted.
--
-- The ngx_cache_purge C module stores:
--   SETEX <cache_key> <ttl> <cache_file_path>
-- in cache_purge_redis_database (default db 2).
--
-- When a key expires or is DEL'd, the value is no longer readable, so this
-- module keeps a parallel mapping in shm and deletes the file on:
--   1) Redis keyevent notifications (expired/del)
--   2) Per-key ngx.timer.at(ttl) scheduled at index time (reliable fallback)
--   3) Periodic sweep for stale redis keys and orphan cache files

local redis = require "resty.redis"
local ngx = ngx

local _M = { _VERSION = "1.1.0" }

local REDIS_SOCK = "unix:/tmp/redis.sock"
local REDIS_DB = 2
local SHM_NAME = "cache_purge_files"
local CACHE_ROOT = "/usr/local/share/dorian/athens/nginx/cache/athens"
local KEY_PREFIX = "fp:"
local TIMER_PREFIX = "timer:"
local DONE_PREFIX = "done:"
local WARMUP_LOCK_KEY = "warmup_lock"
local WARMUP_LOCK_TTL = 30
local SWEEP_INTERVAL = 10

local REMOVE_EVENTS = {
    expired = true,
    del = true,
    ["unlink"] = true,
}

local INDEX_EVENTS = {
    set = true,
    setex = true,
    setnx = true,
    getset = true,
}

local REQUIRED_FLAGS = "Exgh$"

local cjson_safe

local function get_cjson()
    if not cjson_safe then
        cjson_safe = require "cjson.safe"
    end
    return cjson_safe
end

local function shm()
    return ngx.shared[SHM_NAME]
end

local function log_info(...)
    ngx.log(ngx.INFO, "cache_purge_sync: ", ...)
end

local function log_warn(...)
    ngx.log(ngx.WARN, "cache_purge_sync: ", ...)
end

local function log_debug(...)
    ngx.log(ngx.DEBUG, "cache_purge_sync: ", ...)
end

local function log_err(...)
    ngx.log(ngx.ERR, "cache_purge_sync: ", ...)
end

local function get_redis(timeout)
    local red = redis:new()
    red:set_timeout(timeout or 2000)
    local ok, err = red:connect(REDIS_SOCK)
    if not ok then
        return nil, err
    end
    local ok_sel, sel_err = red:select(REDIS_DB)
    if not ok_sel then
        red:close()
        return nil, sel_err
    end
    return red
end

local function release_redis(red)
    if red then
        pcall(function() red:set_keepalive(10000, 100) end)
    end
end

local function get_max_cache_ttl()
    local red, err = get_redis(1000)
    if not red then
        log_debug("get_max_cache_ttl connect failed: ", tostring(err))
        return 600
    end

    local ok_sel, sel_err = red:select(0)
    if not ok_sel then
        release_redis(red)
        return 600
    end

    local max_ttl = 0
    local cursor = "0"
    repeat
        local res = red:scan(cursor, "MATCH", "cache:*", "COUNT", 50)
        if not res then
            break
        end
        cursor = res[1]
        for _, key in ipairs(res[2] or {}) do
            local site_raw = red:get(key)
            if site_raw and site_raw ~= ngx.null and site_raw ~= "" then
                local site_rules = get_cjson().decode(site_raw)
                if type(site_rules) == "table" then
                    for _, rule in ipairs(site_rules) do
                        local t = tonumber(rule.caching_time) or 0
                        if t > max_ttl then
                            max_ttl = t
                        end
                    end
                end
            end
        end
    until cursor == "0"

    if max_ttl <= 0 then
        local raw = red:get("cacherules")
        if raw and raw ~= ngx.null and raw ~= "" then
            local rules = get_cjson().decode(raw)
            if type(rules) == "table" then
                for _, rule in ipairs(rules) do
                    local t = tonumber(rule.caching_time) or 0
                    if t > max_ttl then
                        max_ttl = t
                    end
                end
            end
        end
    end

    red:select(REDIS_DB)
    release_redis(red)
    return max_ttl > 0 and max_ttl or 600
end

local function normalize_redis_ttl(red, redis_key, ttl)
    ttl = tonumber(ttl) or 0
    if ttl <= 0 then
        return ttl
    end

    local expected = get_max_cache_ttl()
    if ttl <= expected + 5 then
        return ttl
    end

    local ok, exp_err = red:expire(redis_key, expected)
    if not ok then
        log_warn("failed to correct TTL for ", redis_key, ": ", tostring(exp_err))
        return ttl
    end

    log_info("corrected TTL for ", redis_key, " from ", ttl, "s to ", expected, "s")
    return expected
end

local function cache_shm_key(redis_key)
    return KEY_PREFIX .. redis_key
end

local function timer_shm_key(redis_key)
    return TIMER_PREFIX .. redis_key
end

local function is_safe_cache_path(path)
    if type(path) ~= "string" or path == "" then
        return false
    end
    if path:sub(1, #CACHE_ROOT) ~= CACHE_ROOT then
        return false
    end
    if path:find("%.%.", 1, true) then
        return false
    end
    return true
end

function _M.delete_cache_file(path)
    if not is_safe_cache_path(path) then
        log_warn("refusing to delete unsafe path: ", tostring(path))
        return false, "unsafe_path"
    end

    local ok, err = os.remove(path)
    if ok then
        log_info("deleted cache file ", path)
        return true
    end

    if err == "No such file or directory" then
        return true, "missing"
    end

    log_err("failed to delete ", path, ": ", tostring(err))
    return false, err
end

local function done_shm_key(redis_key)
    return DONE_PREFIX .. redis_key
end

local function clear_shm_entry(redis_key)
    local dict = shm()
    if not dict or not redis_key then
        return
    end
    dict:delete(cache_shm_key(redis_key))
    dict:delete(timer_shm_key(redis_key))
end

local function mark_cleaned(redis_key)
    local dict = shm()
    if dict and redis_key then
        dict:set(done_shm_key(redis_key), 1, 120)
    end
end

local function already_cleaned(redis_key)
    local dict = shm()
    return dict and redis_key and dict:get(done_shm_key(redis_key)) ~= nil
end

function _M.cleanup_entry(redis_key, path_hint)
    if not redis_key or redis_key == "" then
        return false
    end

    local dict = shm()
    local path = path_hint
    if dict then
        path = path or dict:get(cache_shm_key(redis_key))
    end

    if path and path ~= "" then
        _M.delete_cache_file(path)
    end

    local red = get_redis(1000)
    if red then
        red:del(redis_key)
        release_redis(red)
    end

    mark_cleaned(redis_key)
    clear_shm_entry(redis_key)
    log_debug("cleaned up redis key ", redis_key)
    return true
end

local function schedule_cleanup(redis_key, path, ttl)
    ttl = tonumber(ttl) or 0
    if ttl <= 0 or not redis_key or redis_key == "" then
        return
    end

    local dict = shm()
    if dict and dict:get(timer_shm_key(redis_key)) then
        return
    end

    if dict then
        dict:set(timer_shm_key(redis_key), true, ttl + 120)
        if path and path ~= "" then
            dict:set(cache_shm_key(redis_key), path, 0)
        end
    end

    local ok, err = ngx.timer.at(ttl, function(premature)
        if premature then
            return
        end
        _M.cleanup_entry(redis_key, path)
    end)

    if not ok then
        log_err("failed to schedule cleanup for ", redis_key, ": ", tostring(err))
    else
        log_debug("scheduled cleanup for ", redis_key, " in ", ttl, "s")
    end
end

function _M.index_key(red, redis_key)
    if not redis_key or redis_key == "" then
        return
    end

    local dict = shm()
    if not dict then
        return
    end

    local path = red:get(redis_key)
    if not path or path == ngx.null or path == "" then
        dict:delete(cache_shm_key(redis_key))
        return
    end

    if not is_safe_cache_path(path) then
        log_warn("ignoring unsafe cache path for key ", redis_key, ": ", path)
        return
    end

    local ttl = red:ttl(redis_key)
    if not ttl or ttl <= 0 then
        ttl = 0
    else
        ttl = normalize_redis_ttl(red, redis_key, ttl)
    end

    dict:set(cache_shm_key(redis_key), path, 0)
    if ttl > 0 then
        schedule_cleanup(redis_key, path, ttl)
    end
end

function _M.on_key_removed(redis_key)
    if not redis_key or redis_key == "" then
        return false
    end

    if already_cleaned(redis_key) then
        log_debug("ignored duplicate removal event for ", redis_key)
        clear_shm_entry(redis_key)
        return true, "already_cleaned"
    end

    local dict = shm()
    local path = dict and dict:get(cache_shm_key(redis_key))
    clear_shm_entry(redis_key)

    if path and path ~= "" then
        mark_cleaned(redis_key)
        return _M.delete_cache_file(path)
    end

    -- Timer-based cleanup may have removed the file and shm entry before this
    -- keyevent (expired/del) arrived; that is normal, not a failure.
    log_debug("no shm path on removal event for ", redis_key,
        " (likely already cleaned by timer)")
    return true, "path_not_cached"
end

local function sweep_once()
    if ngx.worker.id() ~= 0 then
        return
    end

    local red, err = get_redis(5000)
    if not red then
        log_err("sweep redis connect failed: ", tostring(err))
        return
    end

    local referenced_paths = {}
    local cursor = "0"
    repeat
        local res, scan_err = red:scan(cursor, "COUNT", 200)
        if not res or scan_err then
            log_err("sweep scan failed: ", tostring(scan_err))
            break
        end

        cursor = res[1]
        local keys = res[2]
        if keys then
            for _, redis_key in ipairs(keys) do
                local ttl = red:ttl(redis_key)
                local path = red:get(redis_key)

                if ttl == -2 then
                    _M.on_key_removed(redis_key)
                elseif path and path ~= ngx.null and path ~= "" then
                    if is_safe_cache_path(path) then
                        referenced_paths[path] = true
                        local dict = shm()
                        if dict then
                            dict:set(cache_shm_key(redis_key), path, 0)
                        end
                        if ttl and ttl > 0 then
                            ttl = normalize_redis_ttl(red, redis_key, ttl)
                            schedule_cleanup(redis_key, path, ttl)
                        elseif ttl == -1 then
                            -- Key without expiry should not exist; remove stale index.
                            log_warn("redis key without TTL, cleaning up: ", redis_key)
                            _M.cleanup_entry(redis_key, path)
                        end
                    end
                end
            end
        end
    until cursor == "0"

    release_redis(red)

    -- Remove orphan cache files not referenced by any current redis index key.
    local handle = io.popen('find "' .. CACHE_ROOT .. '" -maxdepth 1 -type f -printf "%p\n" 2>/dev/null')
    if handle then
        for line in handle:lines() do
            if line ~= "" and not referenced_paths[line] then
                local stat_handle = io.popen('stat -c %Y "' .. line .. '" 2>/dev/null')
                if stat_handle then
                    local mtime = tonumber(stat_handle:read("*l"))
                    stat_handle:close()
                    if mtime and (ngx.time() - mtime) > SWEEP_INTERVAL then
                        _M.delete_cache_file(line)
                    end
                end
            end
        end
        handle:close()
    end
end

function _M.warm_up()
    local dict = shm()
    if not dict then
        return
    end

    if ngx.worker.id() ~= 0 then
        return
    end

    if not dict:add(WARMUP_LOCK_KEY, true, WARMUP_LOCK_TTL) then
        return
    end

    local red, err = get_redis(5000)
    if not red then
        log_err("warm_up redis connect failed: ", tostring(err))
        return
    end

    local cursor = "0"
    local indexed = 0
    repeat
        local res, scan_err = red:scan(cursor, "COUNT", 200)
        if not res or scan_err then
            log_err("warm_up scan failed: ", tostring(scan_err))
            break
        end

        cursor = res[1]
        local keys = res[2]
        if keys then
            for _, redis_key in ipairs(keys) do
                _M.index_key(red, redis_key)
                indexed = indexed + 1
            end
        end
    until cursor == "0"

    release_redis(red)
    log_info("warm_up indexed ", indexed, " cache key(s) from redis db ", REDIS_DB)
end

local function flags_sufficient(existing)
    if not existing or existing == "" then
        return false
    end
    if existing == "AKE" or existing:find("A", 1, true) then
        return true
    end
    return existing:find("E", 1, true)
        and existing:find("x", 1, true)
        and existing:find("g", 1, true)
        and existing:find("%$", 1, true)
end

local function ensure_keyspace_notifications(red)
    local current, err = red:config("get", "notify-keyspace-events")
    if not current then
        log_warn("could not read notify-keyspace-events: ", tostring(err))
        return false
    end

    local existing = ""
    if type(current) == "table" then
        existing = current[2] or current["notify-keyspace-events"] or ""
    end

    if flags_sufficient(existing) then
        return true
    end

    local ok, set_err = red:config("set", "notify-keyspace-events", REQUIRED_FLAGS)
    if not ok then
        log_warn("could not set notify-keyspace-events=", REQUIRED_FLAGS,
            " (set manually in redis-socket.conf): ", tostring(set_err))
        return false
    end

    log_info("set notify-keyspace-events=", REQUIRED_FLAGS)
    return true
end

local function handle_keyevent(event, redis_key)
    if not redis_key or redis_key == "" then
        return
    end

    if REMOVE_EVENTS[event] then
        _M.on_key_removed(redis_key)
        return
    end

    if INDEX_EVENTS[event] then
        local red, conn_err = get_redis(1000)
        if not red then
            log_err("index event redis connect failed: ", tostring(conn_err))
            return
        end
        _M.index_key(red, redis_key)
        release_redis(red)
    end
end

function _M.start_subscriber(premature)
    if premature or ngx.worker.exiting() then
        return
    end

    if ngx.worker.id() ~= 0 then
        return
    end

    local backoff = 1
    local pattern = "__keyevent@" .. REDIS_DB .. "__:*"

    while not ngx.worker.exiting() do
        local red, err = get_redis(2000)
        if not red then
            log_err("subscriber redis connect failed: ", tostring(err))
            ngx.sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        ensure_keyspace_notifications(red)
        red:set_timeout(5000)

        local ok_sub, sub_err = red:psubscribe(pattern)
        if not ok_sub then
            log_err("psubscribe failed: ", tostring(sub_err))
            pcall(red.close, red)
            ngx.sleep(backoff)
            backoff = math.min(backoff * 2, 30)
            goto continue
        end

        backoff = 1
        log_info("subscribed to ", pattern)

        while not ngx.worker.exiting() do
            local msg, read_err = red:read_reply()
            if not msg then
                if read_err ~= "timeout" then
                    log_err("read_reply failed: ", tostring(read_err))
                    break
                end
            elseif type(msg) == "table" and msg[1] == "pmessage" then
                local channel = msg[3]
                local redis_key = msg[4]
                local event = channel and channel:match(":(%w+)$")
                if event then
                    handle_keyevent(event, redis_key)
                end
            end
        end

        pcall(function()
            pcall(red.punsubscribe, red, pattern)
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

local function start_sweep_timer(premature)
    if premature or ngx.worker.exiting() then
        return
    end

    if ngx.worker.id() ~= 0 then
        return
    end

    sweep_once()

    local ok, err = ngx.timer.at(SWEEP_INTERVAL, start_sweep_timer)
    if not ok then
        log_err("failed to reschedule sweep timer: ", tostring(err))
    end
end

function _M.start()
    if ngx.worker.id() ~= 0 then
        return
    end

    local ok_warm, err_warm = ngx.timer.at(0.2, function(premature)
        if premature then
            return
        end
        _M.warm_up()
    end)
    if not ok_warm then
        log_err("failed to schedule warm_up: ", tostring(err_warm))
    end

    local ok_sub, err_sub = ngx.timer.at(0, _M.start_subscriber)
    if not ok_sub then
        log_err("failed to start subscriber: ", tostring(err_sub))
    end

    local ok_sweep, err_sweep = ngx.timer.at(SWEEP_INTERVAL, start_sweep_timer)
    if not ok_sweep then
        log_err("failed to start sweep timer: ", tostring(err_sweep))
    end
end

return _M
