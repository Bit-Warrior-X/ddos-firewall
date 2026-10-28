-- L7 abuse detector (HTTP/2 rapid reset, request floods, limit_req rejects).
-- Runs in log_by_lua for every request (including limit_req / limit_conn
-- rejections and client-reset streams). Never touches Redis on the hot path.
--
-- Per-IP counters over a fixed window (default 10s):
--   req  - all requests
--   rst  - 499 with ~0 request_time and no upstream (client reset the stream)
--   rej  - 444 from limit_req / limit_conn / temporary-block
--   bad  - 400/408 with no request line (malformed / empty connections);
--          needs the server-level log_by_lua hook, these never reach a location
--   bare - HTTP/2 requests without Accept and Accept-Language (weak signal:
--          when most of an IP's requests are bare, req_threshold is halved)
-- On trigger: block locally in temp_blacklist shm (all workers), persist to
-- Redis asynchronously, and queue the IP for XDP (resty.l7_guard_flusher).
--
-- Optional overrides: Redis key l7guard:config (JSON), polled by worker 0:
--   {"enabled":true,"xdp":true,"window":10,"rst_threshold":100,
--    "rej_threshold":200,"bad_threshold":100,"req_threshold":1000,"block_ttl":600,
--    "block_max_ttl":3600,"allow_ips":["1.2.3.4"]}

local ngx = ngx
local cjson = require "cjson.safe"

local _M = { _VERSION = "1.0.0" }

local SHM_NAME = "l7_guard"
local QUEUE_KEY = "queue"
local CONFIG_KEY = "cfg"
local CONFIG_REDIS_KEY = "l7guard:config"
local CONFIG_POLL_INTERVAL = 10
local CONFIG_L1_TTL = 2
local OFFENSE_MEMORY = 86400
local QUEUE_MAX = 100000

local DEFAULTS = {
    enabled = true,
    xdp = true,
    window = 10,
    rst_threshold = 100,
    rej_threshold = 200,
    bad_threshold = 100,
    req_threshold = 1000,
    block_ttl = 600,
    block_max_ttl = 3600,
    allow_ips = {},
}

_M.SHM_NAME = SHM_NAME
_M.QUEUE_KEY = QUEUE_KEY

local cfg_l1, cfg_l1_at = nil, 0

local function build_config(raw)
    local cfg = {}
    for k, v in pairs(DEFAULTS) do
        cfg[k] = v
    end
    if type(raw) == "table" then
        for k, v in pairs(raw) do
            if DEFAULTS[k] ~= nil and type(v) == type(DEFAULTS[k]) then
                cfg[k] = v
            end
        end
    end
    local allow = {}
    for _, ip in ipairs(cfg.allow_ips) do
        allow[tostring(ip)] = true
    end
    cfg.allow_set = allow
    cfg.window = math.max(1, math.floor(cfg.window))
    return cfg
end

local function get_config()
    local now = ngx.now()
    if cfg_l1 and now - cfg_l1_at < CONFIG_L1_TTL then
        return cfg_l1
    end
    local dict = ngx.shared[SHM_NAME]
    local raw = dict and dict:get(CONFIG_KEY)
    cfg_l1 = build_config(raw and cjson.decode(raw))
    cfg_l1_at = now
    return cfg_l1
end

_M.get_config = get_config

local function is_exempt(ip, cfg)
    if ip:find(":", 1, true) then
        -- IPv6: XDP blocked_ips is IPv4-only.
        return true
    end
    if ip:sub(1, 4) == "127." or ip:sub(1, 3) == "10." or ip:sub(1, 8) == "192.168." then
        return true
    end
    local b2 = ip:match("^172%.(%d+)%.")
    if b2 then
        b2 = tonumber(b2)
        if b2 >= 16 and b2 <= 31 then
            return true
        end
    end
    if ip == ngx.var.server_addr then
        return true
    end
    return cfg.allow_set[ip] == true
end

local function count(dict, kind, ip, bucket, ttl)
    local v = dict:incr("c:" .. kind .. ":" .. ip .. ":" .. bucket, 1, 0, ttl)
    return v or 0
end

local function is_reset()
    if ngx.var.status ~= "499" then
        return false
    end
    local addr = ngx.var.upstream_addr
    if addr and addr ~= "" and addr ~= "-" then
        return false
    end
    return (tonumber(ngx.var.request_time) or 1) < 0.005
end

local function is_rejected()
    if ngx.var.status ~= "444" then
        return false
    end
    return ngx.var.limit_req_status == "REJECTED"
        or ngx.var.limit_conn_status == "REJECTED"
        or ngx.var.waf_rule_type == "temporary-block"
end

local function is_bad_request()
    local status = ngx.var.status
    if status ~= "400" and status ~= "408" then
        return false
    end
    local method = ngx.var.request_method
    return method == nil or method == ""
end

local function is_bare_h2()
    if ngx.var.server_protocol ~= "HTTP/2.0" then
        return false
    end
    return ngx.var.http_accept == nil and ngx.var.http_accept_language == nil
end

local function escalate(dict, ip, cfg, reason, counters)
    local offenses = dict:incr("off:" .. ip, 1, 0, OFFENSE_MEMORY) or 1
    local ttl = cfg.block_ttl * 2 ^ (offenses - 1)
    if ttl > cfg.block_max_ttl then
        ttl = cfg.block_max_ttl
    end
    ttl = math.floor(ttl)
    -- Re-arm the dedupe marker with the real block duration.
    dict:set("blk:" .. ip, true, ttl)

    local ok_acl, acl_access = pcall(require, "resty.acl_access")
    if ok_acl and acl_access.add_temporaryblacklist then
        acl_access.add_temporaryblacklist(nil, ip, ".*", "l7-guard:" .. reason, ttl, true)
    end

    if cfg.xdp then
        if (dict:llen(QUEUE_KEY) or 0) < QUEUE_MAX then
            local _, err = dict:rpush(QUEUE_KEY, ip .. " " .. ttl)
            if err then
                ngx.log(ngx.ERR, "l7_guard: queue push failed for ", ip, ": ", err)
            end
        end
    end

    local stats_cache = ngx.shared.stats_cache
    if stats_cache then
        stats_cache:incr("l7guard_escalated", 1, 0)
        stats_cache:incr("l7guard_escalated:" .. reason, 1, 0)
    end
    ngx.var.waf_rule_type = "l7-guard"

    ngx.log(ngx.WARN, "l7_guard: blocking ", ip, " for ", ttl, "s reason=", reason,
        " offense=", offenses, " req=", counters.req, " rst=", counters.rst,
        " rej=", counters.rej, " bad=", counters.bad, " bare=", counters.bare, " host=",
        tostring(ngx.var.host), " xdp=", tostring(cfg.xdp))
end

--- log_by_lua entry point.
function _M.log()
    local cfg = get_config()
    if not cfg.enabled then
        return
    end
    local dict = ngx.shared[SHM_NAME]
    if not dict then
        return
    end

    local ip = ngx.var.remote_addr
    if not ip or ip == "" or is_exempt(ip, cfg) then
        return
    end
    -- Already escalated: XDP / temp_blacklist is handling it.
    if dict:get("blk:" .. ip) then
        return
    end

    local window = cfg.window
    local bucket = math.floor(ngx.now() / window)
    local ttl = window * 2

    local c = {
        req = count(dict, "req", ip, bucket, ttl),
        rst = 0, rej = 0, bad = 0, bare = 0,
    }
    if is_bad_request() then
        c.bad = count(dict, "bad", ip, bucket, ttl)
    else
        c.bad = dict:get("c:bad:" .. ip .. ":" .. bucket) or 0
    end
    if is_reset() then
        c.rst = count(dict, "rst", ip, bucket, ttl)
    else
        c.rst = dict:get("c:rst:" .. ip .. ":" .. bucket) or 0
    end
    if is_rejected() then
        c.rej = count(dict, "rej", ip, bucket, ttl)
    else
        c.rej = dict:get("c:rej:" .. ip .. ":" .. bucket) or 0
    end
    if is_bare_h2() then
        c.bare = count(dict, "bare", ip, bucket, ttl)
    else
        c.bare = dict:get("c:bare:" .. ip .. ":" .. bucket) or 0
    end

    local req_threshold = cfg.req_threshold
    if c.bare * 2 >= c.req then
        req_threshold = math.floor(req_threshold / 2)
    end

    local reason
    if c.rst >= cfg.rst_threshold then
        reason = "rapid-reset"
    elseif c.rej >= cfg.rej_threshold then
        reason = "rejected"
    elseif c.bad >= cfg.bad_threshold then
        reason = "malformed"
    elseif c.req >= req_threshold then
        reason = "flood"
    end
    if not reason then
        return
    end

    -- One escalation per IP across all workers.
    if dict:add("blk:" .. ip, true, cfg.block_ttl) then
        escalate(dict, ip, cfg, reason, c)
    end
end

local function poll_config(premature)
    if premature or ngx.worker.exiting() then
        return
    end
    local site_resolver = require "resty.site_resolver"
    if site_resolver.redis_down() then
        return
    end

    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(1000)
    local ok, err = red:connect("unix:/tmp/redis.sock", { pool = "athens_redis_db0" })
    if not ok then
        site_resolver.mark_redis_down(err)
        return
    end
    local raw, gerr = red:get(CONFIG_REDIS_KEY)
    if gerr then
        red:close()
        return
    end
    red:set_keepalive(10000, 100)

    local dict = ngx.shared[SHM_NAME]
    if not dict then
        return
    end
    if raw and raw ~= ngx.null and raw ~= "" then
        if cjson.decode(raw) then
            dict:set(CONFIG_KEY, raw)
        else
            ngx.log(ngx.WARN, "l7_guard: invalid JSON in ", CONFIG_REDIS_KEY)
        end
    else
        dict:delete(CONFIG_KEY)
    end
end

--- init_worker: worker 0 polls the Redis config override.
function _M.start()
    if ngx.worker.id() ~= 0 then
        return
    end
    local ok, err = ngx.timer.at(0, poll_config)
    if ok then
        ok, err = ngx.timer.every(CONFIG_POLL_INTERVAL, poll_config)
    end
    if not ok then
        ngx.log(ngx.ERR, "l7_guard: failed to start config timer: ", tostring(err))
    end
end

return _M
