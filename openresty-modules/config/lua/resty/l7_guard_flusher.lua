-- Drains the l7_guard escalation queue into angelos, which picks Sparta
-- (unified license) or nftables (L7-only). Athens never opens /tmp/ebpf_fw.sock.
--   POST /internal/l7_escalate  { ips, ttl, reason }
-- Runs on worker 0 only (the queue lives in shm).

local ngx = ngx
local cjson = require "cjson.safe"
local l7_guard = require "resty.l7_guard"

local _M = { _VERSION = "1.1.0" }

local ANGELOS_HOST = "127.0.0.1"
local ANGELOS_PORT = tonumber(os.getenv("ANGELOS_PORT") or "") or 5000
local ANGELOS_URI = "/internal/l7_escalate"
local FLUSH_INTERVAL = 0.2
local BATCH_MAX = 500
local SOCK_TIMEOUT = 2000
local BACKOFF_MAX = 30
local REASON = "l7-guard"

local running = false
local backoff = 0
local retry_at = 0

local function http_post_json(body)
    local sock = ngx.socket.tcp()
    sock:settimeout(SOCK_TIMEOUT)
    local ok, err = sock:connect(ANGELOS_HOST, ANGELOS_PORT)
    if not ok then
        return nil, "connect: " .. tostring(err)
    end

    local payload = body
    local req = table.concat({
        "POST ", ANGELOS_URI, " HTTP/1.0\r\n",
        "Host: ", ANGELOS_HOST, "\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: ", #payload, "\r\n",
        "Connection: close\r\n",
        "\r\n",
        payload,
    })
    local _, serr = sock:send(req)
    if serr then
        sock:close()
        return nil, "send: " .. tostring(serr)
    end

    local chunks = {}
    while true do
        local data, rerr, partial = sock:receive(8192)
        if data then
            chunks[#chunks + 1] = data
        elseif partial and partial ~= "" then
            chunks[#chunks + 1] = partial
        end
        if rerr == "closed" then
            break
        end
        if rerr and rerr ~= "closed" then
            sock:close()
            return nil, "read: " .. tostring(rerr)
        end
        if not data and not partial then
            break
        end
    end
    sock:close()

    local raw = table.concat(chunks)
    local status = tonumber(raw:match("^HTTP/%d%.%d (%d+)")) or 0
    local resp_body = raw:match("\r\n\r\n(.*)$") or raw:match("\n\n(.*)$") or ""
    if status < 200 or status >= 300 then
        return nil, "http " .. tostring(status) .. " " .. tostring(resp_body):sub(1, 200)
    end
    local decoded = cjson.decode(resp_body)
    if type(decoded) == "table" and decoded.status == "success" then
        return decoded
    end
    local msg = type(decoded) == "table" and (decoded.message or decoded.detail) or resp_body
    return nil, tostring(msg or "escalate failed")
end

local function send_batch(secs, ips)
    local body = cjson.encode({
        ips = ips,
        ttl = tonumber(secs) or 0,
        reason = REASON,
    })
    if not body then
        return nil, "json encode failed"
    end
    return http_post_json(body)
end

local function requeue(dict, items)
    for i = #items, 1, -1 do
        dict:lpush(l7_guard.QUEUE_KEY, items[i])
    end
end

local function flush()
    local dict = ngx.shared[l7_guard.SHM_NAME]
    if not dict then
        return
    end
    if ngx.now() < retry_at then
        return
    end

    local items, groups, order = {}, {}, {}
    for _ = 1, BATCH_MAX do
        local item = dict:lpop(l7_guard.QUEUE_KEY)
        if not item then
            break
        end
        local ip, secs = item:match("^(%S+) (%d+)$")
        if ip then
            items[#items + 1] = item
            local g = groups[secs]
            if not g then
                g = {}
                groups[secs] = g
                order[#order + 1] = secs
            end
            g[#g + 1] = ip
        end
    end
    if #items == 0 then
        return
    end

    for idx, secs in ipairs(order) do
        local detail, err = send_batch(secs, groups[secs])
        if not detail then
            local pending = {}
            for j = idx, #order do
                for _, ip in ipairs(groups[order[j]]) do
                    pending[#pending + 1] = ip .. " " .. order[j]
                end
            end
            requeue(dict, pending)
            backoff = backoff == 0 and 1 or math.min(backoff * 2, BACKOFF_MAX)
            retry_at = ngx.now() + backoff
            ngx.log(ngx.ERR, "l7_guard_flusher: escalate failed (", #pending,
                " IPs re-queued, retry in ", backoff, "s): ", err)
            return
        end
        local backend = detail.backend or "?"
        ngx.log(ngx.WARN, "l7_guard_flusher: blocked ", #groups[secs],
            " IPs for ", secs, "s via ", backend,
            " (added=", tostring(detail.added), ")")
    end
    backoff = 0
end

local function tick(premature)
    if premature or running then
        return
    end
    running = true
    local ok, err = pcall(flush)
    running = false
    if not ok then
        ngx.log(ngx.ERR, "l7_guard_flusher: ", tostring(err))
    end
end

function _M.start()
    if ngx.worker.id() ~= 0 then
        return
    end
    local ok, err = ngx.timer.every(FLUSH_INTERVAL, tick)
    if not ok then
        ngx.log(ngx.ERR, "l7_guard_flusher: failed to start timer: ", tostring(err))
    end
end

return _M
