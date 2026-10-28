-- Drains the l7_guard escalation queue into the eBPF firewall (XDP blocked_ips)
-- via the control socket, batching IPs per block duration:
--   ADD_BLOCK_IPS <secs> <reason>\n<ip>\n...\nEND\n   ->  ok\nadded:N\n
-- Runs on worker 0 only (the queue lives in shm).

local ngx = ngx
local l7_guard = require "resty.l7_guard"

local _M = { _VERSION = "1.0.0" }

local SOCK_PATH = "unix:/tmp/ebpf_fw.sock"
local FLUSH_INTERVAL = 0.2
local BATCH_MAX = 500
local SOCK_TIMEOUT = 2000
local BACKOFF_MAX = 30
local REASON = "l7-guard"

local running = false
local backoff = 0
local retry_at = 0

local function send_batch(secs, ips)
    local sock = ngx.socket.tcp()
    sock:settimeout(SOCK_TIMEOUT)
    local ok, err = sock:connect(SOCK_PATH)
    if not ok then
        return nil, "connect: " .. tostring(err)
    end

    local payload = "ADD_BLOCK_IPS " .. secs .. " " .. REASON .. "\n"
        .. table.concat(ips, "\n") .. "\nEND\n"
    local _, serr = sock:send(payload)
    if serr then
        sock:close()
        return nil, "send: " .. tostring(serr)
    end

    local status, rerr = sock:receive("*l")
    local detail = sock:receive("*l")
    sock:close()
    if status ~= "ok" then
        return nil, "reply: " .. tostring(status or rerr) .. " " .. tostring(detail)
    end
    return detail
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
            -- Put back this group and every group not sent yet.
            local pending = {}
            for j = idx, #order do
                for _, ip in ipairs(groups[order[j]]) do
                    pending[#pending + 1] = ip .. " " .. order[j]
                end
            end
            requeue(dict, pending)
            backoff = backoff == 0 and 1 or math.min(backoff * 2, BACKOFF_MAX)
            retry_at = ngx.now() + backoff
            ngx.log(ngx.ERR, "l7_guard_flusher: XDP escalation failed (", #pending,
                " IPs re-queued, retry in ", backoff, "s): ", err)
            return
        end
        ngx.log(ngx.WARN, "l7_guard_flusher: XDP blocked ", #groups[secs],
            " IPs for ", secs, "s (", detail, ")")
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
