-- NDJSON access / security log export (GET /access_logs).
--
-- nginx writes one raw line per request (log_format access_ndjson, http_access_log.conf)
-- into hourly files named after the local hour of $time_iso8601. This module filters
-- them by [start, end), site and type, and reshapes each line into an AccessLogRecord.

local cjson = require("cjson.safe").new()
local request_stats = require "resty.request_stats"

cjson.encode_escape_forward_slash(false)

local _M = { _VERSION = "1.0.0" }

local LOG_DIR = "/usr/local/share/dorian/athens/nginx/logs/access"
local FILE_PREFIX = "access-"
local FILE_SUFFIX = ".ndjson"
local FILE_PATTERN = "^access%-(%d%d%d%d%-%d%d%-%d%dT%d%d)%.ndjson$"

local RETENTION_SECONDS = 7 * 24 * 3600
-- Files are removed one day after they leave the advertised retention window.
local DELETE_AFTER_SECONDS = RETENTION_SECONDS + 24 * 3600
local MAINTENANCE_PERIOD = 300

local DEFAULT_LIMIT = 50000
local MAX_LIMIT = 200000
local OUTPUT_CHUNK = 500
local YIELD_EVERY = 2000

local STATE_RETENTION_KEY = "access_log_retention_start"

local function hour_name(t)
    return os.date("%Y-%m-%dT%H", t)
end

local function file_path(hour)
    return LOG_DIR .. "/" .. FILE_PREFIX .. hour .. FILE_SUFFIX
end

local function list_hours()
    local hours = {}
    local p = io.popen("ls -1 " .. LOG_DIR .. " 2>/dev/null")
    if not p then
        return hours
    end
    for name in p:lines() do
        local hour = name:match(FILE_PATTERN)
        if hour then
            hours[#hours + 1] = hour
        end
    end
    p:close()
    table.sort(hours)
    return hours
end

local function first_record_time(hour)
    local f = io.open(file_path(hour), "r")
    if not f then
        return nil
    end
    local line = f:read("*l")
    f:close()
    return line and tonumber(line:match('^{"msec":"([%d%.]+)"'))
end

local function compute_retention_start()
    for _, hour in ipairs(list_hours()) do
        local t = first_record_time(hour)
        if t then
            return math.floor(t)
        end
    end
    return nil
end

local function retention_start()
    local state = ngx.shared.stats_cache
    local cached = state and tonumber(state:get(STATE_RETENTION_KEY))
    if cached then
        return cached
    end
    local t = compute_retention_start()
    if t and state then
        state:set(STATE_RETENTION_KEY, t, MAINTENANCE_PERIOD)
    end
    return t
end

local function maintenance(premature)
    if premature then
        return
    end
    os.execute("mkdir -p " .. LOG_DIR)

    local cutoff = hour_name(ngx.time() - DELETE_AFTER_SECONDS)
    for _, hour in ipairs(list_hours()) do
        if hour < cutoff then
            os.remove(file_path(hour))
        end
    end

    local state = ngx.shared.stats_cache
    local t = compute_retention_start()
    if state and t then
        state:set(STATE_RETENTION_KEY, t, MAINTENANCE_PERIOD * 2)
    end
end

--- Worker 0 creates the log dir and prunes files past retention.
function _M.start()
    if ngx.worker.id() ~= 0 then
        return
    end
    ngx.timer.at(0, maintenance)
    local ok, err = ngx.timer.every(MAINTENANCE_PERIOD, maintenance)
    if not ok then
        ngx.log(ngx.ERR, "access_logs: failed to start maintenance timer: ", tostring(err))
    end
end

local function bad_request(message, status)
    ngx.status = status or ngx.HTTP_BAD_REQUEST
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode({ error = message }))
end

local function int_arg(raw)
    if type(raw) ~= "string" or not raw:match("^%d+$") then
        return nil
    end
    return tonumber(raw)
end

-- Raw lines come from our own log_format, so cheap pattern matches are enough to filter.
local function line_matches(line, start_ts, end_ts, site_filter, security_only)
    local msec = tonumber(line:match('^{"msec":"([%d%.]+)"'))
    if not msec then
        return false, nil
    end
    if msec < start_ts then
        return false, msec
    end
    if msec >= end_ts then
        return false, msec
    end
    if site_filter then
        local sid = line:match('"site_id":"(%d*)"')
        if (sid == "" and "0" or sid) ~= site_filter then
            return false, msec
        end
    end
    if security_only and not line:find('"blocked":"1"', 1, true) then
        return false, msec
    end
    return true, msec
end

local function nullable(v)
    if v == nil or v == "" or v == "-" then
        return cjson.null
    end
    return v
end

local function format_time(msec)
    local sec = math.floor(msec)
    local ms = math.floor((msec - sec) * 1000 + 0.5)
    if ms >= 1000 then
        sec = sec + 1
        ms = ms - 1000
    end
    return os.date("!%Y-%m-%dT%H:%M:%S", sec) .. string.format(".%03dZ", ms)
end

local function to_record(raw)
    local blocked = raw.blocked == "1"
    local contacted = raw.upstream_addr ~= nil and raw.upstream_addr ~= "" and raw.upstream_addr ~= "-"

    local upstream_status = cjson.null
    local upstream_ms = cjson.null
    if contacted then
        -- No header time means origin never answered; nginx made up the 502 / 504.
        local header_time = request_stats.last_token(raw.upstream_header_time)
        if header_time and header_time ~= "-" then
            upstream_status = tonumber(request_stats.last_token(raw.upstream_status)) or cjson.null
        end
        local secs, seen = request_stats.sum_tokens(raw.upstream_response_time)
        if seen then
            upstream_ms = secs * 1000
        end
    end

    local cache_status = cjson.null
    if not blocked then
        cache_status = nullable(raw.cache_status)
    end

    local rule_type, rule_id = cjson.null, cjson.null
    if blocked then
        rule_type = nullable(raw.rule_type)
        rule_id = nullable(raw.rule_id)
    end

    return {
        time = format_time(tonumber(raw.msec) or 0),
        request_id = nullable(raw.request_id),
        site_id = tonumber(raw.site_id) or 0,
        client_ip = raw.client_ip or "",
        country_iso = nullable(raw.country_iso),
        method = raw.method or "",
        scheme = raw.scheme or "",
        host = raw.host or "",
        uri = raw.uri or "",
        protocol = raw.protocol or "",
        status = tonumber(raw.status) or 0,
        bytes_sent = tonumber(raw.bytes_sent) or 0,
        request_length = tonumber(raw.request_length) or 0,
        referer = nullable(raw.referer),
        user_agent = nullable(raw.user_agent),
        content_type = nullable(raw.content_type),
        cache_status = cache_status,
        request_time_ms = (tonumber(raw.request_time) or 0) * 1000,
        upstream_status = upstream_status,
        upstream_response_time_ms = upstream_ms,
        upstream_bytes_received = (request_stats.sum_tokens(raw.upstream_bytes_received)),
        blocked = blocked,
        rule_type = rule_type,
        rule_id = rule_id,
    }
end

--- Hour files that can hold records in [start_ts, end_ts), oldest first.
local function candidate_hours(start_ts, end_ts)
    local hours, seen = {}, {}
    -- One hour of slack each side: the file hour is local time at log write.
    local t = start_ts - 3600
    while t < end_ts + 3600 do
        local h = hour_name(t)
        if not seen[h] then
            seen[h] = true
            hours[#hours + 1] = h
        end
        t = t + 3600
    end
    table.sort(hours)
    return hours
end

--- Calls fn(line, hour, line_offset) for each complete line from the cursor on;
--- fn returns false to stop. Returns true when stopped early.
local function scan(hours, cursor_hour, cursor_offset, fn)
    local processed = 0
    for _, hour in ipairs(hours) do
        if not cursor_hour or hour >= cursor_hour then
            local f = io.open(file_path(hour), "r")
            if f then
                local offset = 0
                if cursor_hour and hour == cursor_hour and cursor_offset > 0 then
                    offset = f:seek("set", cursor_offset) or 0
                end
                while true do
                    local line = f:read("*l")
                    if not line then
                        break
                    end
                    -- A line still being written has no closing brace yet.
                    if line:sub(-1) ~= "}" then
                        break
                    end
                    if fn(line, hour, offset) == false then
                        f:close()
                        return true
                    end
                    offset = offset + #line + 1
                    processed = processed + 1
                    if processed % YIELD_EVERY == 0 then
                        ngx.sleep(0)
                    end
                end
                f:close()
            end
        end
    end
    return false
end

function _M.handle()
    local args = ngx.req.get_uri_args()
    local start_ts = int_arg(args.start)
    local end_ts = int_arg(args["end"])
    if not start_ts or not end_ts then
        return bad_request("start and end are required Unix epoch seconds")
    end
    if end_ts <= start_ts then
        return bad_request("end must be greater than start")
    end

    local log_type = args.type
    if log_type == nil or log_type == "" then
        log_type = "access"
    end
    if log_type ~= "access" and log_type ~= "security" then
        return bad_request("type must be access or security")
    end

    local limit = DEFAULT_LIMIT
    if args.limit ~= nil and args.limit ~= "" then
        limit = int_arg(args.limit)
        if not limit or limit < 1 then
            return bad_request("Invalid limit")
        end
        limit = math.min(limit, MAX_LIMIT)
    end

    local site_raw = args.siteId or args.site_id
    local site_filter
    if site_raw ~= nil and site_raw ~= "" then
        if type(site_raw) ~= "string" or not site_raw:match("^%d+$") then
            return bad_request("Invalid siteId")
        end
        site_filter = tostring(tonumber(site_raw))
    end

    local cursor_hour, cursor_offset
    if args.cursor ~= nil and args.cursor ~= "" then
        if type(args.cursor) == "string" then
            cursor_hour, cursor_offset = args.cursor:match("^(%d%d%d%d%-%d%d%-%d%dT%d%d)@(%d+)$")
        end
        if not cursor_hour then
            return bad_request("Invalid cursor")
        end
        cursor_offset = tonumber(cursor_offset)
    end

    local oldest = retention_start()
    if oldest then
        ngx.header["X-Retention-Start"] = tostring(oldest)
        if end_ts <= oldest then
            return bad_request("Range starts before retained logs (" .. oldest .. ")", 416)
        end
    end

    local hours = candidate_hours(start_ts, end_ts)
    local security_only = log_type == "security"

    -- Pass 1: find where record limit+1 starts; that position is the next cursor.
    local matched = 0
    local next_cursor
    local stop_hour, stop_offset
    scan(hours, cursor_hour, cursor_offset or 0, function(line, hour, offset)
        if line_matches(line, start_ts, end_ts, site_filter, security_only) then
            matched = matched + 1
            if matched > limit then
                next_cursor = hour .. "@" .. offset
                return false
            end
        end
        stop_hour, stop_offset = hour, offset + #line + 1
        return true
    end)

    ngx.header.content_type = "application/x-ndjson"
    if next_cursor then
        ngx.header["X-Next-Cursor"] = next_cursor
    end

    -- Pass 2: stream the page, stopping where pass 1 stopped so lines appended
    -- in between cannot push records past this page without a cursor.
    local sent = 0
    local buf = {}
    scan(hours, cursor_hour, cursor_offset or 0, function(line, hour, offset)
        if sent >= limit or not stop_hour or hour > stop_hour
            or (hour == stop_hour and offset >= stop_offset) then
            return false
        end
        if line_matches(line, start_ts, end_ts, site_filter, security_only) then
            local raw = cjson.decode(line)
            if type(raw) == "table" then
                buf[#buf + 1] = cjson.encode(to_record(raw))
                sent = sent + 1
                if #buf >= OUTPUT_CHUNK then
                    ngx.print(table.concat(buf, "\n"), "\n")
                    ngx.flush()
                    buf = {}
                end
            end
        end
        return true
    end)
    if #buf > 0 then
        ngx.print(table.concat(buf, "\n"), "\n")
    end
end

return _M
