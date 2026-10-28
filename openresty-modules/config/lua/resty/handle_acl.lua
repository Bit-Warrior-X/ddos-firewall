local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local NGX_ERROR = ngx.ERROR

base.allows_subsystem("http")

ffi.cdef [[
typedef intptr_t ngx_int_t;

ngx_int_t
ngx_http_acl_handle_str_acl_rule(ngx_http_request_t *r, const char * str_acl_rule);
ngx_int_t
ngx_http_acl_process_acl_id(ngx_http_request_t* r, int acl_id);

ngx_int_t
ngx_http_acl_handle_acl_rule(ngx_http_request_t* r, int acl_id, int action, int priority, const char * str_rule_body);

ngx_int_t
ngx_http_acl_remove_acl_rule(ngx_http_request_t* r, int acl_id);

ngx_int_t
ngx_http_acl_matched_priority(ngx_http_request_t* r);
]]

local _M = {
    version = 0.1
}

-- Function to allocate a C string (char*) and copy the Lua string into it
local function stringToCharPointer(str)
    local size = #str + 1  -- Plus one for the null terminator
    local charPtr = ffi.new("char[?]", size)  -- Allocate memory
    if charPtr == nil then
        return nil
    end
    ffi.copy(charPtr, str, size)
    return charPtr
end

function _M.set_str_acl_rule(str)
    local r = get_request()
    local charPtr = stringToCharPointer(str)
    if charPtr == nil then
        return nil, "no memory"
    end

    local rc = C.ngx_http_acl_handle_str_acl_rule(r, charPtr)

    if rc == NGX_ERROR then
        return nil, "failed to set string ACL rule"
    end
    return true
end

function _M.process_acl_id(id)
    local r = get_request()
    local rc = C.ngx_http_acl_process_acl_id(r, id)
    return rc
end

--- Priority of the rule matched by the last process_acl_id call, or nil.
function _M.matched_priority()
    local r = get_request()
    local ok, prio = pcall(function()
        return C.ngx_http_acl_matched_priority(r)
    end)
    if not ok then
        return nil
    end
    prio = tonumber(prio)
    if not prio or prio < 0 then
        return nil
    end
    return prio
end

-- Never-matching placeholder so an empty WAF type still owns its ACL id in
-- ngx_acl shm. Without it, remove+empty leaves the id missing and every
-- request logs "There is no ACL rule which's id is N".
local EMPTY_ACL_PLACEHOLDER = '["Header","Host","eq","__dorian_acl_empty__"]'
local ACTION_ALLOW = 1

function _M.set_acl_rule(cfg)
    local r = get_request()
    local rc = C.ngx_http_acl_remove_acl_rule(r, cfg.id)

    if rc == NGX_ERROR then
        return nil, "Failed to remove original ACL rule"
    end

    local rules = cfg.rules
    if type(rules) ~= "table" or #rules == 0 then
        local charPtr = stringToCharPointer(EMPTY_ACL_PLACEHOLDER)
        if charPtr == nil then
            return nil, "no memory"
        end
        rc = C.ngx_http_acl_handle_acl_rule(r, cfg.id, ACTION_ALLOW, 0, charPtr)
        if rc == NGX_ERROR then
            return nil, "failed to handle empty ACL placeholder"
        end
        return true
    end

    for _, rule in ipairs(rules) do
        local charPtr = stringToCharPointer(rule.rule)
        if charPtr == nil then
            return nil, "no memory"
        end

        rc = C.ngx_http_acl_handle_acl_rule(r, cfg.id, rule.action, rule.priority, charPtr)

        if rc == NGX_ERROR then
            return nil, "failed to handle ACL rule"
        end
    end
    return true
end

return _M
