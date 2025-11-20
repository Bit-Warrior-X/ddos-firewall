local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local NGX_ERROR = ngx.ERROR

base.allows_subsystem("http")


ffi.cdef [[
typedef intptr_t ngx_int_t;

ngx_int_t
ngx_http_acl_handle_str_acl_rule(ngx_http_request_t *r, char * str_acl_rule);
ngx_int_t
ngx_http_acl_process_acl_id(ngx_http_request_t* r, int acl_id);

ngx_int_t
ngx_http_acl_handle_acl_rule(ngx_http_request_t* r, int acl_id, int action, int priority, char * str_rule_body);

ngx_int_t
ngx_http_acl_remove_acl_rule(ngx_http_request_t* r, int acl_id);
]]

local _M = {
    version = 0.1
}

local function stringToCharPointer(str)
  -- Allocate memory for the char* (plus one extra byte for the null terminator)
  local charPtr = ffi.new("char[?]", #str + 1)
  -- Copy the string to the char*
  ffi.copy(charPtr, str)
  -- Return the char*
  return charPtr
end

function _M.set_str_acl_rule(str)
    local r = get_request()
    local charPtr = stringToCharPointer(str)
    local rc = C.ngx_http_acl_handle_str_acl_rule(r, charPtr)
    if rc == NGX_ERROR then
        --ffi.C.free(charPtr)
        return nil, "no memory"
    end
    --ffi.C.free(charPtr)
    return true
end

function _M.process_acl_id(id)
    local r = get_request()
    local rc = C.ngx_http_acl_process_acl_id(r, id)
    return rc
end

function _M.set_acl_rule(cfg)
    local r = get_request()
    local rc = C.ngx_http_acl_remove_acl_rule(r, cfg.id)

    if rc == NGX_ERROR then
        return nil, "Failed to remove original acl rule"
    end

    for _, rule in ipairs(cfg.rules) do
        local charPtr = stringToCharPointer(rule.rule)
        local rc = C.ngx_http_acl_handle_acl_rule(r, cfg.id, rule.action, rule.priority, charPtr)
        if rc == NGX_ERROR then
            --ffi.C.free(charPtr)
            return nil, "no memory"
        end
    end
    return true
end

return _M
