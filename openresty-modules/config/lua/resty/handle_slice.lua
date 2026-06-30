local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local NGX_ERROR = ngx.ERROR

base.allows_subsystem("http")


ffi.cdef [[
typedef intptr_t ngx_int_t;

ngx_int_t 
ngx_http_set_slice(ngx_http_request_t *r, size_t slice_size);
]]

local _M = {
    version = 0.1
}

function _M.set_slice(slice_size)
    local r = get_request()
    local rc = C.ngx_http_set_slice(r, slice_size)
    if rc == NGX_ERROR then
        return nil, "Failed to set slice size"
    end
    return true
end

return _M
