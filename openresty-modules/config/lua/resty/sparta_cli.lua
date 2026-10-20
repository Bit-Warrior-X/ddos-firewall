local cjson = require "cjson"

local _M = {}

--- Run a sparta_cli command. Returns output, nil on success or output, err otherwise.
function _M.capture(cmd)
    local handle, err = io.popen(cmd .. " 2>&1", "r")
    if not handle then
        return nil, "failed to run sparta_cli: " .. tostring(err)
    end

    local output = handle:read("*a") or ""
    handle:close()

    if not output:find("ok") then
        return output, "sparta_cli returned error"
    end
    return output, nil
end

function _M.run(cmd)
    local output, err = _M.capture(cmd)
    if err then
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.header.content_type = "application/json"
        ngx.say(cjson.encode({ error = err, details = output }))
        return nil
    end
    return output
end

return _M
