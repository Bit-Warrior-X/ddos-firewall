local cjson = require "cjson"

local _M = {}

function _M.run(cmd)
    local handle, err = io.popen(cmd .. " 2>&1", "r")
    if not handle then
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.header.content_type = "application/json"
        ngx.say(cjson.encode({ error = "failed to run sparta_cli", details = err }))
        return nil
    end

    local output = handle:read("*a") or ""
    handle:close()

    if not output:find("ok") then
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.header.content_type = "application/json"
        ngx.say(cjson.encode({ error = "sparta_cli returned error", details = output }))
        return nil
    end

    return output
end

return _M
