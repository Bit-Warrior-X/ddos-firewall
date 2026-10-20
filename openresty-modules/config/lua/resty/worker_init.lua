local ngx = ngx

local _M = { _VERSION = "1.0.0" }

local GEO_DB_PATH = "/usr/local/share/dorian/athens/nginx/lua/geoip2/dbip-full-2026-02.mmdb"

function _M.run()
    local ok, acl_manager = pcall(require, "resty.acl_manager")
    if not ok then
        ngx.log(ngx.ERR, "failed to require resty.acl_manager: ", tostring(acl_manager))
        return
    end

    local ok_init, err_init = acl_manager.init()
    if not ok_init then
        ngx.log(ngx.ERR, "acl_manager.init() failed: ", tostring(err_init))
    end

    local ok_timer, err_timer = ngx.timer.at(0, function(premature)
        if premature then
            return
        end
        acl_manager.start_redis_subscriber()
    end)
    if not ok_timer then
        ngx.log(ngx.ERR, "failed to start redis subscriber timer: ", tostring(err_timer))
    end

    ngx.timer.at(0.1, function(premature)
        if premature then
            return
        end
        local ok_load, err_load = acl_manager.load_all_rules()
        if not ok_load then
            ngx.log(ngx.ERR, "initial load_all_rules failed: ", tostring(err_load))
        else
            ngx.log(ngx.INFO, "initial load_all_rules success")
        end
    end)

    local ok_ur, upstream_redis = pcall(require, "resty.upstream_redis")
    if ok_ur and upstream_redis and upstream_redis.start_refresh then
        upstream_redis.start_refresh()
    end

    local ok_cm, cache_manager = pcall(require, "resty.cache_manager")
    if ok_cm and cache_manager and cache_manager.start_refresh then
        cache_manager.start_refresh()
    end

    local ok_cmp, compress_manager = pcall(require, "resty.compress_manager")
    if ok_cmp and compress_manager and compress_manager.start_refresh then
        compress_manager.start_refresh()
    end

    local ok_lp, listening_manager = pcall(require, "resty.listening_manager")
    if ok_lp and listening_manager and listening_manager.start_refresh then
        listening_manager.start_refresh()
    end

    local ok_mm, maxminddb = pcall(require, "resty.maxminddb")
    if ok_mm and maxminddb and maxminddb.init then
        if maxminddb.available and not maxminddb.available() then
            ngx.log(ngx.WARN, "libmaxminddb unavailable: ", tostring(maxminddb.load_error and maxminddb.load_error()))
        else
            local ok_geo, err_geo = maxminddb.init(GEO_DB_PATH)
            if not ok_geo then
                ngx.log(ngx.WARN, "maxminddb.init failed (temporary blacklist geo will be empty): ", tostring(err_geo))
            end
        end
    else
        ngx.log(ngx.WARN, "failed to require resty.maxminddb: ", tostring(maxminddb))
    end

    local ok_tb, temp_blacklist = pcall(require, "resty.temp_blacklist")
    if ok_tb and temp_blacklist and temp_blacklist.start then
        temp_blacklist.start()
    end

    local ok_ssl, ssl_cert = pcall(require, "resty.ssl_cert")
    if ok_ssl and ssl_cert and ssl_cert.start then
        ssl_cert.start()
    end

    local ok_cps, cache_purge_sync = pcall(require, "resty.cache_purge_sync")
    if ok_cps and cache_purge_sync and cache_purge_sync.start then
        cache_purge_sync.start()
    end

    local stats_worker = require "resty.stats_worker"
    stats_worker.start()

    local ok_al, access_logs = pcall(require, "resty.access_logs")
    if ok_al and access_logs and access_logs.start then
        access_logs.start()
    else
        ngx.log(ngx.ERR, "failed to require resty.access_logs: ", tostring(access_logs))
    end
end

return _M
