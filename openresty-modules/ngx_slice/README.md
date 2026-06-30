# NGINX_HTTP_SLICE_MODULE

The ngx_http_slice_module module is a filter that splits a request into subrequests, each returning a certain range of response. The filter provides more effective caching of big responses.
This module is not built by default, it should be enabled with the --with-http_slice_module configuration parameter.






## Installation
Apply git patch file.
```bash
cd /var/local/ddos-firewall/openresty-modules/openresty-1.27.1.2/bundle/nginx-1.27.1
patch -p1 < /var/local/ddos-firewall/openresty-modules/ngx_slice/ngx_http_slice_filter_module.patch
#git apply ngx_http_slice_filter_module.patch
```

Download source code into openresty directory
```bash
cd /path/openresty
git clone http://admin.skycloud.tw/skycloud-rd/nginx-slice-module.git
cd nginx-slice-module
```
Configure openresty with original http slice module and current project
```bash
 ./configure --add-module=./nginx-slice-module/ --with-http_slice_module
 make && make install
 ```
 Install Lua script
 ```bash
 cp ./nginx-slice-module/lua/handle_slice.lua /installed/openresty/nginx/lua/resty/
 ```





## Example configuration

```bash
location / {
    access_by_lua_block {
        -- omit block
    }
    slice             on;
    proxy_cache       cache;
    proxy_cache_key   $uri$is_args$args$slice_range;
    proxy_set_header  Range $slice_range;
    proxy_cache_valid 200 206 1h;
    proxy_pass        http://localhost:8000;
}
```
In this example, the response is split into 1000 bytes cacheable slices.



## LUA API Function

- **set_slice (slice_size)**
```bash
access_by_lua_block {
    local is_handle_slice_or, handle_slice = pcall(require, 'resty.handle_slice')
    if not is_handle_slice_or then
        ngx.log(ngx.ERR, 'need to build with nginx_http_slice module')
        return 501
    end

    local ok, err = handle_slice.set_slice(1000);
    if not ok then 
        ngx.log(ngx.ERR, 'failed to set slice size : ', err)
        return 403
    end
    
    ngx.log(ngx.INFO, 'set slice size success')
}
```
This function allows to set slice size.

## Directives

### **slice**
- **syntax:** `slice on|off`
- **default:** `none`
- **context:** `location`

Set slice status to let on and off. Default is off and if this directive is not specified, you can't use lua API to set slice size.

## Embedded Variables

The ngx_http_slice_module module supports the following embedded variables:

$slice_range
the current slice range in HTTP byte range format, for example, bytes=0-1048575.


## Reference

 - [Nginx http slice filter module](https://nginx.org/en/docs/http/ngx_http_slice_module.html)
 - [Alibaba nginx http slice module](https://github.com/alibaba/nginx-http-slice)
 - [HTTP 206 code explain](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/206)
 

