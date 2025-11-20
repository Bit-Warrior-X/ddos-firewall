# HTTP NGINX ACL Module

Handy, High performance, Easy to modify Nginx firewall module.

## Features

- Support well-structed ACL rules and parsing algorithm.
- Realtime management of ACL rules for OpenResty
- Anti SQL injection (powered by libinjection).
- Anti XSS (powered by libinjection).
- IPV4 and IPV6 support.
- Exceptional allow on specific IP address.
- Block the specified IP address.
- Exceptional allow on specific URL.
- Block the specified Geo location including Contient/Country/Province
- Block the specified URL.
- Block the specified query string.
- Block the specified UserAgent.
- Block the specified Cookie.
- Exceptional allow on specific Referer.
- Block the specified Referer.
- Block the specified Request Method.
- Block the specified Header.
- Block the IP address for frequency access.



## Installation

Install http nginx acl module to openresty 

```bash
  # cd /usr/local/src
  # git clone https://github.com/troydhanson/uthash.git
  # export LIB_UTHASH=/usr/local/src/uthash

  # cd /usr/local/src
  # git clone http://admin.skycloud.tw/skycloud-rd/libmaxminddb.git
  # cd libmaxminddb
  # ./configure --prefix=/usr/local/src/libmaxminddb --with-pic
  # make -j2 && make check -j2
  # make install
  # sudo ldconfig
  # export LIB_MAXMINDDB=/usr/local/src/libmaxminddb

  # cd /path/openresty
  # git clone http://admin.skycloud.tw/skycloud-rd/nginx_acl.git
  # cd nginx_acl
  # make
  # cd inc/
  # git clone https://github.com/libinjection/libinjection.git
  # cd ../../
```

To enable debug messages please remove below line in ***config***
```bash
have=NGX_HTTP_ACL_NO_DEBUG . auto/have
```

Configure and compile the project

```bash
  # ./configure -j2 --add-module=./nginx_acl/ --with-cc-opt='-std=gnu99'
  # make && make install
```
    
## ACL Rule Configuration

#### ACL rule template

```bash
{
  id = 1,
  rules = {
      {
          action = 1,
          priority = 10,
          rule = 
          [[
              ["Header","Content-Type","is in","aaa, bbb, ccc"] 
              OR 
              ["URI Path","-","contains","/api/config"] 
              OR 
              [
                  ["UserAgent","-","contains","Firefox/120.0"]
                  OR
                  ["Geo","-","is in","Asia, China, Guangdong"]
              ]
          ]]
      },
      -- omitted other id 1 rules
  }
}
```
| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `id`      | `integer` | Id of ACL rule |
| `rules`   | `string`  | Group of rules for ACL rule id. To remove current ACL rule, set `rules = {}` |
| `action`   | `integer` | Action for current rule. `1 : BLOCK`, `2 : ALLOW` |
| `priority` | `integer` | Priority for a rule. Higher value is higher priority. |
| `Statement` | `string` | Rules are consist of statements. They are combined by `OR` and `AND` operator.  |

To describe not command, it can be described like below:
```bash
["Geo","-","is in","Asia, China, Guangdong"]
["Geo","-","is not in","Asia, China, Guangdong"]
```

#### Statement detail

| Field | Name     | Operator                | Value |
| :-------- | :------- | :------------------------- | :------ |
| `Cookie` | `-` | `equals`, `does not equals`, `contains`, `does not contain` | `name1=value1` |
| `Geo` | `-` | `is in`, `is not in` | `Asia, China, Guangdong` |
| `IP` | `-` | `is in`, `is not in`, | `1.1.1.1, 2.2.2.2` |
| `Referer` | `-` | `equals`, `does not equals`, `contains`, `does not contain` | `www.google.com` |
| `RequestMethod` | `-` | `is in`, `is not in` | `GET, HEAD, POST, PUT, DELETE, ... ` |
| `URI Path` | `-` | `equals`, `does not equals`, `contains`, `does not contain` | `/api/config` |
| `URI Query String` | `-` | `equals`, `does not equals`, `contains`, `does not contain` | `testParam=testValue` |
| `UserAgent` | `-` | `equals`, `does not equals`, `contains`, `does not contain` | `Firefox/120.0` |
| `Header` | `Content-Type` | `is in`, `is not in`, `contains`, `does not contain` | `value1, value2, value3` |
| `Request Frequency` | `-` | `>`, `<`, `>=`, `<=` | `10times/60s` |
| `Response Frequency` | `404` | `>`, `<`, `>=`, `<=` | `10times/60s` |
| `AS Num` | `-` | `is in`, `is not in`, `>`, `<`, `>=`, `<=` | `3252` |

#### Possible operators are:
`equals`, `does not equals`, `contains`,`does not contain`,`is in`,`is not in`,`>`,`<`,`>=`,`<=` 
## Module configuration

### Configuration directives (same location syntax)
#### **acl**
- **syntax:** `acl on|off`
- **default:** `none`
- **context:** `http, server, location`

Allow checking acl rule for current server. 

#### **acl_geo_database_path** (Mantatory)
- **syntax:** `acl_geo_database_path geo_databse_path`
- **default:** `none`
- **context:** `http`

Sets geo location database path for checking geo location rule.

#### **acl_isp_database_path** (Mantatory)
- **syntax:** `acl_isp_database_path geo_databse_path`
- **default:** `none`
- **context:** `http`

Sets isp database path for checking AS number rule.

#### **acl_rule_shm_size** (Mantatory)
- **syntax:** `acl_rule_shm_size <shm_size>`
- **default:** `none`
- **context:** `http`

Sets shared memory size for the management of acl rule.

#### **acl_req_shm_size** (Mantatory)
- **syntax:** `acl_req_shm_size <shm_size>`
- **default:** `none`
- **context:** `http`

Sets shared memory size of ip address access statistic for cc attack deny.

#### **acl_rsp_shm_size** (Mantatory)
- **syntax:** `acl_rsp_shm_size <shm_size>`
- **default:** `none`
- **context:** `http`

Sets shared memory size of ip address response statistic for cc attack deny.

#### **acl_captcha** (Mantatory)
- **syntax:** `acl_captcha [sitekey=your_sitekey] [secret=your_secret] [api=uri] [expire=30m]`
- **default:** `none`
- **context:** `http`

Use CAPTCHA for human identification of the client.
- **sitekey**: The sitekey you get from the captcha platform, this parameter needs to be set if and only if the parameter file is omitted.
- **secret**: The key used to confirm the result of the CAPTCHA, you can get it from the corresponding CAPTCHA platform.
- **api**: The API provided by the CAPTCHA platform to the server to confirm the result of the CAPTCHA run. The default value is https://hcaptcha.com/siteverify.
- **expire**: The expiration time of the CAPTCHA, after which the CAPTCHA needs to be re-run. The default is 30 minutes.

### LUA API

#### **process_acl_id (acl_rule_id)**
```bash
access_by_lua_block {
    local is_handle_acl_or, handle_acl = pcall(require, 'resty.handle_acl')
    if not is_handle_acl_or then
        ngx.log(ngx.ERR, 'need to build with nginx_http_acl module')
        return 501
    end

    local ret = handle_acl.process_acl_id(1);
    if ret == 0 then
        ngx.say("Forbidden");
    elseif ret == 1 then
        ngx.say("Welcome to OpenResty ACL nginx");
    end
}
```
Process http request according to acl rules.

##### **Return Value**

-**0** : Block the request.

-**1** : Allow the request.

-**2** : Captcha is being processed for the request.

-**3** : Internal server error occured.


#### **set_acl_rule (acl_rule)**
```bash
access_by_lua_block {
    local is_handle_acl_or, handle_acl = pcall(require, 'resty.handle_acl')
    if not is_handle_acl_or then
        ngx.log(ngx.ERR, 'need to build with nginx_http_acl module')
        return 501
    end
    local cfg = {
        id = 1,
        rules = {
            {
                action = 2,
                priority = 10,
                rule = [[
                    [
                        ["Header","Content-Type","is in","aaa, bbb, ccc"]
                        OR
                        ["URI Path","-","contains","/api/config"]
                        OR
                        [
                            ["UserAgent","-","contains","Firefox/120.0"]
                            OR
                            ["Geo","-","is in","Asia, China, Guangdong"]
                        ]
                    ]
                ]]
            },
            {
                action = 1,
                priority = 15,
                rule = 
                [[
                    [
                        ["Request Frequency","-",">=","10times/60s"]
                    ]
                ]]
            }
        }
    }
    
    local ok, err = handle_acl.set_acl_rule(cfg)
    if not ok then
        ngx.log(ngx.ERR, 'failed to set acl rule : ', err)
        return 403
    end

    ngx.log(ngx.INFO, 'set acl rule success')
    ngx.say('hello workd')
}
```
Set acl rules for ACL rule id.


#### **set_str_acl_rule (acl_rule_string)**
```bash
access_by_lua_block {
    local is_handle_acl_or, handle_acl = pcall(require, 'resty.handle_acl')
    if not is_handle_acl_or then
        ngx.log(ngx.ERR, 'need to build with nginx_http_acl module')
        return 501
    end
    local cfg = [[{
        id = 1,
        rules = {
            {{
                action = 2,
                priority = 10,
                [
                    ["Header","Content-Type","is in","aaa, bbb, ccc"] 
                    OR 
                    ["URI Path","-","contains","/api/config"] 
                    OR 
                    [
                        ["UserAgent","-","contains","Firefox/120.0"]
                        OR
                        ["Geo","-","is in","Asia, China, Guangdong"]
                    ]
                ]
            }},
            {{
                action = 1,
                priority = 15,
                [
                    ["Request Frequency","-",">=","10times/60s"]
                ]
            }}
        }
    }]]
    
    local ok, err = handle_acl.set_str_acl_rule(cfg)
    if not ok then
        ngx.log(ngx.ERR, 'failed to set acl rule string: ', err)
        return 403
    end

    ngx.log(ngx.INFO, 'set acl rule string success')
    ngx.say('hello workd')
}
```
Set acl rules for ACL rule id.


## Reference URLs

[https://github.com/ADD-SP/ngx_waf](https://github.com/ADD-SP/ngx_waf.git/)

[https://owasp.org/www-project-modsecurity-core-rule-set/](https://owasp.org/www-project-modsecurity-core-rule-set/)

[https://github.com/SpiderLabs/ModSecurity](https://github.com/SpiderLabs/ModSecurity)

[https://github.com/wallarm/awesome-nginx-security](https://github.com/wallarm/awesome-nginx-security.git)

[https://github.com/SpiderLabs/ModSecurity](https://github.com/SpiderLabs/ModSecurity)

[https://github.com/libinjection/libinjection](https://github.com/libinjection/libinjection)

[https://github.com/allangood/nginx-waf](https://github.com/allangood/nginx-waf.git)

[https://github.com/nginx-with-docker/ngx-waf-module-src](https://github.com/nginx-with-docker/ngx-waf-module-src.git)

[https://github.com/gsdu8g9/waf-nginx-module](https://github.com/gsdu8g9/waf-nginx-module.git)

[https://github.com/nbs-system/naxsi](https://github.com/nbs-system/naxsi.git)



