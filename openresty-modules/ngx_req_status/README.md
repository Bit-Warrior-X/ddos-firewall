Name
====

ngx_req_status - Request status in nginx

Synopsis
========

    http {
        req_status_zone server_name $server_name 256k;
        req_status_zone server_addr $server_addr 256k;

        req_status server_name server_addr;

        server {
            location /req-status {
                req_status_show on;

                allow 10.0.0.0/8;
                allow 127.0.0.1;
                deny all;
            }
        }
    }

Directives
==========
req_status_enable 
-----------------
**syntax:** *req_status_enable on|off*

**default:** *off*

**context:** *http*

Enables or disable req_status module.

req_status_zone
---------------
**syntax:** *req_status_zone name string size*

**default:** *None*

**context:** *http*

Define a request status zone.
Requests are grouped by the value of string specified in the second paramter.

    req_status_zone server_addr "$server_addr:$server_port" 256k;

req_status
----------
**syntax:** *req_status zone1[ zone2]*

**default:** *None*

**context:** *http, server, location*

Enables request status in this location.
You can specify as many zones as needed.

req_status_show
---------------
**syntax:** *req_status_show on*

**default:** *None*

**context:** *location*

Enables the request status handler in this location.
This directive can be used when *req_status_enable on*.
For example:

    location /req-status {
        req_status_show on;

        allow 10.0.0.0/8;
        allow 127.0.0.1;
        deny all;
    }
   
Then you can see the page by 
    
    curl http://127.0.0.1/req-status

It returns json format information like
   ```
{
    "timestamp": 1697769767,
    "data": [
        {
        "domain": "127.0.0.1",
        "zone_name": "server_addr",
        "bandwidth": "4096",
        "active": 1
        },
        {
        "domain": "localhost",
        "zone_name": "server_name",
        "bandwidth": "4096",
        "active": 1
        },
        {
        "domain": "d.123.sogou.com",
        "zone_name": "server_name",
        "bandwidth": "12943",
        "active": 1
        }
      ]
    }
```

Add filters
===========

**Available filters for conditions**

> [domain=name]

    Filter domains with given name. Name is string.

> [zone_name=zone name]

    Filter zone name with give zone name. Zone name is string.

> [bandwidth=true/false]

    Filter with bandwidth. If bandwidth is true, then returns only non-zero bandwidth values.

> [active=true/false]

    Filter with active status. Active shows current domain's status. If active is ture, then returns only active statistics.

**Example usages for filters**

    curl -v "http://127.0.0.1:80/req-status?active=true&domain=127.0.0.1"

This command returns only active is true and domain name is 127.0.0.1.

Installation
============

    wget "https://openresty.org/download/openresty-1.21.4.2.tar.gz"
    tar -xzvf openresty-1.21.4.2.tar.gz
    cd openresty-1.21.4.2/bundle/nginx-1.21.4

    patch -p1 < /path/to/ngx_req_status/write_filter-openresty-1.21.4.2.patch

    ./configure -j2  --add-module=/path/to/ngx_req_status

    make
    make install

