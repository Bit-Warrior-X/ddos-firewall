# OpenResty Custom Modules

This directory contains custom Nginx/OpenResty modules used in the DDoS Firewall project.

## Modules

### 1. ngx_acl
**HTTP NGINX ACL Module** - A high-performance, easy-to-modify Nginx firewall module.

**Features:**
- Support well-structured ACL rules and parsing algorithm
- Real-time management of ACL rules for OpenResty
- Anti SQL injection (powered by libinjection)
- Anti XSS (powered by libinjection)
- IPv4 and IPv6 support
- Exceptional allow on specific IP address
- Block the specified IP address
- Exceptional allow on specific URL
- Block the specified Geo location including Continent/Country/Province
- Block the specified URL
- Block the specified query string
- Block the specified UserAgent
- Block the specified Cookie
- Exceptional allow on specific Referer
- Block the specified Referer
- Block the specified Request Method
- Block the specified Header
- Block the IP address for frequency access

**Source:** Based on OpenResty 1.25.3.1

### 2. ngx_http_report_ip
**HTTP NGINX Report IP Module** - Detects invalid HTTP request methods and reports the source IP to the eBPF firewall.

**Features:**
- Detects invalid HTTP request methods
- Reports malicious source IPs to eBPF firewall via Unix socket
- Configurable health check interval
- Configurable allowed HTTP methods
- Protects Nginx server from malicious attacks

**Configuration Directives:**
- `report_healthcheck_interval` - Time interval for health check (milliseconds)
- `report_available_methods` - Specifies allowed HTTP methods (default: GET POST)
- `report_socket_path` - Unix socket path to connect to eBPF firewall

**Source:** Based on OpenResty 1.25.3.1

### 3. ngx_lic
**NGINX License Module** - License validation module for OpenResty.

**Features:**
- License validation for OpenResty installations
- Prevents unauthorized use of the firewall system

**Source:** Based on OpenResty 1.25.3.1

## Building OpenResty with These Modules

To build OpenResty with these custom modules, you need to add them during the OpenResty configure step:

```bash
cd /path/to/openresty-1.25.3.1
./configure \
    --prefix=/usr/local/openresty \
    --add-module=../ddos-firewall/openresty-modules/ngx_acl \
    --add-module=../ddos-firewall/openresty-modules/ngx_http_report_ip \
    --add-module=../ddos-firewall/openresty-modules/ngx_lic \
    [other configure options...]

make -j2
make install
```

## Dependencies

### ngx_acl Dependencies:
- **uthash** - Hash table library
  ```bash
  git clone https://github.com/troydhanson/uthash.git
  export LIB_UTHASH=/path/to/uthash
  ```

- **libmaxminddb** - MaxMind GeoIP2 database library
  ```bash
  git clone http://admin.skycloud.tw/skycloud-rd/libmaxminddb.git
  cd libmaxminddb
  ./configure --prefix=/usr/local/libmaxminddb --with-pic
  make -j2 && make check -j2
  make install
  sudo ldconfig
  export LIB_MAXMINDDB=/usr/local/libmaxminddb
  ```

- **libinjection** - SQL injection and XSS detection library
  ```bash
  git clone https://github.com/client9/libinjection.git
  export LIB_LIBINJECTION=/path/to/libinjection
  ```

- **bison** and **flex** - Parser generators (usually available via package manager)

### ngx_http_report_ip Dependencies:
- Unix socket support (standard in Linux)
- eBPF firewall userspace daemon running

### ngx_lic Dependencies:
- Standard C library

## Integration with DDoS Firewall

These modules are integrated into the DDoS Firewall system:

1. **ngx_acl** - Provides L7 firewall rules and ACL management
2. **ngx_http_report_ip** - Reports malicious IPs detected at L7 to the L4 eBPF firewall
3. **ngx_lic** - Ensures license compliance

The modules are packaged with OpenResty in the installation package (`setup/payload/l7/openresty.tar.gz`).

## Version Information

- **OpenResty Version:** 1.25.3.1
- **Nginx Version:** 1.25.3
- **Module Compatibility:** OpenResty 1.25.3.1

## License

Please refer to the individual module directories for license information.

## References

- [OpenResty Official Site](https://openresty.org/)
- [Nginx Module Development Guide](https://www.nginx.com/resources/wiki/extending/)

