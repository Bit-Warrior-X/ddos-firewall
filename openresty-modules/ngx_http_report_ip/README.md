# HTTP NGINX report block ip to ebpf-firewall

Detect invalid http request method and report the source ip to the ebpf-firewall, so that protect nginx server from malicious attack.

## Installation
```bash
  # cd /path/nginx
  # ./configure -j2 --add-module=./nginx_http_report_ip/
  # make && make install
```

## Configuration directives

#### **report_healthcheck_interval**
- **syntax:** `report_healthcheck_interval 100`
- **default:** `none`
- **context:** `http`

Set the time interval for health check (unit is miliseconds)

#### **report_available_methods**
- **syntax:** `report_available_methods GET POST`
- **default:** `GET POST`
- **context:** `http, location`

Specifies the http code to be passed.

#### **report_socket_path**
- **syntax:** `report_socket_path /tmp/unix.sock`
- **default:** `nonoe`
- **context:** `http, location`

Set the unix socket path that can be connected from this module to ebpf-firewall.

##### Example:
```bash
http {
    report_module_check on;
    report_healthcheck_interval 100; #miliseconds
    report_available_methods GET POST;
    report_socket_path /tmp/unix.sock;
    
    server {
        listen  8080;

        location / {
	    
        }
    }
}
```

 