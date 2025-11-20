#ifndef _NGX_LIC_H_INCLUDED_
#define _NGX_LIC_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define LICENSE_OK          0
#define LICENSE_ERROR      -1
#define LICENSE_EXPIRED    -2

typedef struct {
    ngx_int_t license_status;
    ngx_msec_t interval;
    ngx_event_t timer_event;
} ngx_lic_main_conf_t;

/* Function declarations */
ngx_int_t get_license_status(void);

/* Module definition */
extern ngx_module_t ngx_lic_module;

#endif /* _NGX_LIC_H_INCLUDED_ */