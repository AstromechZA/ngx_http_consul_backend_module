#include <ndk.h>
// see https://github.com/simplresty/ngx_devel_kit

/*
This file contains C code that will be compiled into Nginx in order to provide the ngx_http_consol_backend_module. 
The Golang .so file is not strictly bound to this, but is loaded using dlopen/dlsym on each request.
*/

// signature defined here and then fully defined with function body at the bottom of this file.
// the signature is similar to the one that the nginx lua framework uses.
// The request type is defined in https://github.com/nginx/nginx/blob/4bf4650f2f10f7bbacfe7a33da744f18951d416d/src/http/ngx_http_request.h#L371
// 
static ngx_int_t
ngx_http_consul_backend(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v);

// see https://github.com/simplresty/ngx_devel_kit/blob/a22dade76c838e5f377d58d007f65d35b5ce1df3/src/ndk_set_var.h#L21
// type, func, size, data
static ndk_set_var_t
ngx_http_consul_backend_filter = {
  NDK_SET_VAR_VALUE,
  (void *) ngx_http_consul_backend,
  2,
  NULL
};

// 
static ngx_command_t
ngx_http_consul_backend_commands[] = {
  {
    ngx_string("consul"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ndk_set_var_value,
    0,
    0,
    &ngx_http_consul_backend_filter
  },

  ngx_null_command
};

static ngx_http_module_t
ngx_http_consul_backend_module_ctx = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

ngx_module_t ngx_http_consul_backend_module = {
  NGX_MODULE_V1,
  &ngx_http_consul_backend_module_ctx, /* module context */
  ngx_http_consul_backend_commands,    /* module directives */
  NGX_HTTP_MODULE,                     /* module type */
  NULL,                                /* init master */
  NULL,                                /* init module */
  NULL,                                /* init process */
  NULL,                                /* init thread */
  NULL,                                /* exit thread */
  NULL,                                /* exit process */
  NULL,                                /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_consul_backend(ngx_http_request_t *r, ngx_str_t *res, ngx_http_variable_value_t *v) {
  void *go_module = dlopen("ngx_http_consul_backend_module.so", RTLD_LAZY);
  if (!go_module) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "go module not found");
    return NGX_ERROR;
  }
  
  // load up the function from the so file by name
  u_char* (*fun)(u_char *) = (u_char* (*)(u_char *)) dlsym(go_module, "LookupBackend");
  // call the function and get the backend data
  u_char* backend = fun(v->data);
  
  // wrap the backend data as a structure
  ngx_str_t ngx_backend = { strlen(backend), backend };

  // bind this result struct for passing the data back to nginx
  res->data = ngx_palloc(r->pool, ngx_backend.len);
  if (res->data == NULL) {
    return NGX_ERROR;
  }
  // copy the data from the backend struct to the result struct
  ngx_memcpy(res->data, ngx_backend.data, ngx_backend.len);
 
  // update the content length
  res->len = ngx_backend.len;

  return NGX_OK;
}
