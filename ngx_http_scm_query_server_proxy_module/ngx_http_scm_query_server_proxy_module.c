#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t ngx_http_scm_query_server_proxy_module;

static ngx_int_t ngx_http_scm_query_server_proxy_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_scm_query_server_proxy_handler(ngx_http_request_t *r);

static ngx_http_module_t ngx_http_scm_query_server_proxy_module_ctx = {
  NULL,                                 /* preconfiguration */
  ngx_http_scm_query_server_proxy_init, /* postconfiguration */
  NULL,                                 /* create main configuration */
  NULL,                                 /* init main configuration */
  NULL,                                 /* create server configuration */
  NULL,                                 /* merge server configuration */
  NULL,                                 /* create location configuration */
  NULL                                  /* merge location configuration */
};

ngx_module_t ngx_http_scm_query_server_proxy_module = {
  NGX_MODULE_V1,
  &ngx_http_scm_query_server_proxy_module_ctx, /* module context */
  NULL,                                        /* module directives */
  NGX_HTTP_MODULE,                             /* module type */
  NULL,                                        /* init master */
  NULL,                                        /* init module */
  NULL,                                        /* init process */
  NULL,                                        /* init thread */
  NULL,                                        /* exit thread */
  NULL,                                        /* exit process */
  NULL,                                        /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_scm_query_server_proxy_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_scm_query_server_proxy_handler;

  return NGX_OK;
}

static ngx_int_t ngx_http_scm_query_server_proxy_handler(ngx_http_request_t *r)
{

}


