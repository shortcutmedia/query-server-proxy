#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// Module callbacks
static ngx_int_t ngx_http_scm_query_server_proxy_init(ngx_conf_t *cf);
static void* ngx_http_scm_query_server_proxy_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_scm_query_server_proxy_handler(ngx_http_request_t *r);


// Config file reader
static char* ngx_http_scm_query_server_proxy_add_scm_auth_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


// Helper functions
// ...


// Config file directives provided by this module
static ngx_command_t ngx_http_scm_query_server_proxy_commands[] = {
  {
    // Usage: scm_auth_rewrite SCM_ACCESS_KEY SCM_SECRET_TOKEN KOOABA_ACCESS_KEY KOOABA_SECRET_TOKEN
    ngx_string("scm_auth_rewrite"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE4,
    ngx_http_scm_query_server_proxy_add_scm_auth_rewrite,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  ngx_null_command
};


// Module context
static ngx_http_module_t ngx_http_scm_query_server_proxy_module_ctx = {
  NULL,                                            /* preconfiguration */
  ngx_http_scm_query_server_proxy_init,            /* postconfiguration */
  NULL,                                            /* create main configuration */
  NULL,                                            /* init main configuration */
  NULL,                                            /* create server configuration */
  NULL,                                            /* merge server configuration */
  ngx_http_scm_query_server_proxy_create_loc_conf, /* create location configuration */
  NULL                                             /* merge location configuration */
};

// Module definition
ngx_module_t ngx_http_scm_query_server_proxy_module = {
  NGX_MODULE_V1,
  &ngx_http_scm_query_server_proxy_module_ctx, /* module context */
  ngx_http_scm_query_server_proxy_commands,    /* module directives */
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


// This struct stores an authorization rewrite configuration, i.e. a
// mapping of shortcut key/secret to a kooaba key/secret.
typedef struct {
  ngx_str_t scm_access_key;
  ngx_str_t scm_secret_token;
  ngx_str_t kooaba_access_key;
  ngx_str_t kooaba_secret_token;
} scm_auth_rewrite_rule_t;


// This struct stores the module's config for a location
typedef struct {
  ngx_array_t *rewrite_rules; // of type scm_auth_rewrite_rule_t
} ngx_http_scm_query_server_proxy_loc_conf_t;


// Init callback. Called when the server starts up.
//
// This function sets up the module's callbacks:
// - ngx_http_scm_query_server_proxy_handler is called for every request in the ACCESS phase
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


// Per-request callback. Called for every request in the ACCESS phase
static ngx_int_t ngx_http_scm_query_server_proxy_handler(ngx_http_request_t *r)
{
  ngx_http_scm_query_server_proxy_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_scm_query_server_proxy_module);
  if (loc_conf->rewrite_rules && loc_conf->rewrite_rules->nelts > 0) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Auth rewrite rules present:");
    scm_auth_rewrite_rule_t *rules = loc_conf->rewrite_rules->elts;
    for (size_t i = 0; i < loc_conf->rewrite_rules->nelts; i++) {
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s/%s => %s/%s", rules[i].scm_access_key.data, rules[i].scm_secret_token.data, rules[i].kooaba_access_key.data, rules[i].kooaba_secret_token.data);
    }
  } else {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "No auth rewrite rules found");
  }


  return NGX_DECLINED;
}


// Location creation callback. Called when a location is read from the config file.
//
// This function initializes a ngx_http_scm_query_server_proxy_loc_conf_t for a location
static void* ngx_http_scm_query_server_proxy_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_scm_query_server_proxy_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_scm_query_server_proxy_loc_conf_t));
  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }

  return conf;
}


// This function stores config file content in a scm_auth_rewrite_rule_t within an ngx_http_scm_query_server_proxy_loc_conf_t
static char *ngx_http_scm_query_server_proxy_add_scm_auth_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_scm_query_server_proxy_loc_conf_t *loc_conf = conf;

  if (loc_conf->rewrite_rules == NULL) {
    loc_conf->rewrite_rules = ngx_array_create(cf->pool, 4, sizeof(scm_auth_rewrite_rule_t));
    if (loc_conf->rewrite_rules == NULL) {
      return NGX_CONF_ERROR;
    }
  }

  scm_auth_rewrite_rule_t *rule = ngx_array_push(loc_conf->rewrite_rules);
  if (rule == NULL) {
    return NGX_CONF_ERROR;
  }

  ngx_str_t *value;
  value = cf->args->elts;

  rule->scm_access_key      = value[1];
  rule->scm_secret_token    = value[2];
  rule->kooaba_access_key   = value[3];
  rule->kooaba_secret_token = value[4];

  return NGX_CONF_OK;
}
