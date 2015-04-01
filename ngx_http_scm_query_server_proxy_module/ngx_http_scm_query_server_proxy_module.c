#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>


#define SCM_AUTH_HEADER_PREFIX "SCMA "
#define KOOABA_AUTH_HEADER_PREFIX "KA "
#define AUTH_HEADER_SEPARATOR_CHAR ':'
#define AUTH_HEADER_SEPARATOR_LEN 1

#define QUERY_LOG_FILE "logs/queries.log"
#define QUERY_LOG_SEPARATOR " - "
#define QUERY_LOG_SUFFIX "\n"


// Module callbacks
static ngx_int_t ngx_http_scm_query_server_proxy_init(ngx_conf_t *cf);
static void* ngx_http_scm_query_server_proxy_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_scm_query_server_proxy_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_scm_query_server_proxy_log_handler(ngx_http_request_t *r);


// Config file reader
static char* ngx_http_scm_query_server_proxy_add_scm_auth_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


// "Model" functions
ngx_str_t* create_request_signature(ngx_http_request_t *r, ngx_str_t *secret_token);


// Helper functions
ngx_table_elt_t* get_request_header(ngx_http_request_t *r, const char *name);
ngx_str_t* get_request_header_str(ngx_http_request_t *r, const char *name);
ngx_str_t* create_base64encoded_string(ngx_pool_t *pool, ngx_str_t *string);
ngx_log_t *ngx_log_create(ngx_cycle_t *cycle, ngx_str_t *name);


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
  ngx_log_t *query_log;
} ngx_http_scm_query_server_proxy_loc_conf_t;


// This struct stores state associated with a request
typedef struct {
  ngx_str_t *current_scm_access_key;
} scm_query_server_proxy_request_ctx_t;


// Init callback. Called when the server starts up.
//
// This function sets up the module's callbacks:
// - ngx_http_scm_query_server_proxy_access_handler is called for every request in the ACCESS phase
// - ngx_http_scm_query_server_proxy_log_handler is called for every request in the LOG phase
static ngx_int_t ngx_http_scm_query_server_proxy_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *ah, *lh;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  ah = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (ah == NULL) {
    return NGX_ERROR;
  }
  *ah = ngx_http_scm_query_server_proxy_access_handler;

  lh = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
  if (lh == NULL) {
    return NGX_ERROR;
  }
  *lh = ngx_http_scm_query_server_proxy_log_handler;

  return NGX_OK;
}


// Per-request callback. Called for every request in the ACCESS phase
static ngx_int_t ngx_http_scm_query_server_proxy_access_handler(ngx_http_request_t *r)
{
  ngx_http_scm_query_server_proxy_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_scm_query_server_proxy_module);

  // only process each request once
  if (r->main->internal) {
    return NGX_DECLINED;
  }
  r->main->internal = 1;

  // abort if there are no rewrite rules
  if (!loc_conf->rewrite_rules || loc_conf->rewrite_rules->nelts == 0) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no auth rewrite rules present");
    return NGX_DECLINED;
  }

  // read Authorization header
  ngx_table_elt_t *authorization_header = get_request_header(r, "Authorization");
  if (authorization_header) {
    ngx_str_t *auth_header_str = &authorization_header->value;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Authorization header present: %V", auth_header_str);

    // check if Authorization header matches SCMA auth scheme
    u_int is_scm_auth_header = ngx_strncmp(auth_header_str->data, SCM_AUTH_HEADER_PREFIX, ngx_strlen(SCM_AUTH_HEADER_PREFIX)) == 0;
    if (is_scm_auth_header) {

      // get access key and signature from Authorization header
      //
      // Authorization header is structured as follows:
      // SCM_AUTH_HEADER_PREFIX + access_key + AUTH_HEADER_SEPARATOR_CHAR + signature, e.g. "SCMA access_key:signature"
      ngx_str_t *scm_access_key = NULL, *scm_signature = NULL;

      u_int access_key_start_pos = ngx_strlen(SCM_AUTH_HEADER_PREFIX), access_key_len, signature_start_pos, signature_len;
      for (int i = access_key_start_pos + 1; i < auth_header_str->len - 1; i++) {
        if (auth_header_str->data[i] == AUTH_HEADER_SEPARATOR_CHAR) {
          access_key_len      = i - access_key_start_pos;
          signature_start_pos = i + 1;
          signature_len       = auth_header_str->len - signature_start_pos;

          scm_access_key = ngx_palloc(r->pool, sizeof(ngx_str_t));
          scm_access_key->len  = access_key_len;
          scm_access_key->data = &auth_header_str->data[access_key_start_pos];

          scm_signature = ngx_palloc(r->pool, sizeof(ngx_str_t));
          scm_signature->len  = signature_len;
          scm_signature->data = &auth_header_str->data[signature_start_pos];

          break;
        }
      }

      // store access key in the request context.
      // This is used for logging, see ngx_http_scm_query_server_proxy_log_handler
      if (scm_access_key) {
        scm_query_server_proxy_request_ctx_t *ctx = ngx_palloc(r->pool, sizeof(scm_query_server_proxy_request_ctx_t));
        if (!ctx) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }

        ctx->current_scm_access_key = scm_access_key;
        ngx_http_set_ctx(r, ctx, ngx_http_scm_query_server_proxy_module);
      }

      if (scm_access_key && scm_signature) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "parsed Authorization header into SCM access key: %V, SCM signature: %V", scm_access_key, scm_signature);

        // fetch rewrite rule for access key
        scm_auth_rewrite_rule_t *rewrite_rule = NULL;

        scm_auth_rewrite_rule_t *rules = loc_conf->rewrite_rules->elts;
        for (int i = 0; i < loc_conf->rewrite_rules->nelts; i++) {
          int rule_matches_scm_access_key = ngx_strncmp(rules[i].scm_access_key.data, scm_access_key->data, scm_access_key->len) == 0;
          if (rule_matches_scm_access_key) {
            rewrite_rule = &rules[i];
            break;
          }
        }

        if (rewrite_rule) {
          ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "found auth rewrite rule: %V/%V => %V/%V", &rewrite_rule->scm_access_key, &rewrite_rule->scm_secret_token, &rewrite_rule->kooaba_access_key, &rewrite_rule->kooaba_secret_token);

          // build reference SCM signature
          ngx_str_t *reference_scm_signature = create_request_signature(r, &rewrite_rule->scm_secret_token);

          if (reference_scm_signature) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "calculated reference SCM signature: %V", reference_scm_signature);

            // check if request signature matches
            int scm_signature_matches = ngx_strncmp(scm_signature->data, reference_scm_signature->data, reference_scm_signature->len) == 0;
            if (scm_signature_matches) {
              ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request signature matches reference SCM signature");

              // calculate kooaba signature
              ngx_str_t *calculated_kooaba_signature = create_request_signature(r, &rewrite_rule->kooaba_secret_token);

              if (calculated_kooaba_signature) {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "calculated kooaba signature: %V", calculated_kooaba_signature);

                // rewrite the Authorization header
                u_int kooaba_auth_header_len = ngx_strlen(KOOABA_AUTH_HEADER_PREFIX) + rewrite_rule->kooaba_access_key.len + AUTH_HEADER_SEPARATOR_LEN + calculated_kooaba_signature->len;
                u_char *kooaba_auth_header = ngx_palloc(r->pool, kooaba_auth_header_len + 1);
                if (!kooaba_auth_header) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }

                ngx_sprintf(kooaba_auth_header, "%s%V%c%V", KOOABA_AUTH_HEADER_PREFIX, &rewrite_rule->kooaba_access_key, AUTH_HEADER_SEPARATOR_CHAR, calculated_kooaba_signature);

                authorization_header->lowcase_key = (u_char *)"authorization"; // see last section on http://wiki.nginx.org/HeadersManagement
                authorization_header->value.data = kooaba_auth_header;
                authorization_header->value.len = kooaba_auth_header_len;

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rewrote the Authorization header: %s", kooaba_auth_header);
              }

            } else {
              ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request signature does not match reference SCM signature");
            }

          } else {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "cannot verify signature because of missing data");
          }

        } else {
          ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no matching rewrite rule found");
        }

      } else {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Authorization header is malformed");
      }

    } else {
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ignoring Authorization header because of unknown format");
    }

  } else {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no Authorization header found");
  }

  return NGX_DECLINED;
}


// Per-request callback. Called for every request in the LOG phase
static ngx_int_t ngx_http_scm_query_server_proxy_log_handler(ngx_http_request_t *r)
{
  ngx_http_scm_query_server_proxy_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_scm_query_server_proxy_module);

  // abort if there is no query log
  if (!loc_conf->query_log) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no query log present");
    return NGX_OK;
  }

  // fetch access key from request context
  ngx_str_t *scm_access_key = NULL;
  scm_query_server_proxy_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_scm_query_server_proxy_module);
  if (ctx) {
    scm_access_key = ctx->current_scm_access_key;
  }

  if (scm_access_key) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "access key present in request context: %V", scm_access_key);

    // build log entry
    //
    // a log line is structured as follows:
    // remote_address + QUERY_LOG_SEPARATOR + TIMESTAMP + QUERY_LOG_SEPARATOR + access_key + QUERY_LOG_SUFFIX,
    // e.g. "remote_addr - timestamp - access_key\n"
    u_int line_len = r->connection->addr_text.len      + ngx_strlen(QUERY_LOG_SEPARATOR)
                     + ngx_cached_http_log_iso8601.len + ngx_strlen(QUERY_LOG_SEPARATOR)
                     + scm_access_key->len             + ngx_strlen(QUERY_LOG_SUFFIX);
    u_char *line = ngx_palloc(r->pool, line_len + 1);
    if (!line) { return NGX_ERROR; }

    ngx_sprintf(line, "%V%s%V%s%V%s", &r->connection->addr_text, QUERY_LOG_SEPARATOR,
                                      &ngx_cached_http_log_iso8601, QUERY_LOG_SEPARATOR,
                                      scm_access_key, QUERY_LOG_SUFFIX);

    // write to log file
    u_int written = ngx_write_fd(loc_conf->query_log->file->fd, line, line_len);

    if (written == line_len) {
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "wrote %d/%d bytes to %V", written, line_len, &loc_conf->query_log->file->name);

    } else {
      ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "could not write \"%s\" (%d bytes) to %V: %d bytes written", line, line_len, &loc_conf->query_log->file->name, written);
      return NGX_ERROR;
    }

  } else {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no access key found in request context");
  }

  return NGX_OK;
}


// Creates and returns a string containing the signature of the current request using the given secret token.
ngx_str_t* create_request_signature(ngx_http_request_t *r, ngx_str_t *secret_token)
{
  ngx_str_t *request_signature = NULL;

  // build the "string-to-sign" consisting of:
  // - http verb..
  ngx_str_t *method_name_str = &r->method_name;

  // - MD5 of request body...
  ngx_str_t *content_md5_str = get_request_header_str(r, "Content-MD5");
  if (!content_md5_str) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Content-MD5 header missing");
  }

  // - content type..
  ngx_str_t *content_type_str = NULL;

  ngx_str_t full_content_type = ngx_null_string;
  if (r->headers_in.content_type) {
    full_content_type = r->headers_in.content_type->value;
  } else {
    ngx_table_elt_t *content_type_header = get_request_header(r, "Content-Type");
    if (content_type_header) { full_content_type = content_type_header->value; }
  }

  // strip away any additional info in the Content-Type header
  // e.g. "multipart/form-data; boundary=xyz" becomes "multipart/form-data"
  if (full_content_type.len > 0) {
    for (int i = 0; i < full_content_type.len; i++) {
      if(full_content_type.data[i] == ';') {
        full_content_type.len = i;
        break;
      }
    }
    if (full_content_type.len > 0) {
      content_type_str = &full_content_type;
    }
  }
  if (!content_type_str) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Content-Type header missing");
  }

  // - date...
  ngx_str_t *date_str = get_request_header_str(r, "Date");
  if (!date_str) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Date header missing");
  }

  // - request path...
  ngx_str_t *path_str = &r->uri;

  if (method_name_str && content_md5_str && content_type_str && date_str && path_str) {

    // ... joined by newlines
    u_int string_to_sign_len = method_name_str->len + 1 + content_md5_str->len + 1 + content_type_str->len + 1 + date_str->len + 1 + path_str->len;
    u_char *string_to_sign = ngx_palloc(r->pool, string_to_sign_len + 1);
    if (string_to_sign) {
      ngx_sprintf(string_to_sign, "%V\n%V\n%V\n%V\n%V", method_name_str, content_md5_str, content_type_str, date_str, path_str);
    }

    // build the signature (base64-encoded SHA1-HMAC)
    u_int macLen;
    u_char macData[20];
    HMAC(EVP_sha1(), secret_token->data, secret_token->len, string_to_sign, string_to_sign_len, macData, &macLen);

    ngx_str_t mac = {macLen, macData};
    request_signature = create_base64encoded_string(r->pool, &mac);
  }

  return request_signature;
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

  ngx_str_t query_log_name = ngx_string(QUERY_LOG_FILE);
  conf->query_log = ngx_log_create(cf->cycle, &query_log_name);
  if (conf->query_log == NULL) {
    return NGX_CONF_ERROR;
  }

  return conf;
}


// This function stores config file content in a scm_auth_rewrite_rule_t within an ngx_http_scm_query_server_proxy_loc_conf_t
static char* ngx_http_scm_query_server_proxy_add_scm_auth_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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


// Returns a request header, if present.
//
// Taken from http://wiki.nginx.org/HeadersManagement#Get_a_header_value
ngx_table_elt_t* get_request_header(ngx_http_request_t *r, const char *name)
{
  ngx_http_core_main_conf_t  *cmcf;
  ngx_http_header_t          *hh;
  u_char                     *lowcase_key;
  ngx_uint_t                  i, hash;

  u_int len = ngx_strlen(name);

  /*
  Header names are case-insensitive, so have been hashed by lowercases key
  */
  lowcase_key = ngx_palloc(r->pool, len);
  if (lowcase_key == NULL) {
    return NULL;
  }

  /*
  Calculate a hash of lowercased header name
  */
  hash = 0;
  for (i = 0; i < len; i++) {
    lowcase_key[i] = ngx_tolower(name[i]);
    hash = ngx_hash(hash, lowcase_key[i]);
  }

  /*
  The layout of hashed headers is stored in ngx_http_core_module main config.
  All the hashes, its offsets and handlers are pre-calculated
  at the configuration time in ngx_http_init_headers_in_hash() at ngx_http.c:432
  with data from ngx_http_headers_in at ngx_http_request.c:80.
  */
  cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

  /*
  Find the current header description (ngx_http_header_t) by its hash
  */
  hh = ngx_hash_find(&cmcf->headers_in_hash, hash, lowcase_key, len);

  /*
  The header value was already cached in some field
  of the r->headers_in struct (hh->offset tells in which one).
  */
  if (hh != NULL && hh->offset > 0) {
    return *((ngx_table_elt_t **) ((char *) &r->headers_in + hh->offset));
  }


  /*
  If the header is not yet hashed, then search through the complete list of headers
  */
  ngx_list_part_t            *part;
  ngx_table_elt_t            *h;

  /*
  Get the first part of the list. There is usual only one part.
  */
  part = &r->headers_in.headers.part;
  h = part->elts;

  /*
  Headers list array may consist of more than one part,
  so loop through all of it
  */
  for (i = 0; /* void */ ; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        /* The last part, search is done. */
        break;
      }

      part = part->next;
      h = part->elts;
      i = 0;
    }

    /*
    Just compare the lengths and then the names case insensitively.
    */
    if (len != h[i].key.len || ngx_strcasecmp((u_char *)name, h[i].key.data) != 0) {
      /* This header doesn't match. */
      continue;
    }

    /*
    Ta-da, we got one!
    Note, we'v stop the search at the first matched header
    while more then one header may fit.
    */
    return &h[i];
  }

  /*
  No headers was found
  */
  return NULL;
}


// Returns the value of a request header, if present.
ngx_str_t* get_request_header_str(ngx_http_request_t *r, const char *name)
{
  ngx_table_elt_t *header = get_request_header(r, name);
  if (header) {
    return &(header->value);
  } else {
    return NULL;
  }
}


// Returns a base64 encoded version of the parameter string.
ngx_str_t* create_base64encoded_string(ngx_pool_t *pool, ngx_str_t *string)
{

  ngx_str_t *base64 = ngx_palloc(pool, sizeof(ngx_str_t));

  if (base64) {
    base64->len  = ngx_base64_encoded_length(string->len);
    base64->data = ngx_palloc(pool, base64->len);

    ngx_encode_base64(base64, string);
  }

  return base64;
}


// Returns a log set up with a backing file.
//
// This function is ported over from nginx v1.4.7.
ngx_log_t *ngx_log_create(ngx_cycle_t *cycle, ngx_str_t *name)
{
  ngx_log_t  *log;

  log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t));
  if (log == NULL) {
    return NULL;
  }

  log->file = ngx_conf_open_file(cycle, name);
  if (log->file == NULL) {
    return NULL;
  }

  return log;
}
