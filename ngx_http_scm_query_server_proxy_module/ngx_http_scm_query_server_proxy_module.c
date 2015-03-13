#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>


#define SCM_AUTH_HEADER_PREFIX "SCMA "
#define KOOABA_AUTH_HEADER_PREFIX "KA "
#define AUTH_HEADER_SEPARATOR_CHAR ':'
#define AUTH_HEADER_SEPARATOR_LEN 1


// Module callbacks
static ngx_int_t ngx_http_scm_query_server_proxy_init(ngx_conf_t *cf);
static void* ngx_http_scm_query_server_proxy_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_scm_query_server_proxy_handler(ngx_http_request_t *r);


// Config file reader
static char* ngx_http_scm_query_server_proxy_add_scm_auth_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


// Helper functions
ngx_table_elt_t* get_request_header(ngx_http_request_t *r, u_char *name);
ngx_str_t* get_request_header_str(ngx_http_request_t *r, u_char *name);
u_char* encode_base64(u_char *string, u_int len);



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
  if (r->main->internal) {
    return NGX_DECLINED;
  }
  r->main->internal = 1;

  ngx_http_scm_query_server_proxy_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_scm_query_server_proxy_module);

  // read Authorization header
  ngx_str_t *auth_header_str = get_request_header_str(r, "Authorization");
  if (auth_header_str) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Authorization header present: %s", auth_header_str->data);

    // check if Authorization header matches SCMA auth scheme
    u_int is_scm_auth_header = ngx_strncmp(auth_header_str->data, SCM_AUTH_HEADER_PREFIX, strlen(SCM_AUTH_HEADER_PREFIX)) == 0;
    if (is_scm_auth_header) {

      // split Authorization header into access key and signature
      u_char *scm_access_key, *scm_signature;

      u_int key_and_signature_len = auth_header_str->len - strlen(SCM_AUTH_HEADER_PREFIX);
      u_char key_and_signature[key_and_signature_len + 1];
      key_and_signature[key_and_signature_len] = '\0';
      ngx_memcpy(key_and_signature, &(auth_header_str->data[strlen(SCM_AUTH_HEADER_PREFIX)]), key_and_signature_len);

      u_int separator_pos = 0;
      for (int i = 1; i < key_and_signature_len - 1; i++) {
        if (key_and_signature[i] == AUTH_HEADER_SEPARATOR_CHAR) {
          separator_pos = i;
        }
      }
      if (separator_pos) {
        key_and_signature[separator_pos] = '\0';
        scm_access_key = &key_and_signature[0];
        scm_signature = &key_and_signature[separator_pos + 1];
      }

      if (scm_access_key && scm_signature) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "parsed Authorization header (SCM access key: %s, SCM signature: %s)", scm_access_key, scm_signature);

        // fetch rewrite rule for access key
        if (loc_conf->rewrite_rules && loc_conf->rewrite_rules->nelts > 0) {
          scm_auth_rewrite_rule_t *rewrite_rule;

          scm_auth_rewrite_rule_t *rules = loc_conf->rewrite_rules->elts;
          for (int i = 0; i < loc_conf->rewrite_rules->nelts; i++) {
            int rule_matches_scm_access_key = strncmp(rules[i].scm_access_key.data, scm_access_key, strlen(scm_access_key)) == 0;
            if (rule_matches_scm_access_key) {
              rewrite_rule = &rules[i];
              break;
            }
          }

          if (rewrite_rule) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "found auth rewrite rule: %s/%s => %s/%s", rewrite_rule->scm_access_key.data, rewrite_rule->scm_secret_token.data, rewrite_rule->kooaba_access_key.data, rewrite_rule->kooaba_secret_token.data);

            // build the "string-to-sign"
            ngx_str_t *method_name_str = &r->method_name;

            ngx_str_t *content_md5_str = get_request_header_str(r, "Content-MD5");
            if (!content_md5_str) {
              ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Content-MD5 header missing");
            }

            ngx_str_t full_content_type = ngx_null_string;
            if (r->headers_in.content_type) {
              full_content_type = r->headers_in.content_type->value;
            } else {
              ngx_table_elt_t *content_type_header = get_request_header(r, "Content-Type");
              if (content_type_header) { full_content_type = content_type_header->value; }
            }

            ngx_str_t *content_type_str;
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
            if (!content_md5_str) {
              ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Content-Type header missing");
            }

            ngx_str_t *date_str = get_request_header_str(r, "Date");
            if (!content_md5_str) {
              ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Date header missing");
            }

            ngx_str_t *path_str = &r->uri;

            if (method_name_str && content_md5_str && content_type_str && date_str && path_str) {
              u_int string_to_sign_len = method_name_str->len + 1 + content_md5_str->len + 1 + content_type_str->len + 1 + date_str->len + 1 + path_str->len;
              u_char string_to_sign[string_to_sign_len + 1];
              u_int offset = 0;

              ngx_memcpy(string_to_sign+offset, method_name_str->data, method_name_str->len);
              offset += method_name_str->len;
              ngx_memcpy(string_to_sign+offset, "\n", 1);
              offset += 1;
              ngx_memcpy(string_to_sign+offset, content_md5_str->data, content_md5_str->len);
              offset += content_md5_str->len;
              ngx_memcpy(string_to_sign+offset, "\n", 1);
              offset += 1;
              ngx_memcpy(string_to_sign+offset, content_type_str->data, content_type_str->len);
              offset += content_type_str->len;
              ngx_memcpy(string_to_sign+offset, "\n", 1);
              offset += 1;
              ngx_memcpy(string_to_sign+offset, date_str->data, date_str->len);
              offset += date_str->len;
              ngx_memcpy(string_to_sign+offset, "\n", 1);
              offset += 1;
              ngx_memcpy(string_to_sign+offset, path_str->data, path_str->len);
              offset += path_str->len;
              ngx_memcpy(string_to_sign+offset, "\0", 1);

              // build reference signature
              size_t macLen;
              u_char mac[20];
              HMAC(EVP_sha1(), rewrite_rule->scm_secret_token.data, rewrite_rule->scm_secret_token.len, string_to_sign, string_to_sign_len, mac, &macLen);
              u_char *reference_scm_signature = encode_base64(mac, macLen);

              ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "calculated reference SCM signature: %s", reference_scm_signature);

              // check if request signature matches
              int scm_signature_matches = strcmp(scm_signature, reference_scm_signature) == 0;
              if (scm_signature_matches) {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request signature matches reference SCM signature");

                // calculate kooaba signature
                HMAC(EVP_sha1(), rewrite_rule->kooaba_secret_token.data, rewrite_rule->kooaba_secret_token.len, string_to_sign, string_to_sign_len, mac, &macLen);
                u_char *calculated_kooaba_signature = encode_base64(mac, macLen);

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "calculated kooaba signature: %s", calculated_kooaba_signature);

                // rewrite the Authorization header
                u_int kooaba_auth_header_len = strlen(KOOABA_AUTH_HEADER_PREFIX) + rewrite_rule->kooaba_access_key.len + AUTH_HEADER_SEPARATOR_LEN + strlen(calculated_kooaba_signature);
                u_char *kooaba_auth_header = malloc(kooaba_auth_header_len + 1);
                sprintf(kooaba_auth_header, "%s%s%c%s", KOOABA_AUTH_HEADER_PREFIX, rewrite_rule->kooaba_access_key.data, AUTH_HEADER_SEPARATOR_CHAR, calculated_kooaba_signature);

                ngx_table_elt_t *authorization_header = get_request_header(r, "Authorization");
                authorization_header->lowcase_key = "authorization"; // see last section on http://wiki.nginx.org/HeadersManagement
                authorization_header->value.data = kooaba_auth_header;
                authorization_header->value.len = kooaba_auth_header_len;

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rewrote the Authorization header: %s", kooaba_auth_header);

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
          ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no rewrite rules present");
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
ngx_table_elt_t* get_request_header(ngx_http_request_t *r, u_char *name)
{
  ngx_http_core_main_conf_t  *cmcf;
  ngx_http_header_t          *hh;
  u_char                     *lowcase_key;
  ngx_uint_t                  i, hash;

  size_t len = strlen(name);

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
    if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
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
ngx_str_t* get_request_header_str(ngx_http_request_t *r, u_char *name)
{
  ngx_table_elt_t *header = get_request_header(r, name);
  if (header) {
    return &(header->value);
  } else {
    return NULL;
  }
}


// Returns a base64 encoded version of the parameter string.
u_char* encode_base64(u_char *string, u_int len)
{
  BIO *b64, *bmem, *wbio;
  BUF_MEM *bptr;
  char *buf;
  unsigned int siz;

  siz = ((len + 2) / 3) * 4 + 1;
  buf = (char *)malloc(siz);
  if (buf == NULL) {
    return NULL;
  }

  b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL) {
    free(buf);
    return NULL;
  }

  bmem = BIO_new(BIO_s_mem());
  if (bmem == NULL) {
    BIO_free(b64);
    free(buf);
    return NULL;
  }

  wbio = BIO_push(b64, bmem);
  BIO_write(wbio, string, (int)len);
  (void)BIO_flush(wbio);
  BIO_get_mem_ptr(b64, &bptr);

  memcpy(buf, bptr->data, bptr->length - 1);
  buf[bptr->length - 1] = '\0';

  BIO_free(b64);
  BIO_free(bmem);

  return buf;
}
