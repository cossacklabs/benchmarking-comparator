/*
 * Copyright (c) 2015 Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "plugin.h"
#include "log.h"
#include "response.h"
#include "base64.h"

#include <themis/themis.h>

#define LOG(level, ...)                                           \
    if (pc->loglevel >= level) {                                  \
        log_error_write(srv, __FILE__, __LINE__, __VA_ARGS__);    \
    }

#define FATAL(...) LOG(0, __VA_ARGS__)
#define ERROR(...) LOG(1, __VA_ARGS__)
#define WARN(...)  LOG(2, __VA_ARGS__)
#define INFO(...)  LOG(3, __VA_ARGS__)
#define DEBUG(...) LOG(4, __VA_ARGS__)

#define HEADER(con, key)                                                \
    (data_string *)array_get_element((con)->request.headers, (key))

typedef struct {
  int loglevel;
  buffer* enable;
  buffer* username;
  buffer* password;
} plugin_config;

typedef struct {
  PLUGIN_DATA;
  plugin_config **config;
  plugin_config   conf;

  buffer* tmp_buf;
} plugin_data;

typedef struct{
  secure_comparator_t* comparator;
} handler_ctx;

static handler_ctx* handler_ctx_init(const char* data){
  handler_ctx *ctx;
  ctx=calloc(1, sizeof(*ctx));
  if(ctx){
    ctx->comparator=secure_comparator_create();
    if(!ctx->comparator){
      free(ctx);
      return NULL;
    }
    if(THEMIS_SUCCESS != secure_comparator_append_secret(ctx->comparator, data, strlen(data))){
      secure_comparator_destroy(ctx->comparator);
      free(ctx);
      return NULL;      
    }
  }
  return ctx;
}

static void handler_ctx_free(handler_ctx* ctx){
  secure_comparator_destroy(ctx->comparator);
  free(ctx);
}

static plugin_config * merge_config(server *srv, connection *con, plugin_data *pd) {
#define PATCH(x) pd->conf.x = pc->x
#define MATCH(k) if (buffer_is_equal_string(du->key, CONST_STR_LEN(k)))
#define MERGE(k, x) MATCH(k) PATCH(x)

    size_t i, j;
    plugin_config *pc = pd->config[0];

    PATCH(loglevel);
    PATCH(enable);
    PATCH(username);
    PATCH(password);

    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        if (! config_check_cond(srv, con, dc)) continue;
        pc = pd->config[i];
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];
            MERGE("themis-auth.loglevel", loglevel);
            MERGE("themis-auth.enable", enable);
            MERGE("themis-auth.username", username);
            MERGE("themis-auth.password", password);
        }
    }
    return &(pd->conf);
#undef PATCH
#undef MATCH
#undef MERGE
}

INIT_FUNC(module_init) {
    plugin_data *pd;

    pd = calloc(1, sizeof(*pd));

    pd->tmp_buf=buffer_init();
    return pd;
}

FREE_FUNC(module_free) {
    plugin_data *pd = p_d;
    UNUSED(srv);
    if (! pd) return HANDLER_GO_ON;
    free(pd);
    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(module_con_close){
    plugin_data   *pd = p_d;
    UNUSED(srv);
    if(con->plugin_ctx[pd->id]){
      handler_ctx_free(con->plugin_ctx[pd->id]);
      con->plugin_ctx[pd->id]=NULL;
    }
    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(module_con_reset){
    plugin_data   *pd = p_d;
    UNUSED(srv);
    if((con->mode != pd->id) && con->plugin_ctx[pd->id]){
      handler_ctx_free(con->plugin_ctx[pd->id]);
      con->plugin_ctx[pd->id]=NULL;
    }
    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(module_uri_handler) {
  clock_t start=clock();
    plugin_data   *pd = p_d;
    UNUSED(srv);
    plugin_config *pc = merge_config(srv, con, pd);
    if(buffer_is_empty(pc->enable) || strcmp(pc->enable->ptr, "yes")!=0){
      return HANDLER_GO_ON;
    }
    data_string *ds;
    if ((ds = HEADER(con, "Authorization")) == NULL){
      con->http_status = 401;
      con->mode = DIRECT;
      response_header_insert(srv, con, CONST_STR_LEN("WWW-Authenticate"), CONST_STR_LEN("Themis"));
      return HANDLER_FINISHED;
    }

    data_string *authorization_header;
    if (NULL == (authorization_header = (data_string *)array_get_element(con->request.headers, "Authorization"))
	|| buffer_is_empty(authorization_header->value)) {
      response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("Authorization header is empty"));
      con->http_status = 403;
      con->mode = DIRECT;
      return HANDLER_FINISHED;
    }
    char *themis_auth_data = strchr(authorization_header->value->ptr, ' ');
    if (NULL == themis_auth_data
	|| (themis_auth_data - authorization_header->value->ptr)!=6
	|| (0 != strncasecmp(authorization_header->value->ptr, "Themis", themis_auth_data - authorization_header->value->ptr))) {
      response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("Authorization header type is not Themis"));
      con->http_status = 403;
      con->mode = DIRECT;
      return HANDLER_FINISHED;
    }
    if(con->plugin_ctx[pd->id]==NULL){
      char *themis_auth_sc_data;
      
      if(NULL == (themis_auth_sc_data = strchr(themis_auth_data+1, ' '))
	 || (0 != strncasecmp(themis_auth_data+1, pc->username->ptr, themis_auth_sc_data - themis_auth_data - 1))){
	response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("Authorization header username not listed in userlist"));
	con->http_status = 403;
	con->mode = DIRECT;
	return HANDLER_FINISHED;
      }
      buffer_reset(pd->tmp_buf);
      if( NULL == buffer_append_base64_decode(pd->tmp_buf, themis_auth_sc_data+1, strlen(themis_auth_sc_data+1), BASE64_STANDARD)){
	response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("Authorization header consist not base64 encoded themis sc data"));
	con->http_status = 500;
	con->mode = DIRECT;
	return HANDLER_FINISHED;
      }
      if(NULL == (con->plugin_ctx[pd->id]=handler_ctx_init(pc->password->ptr))){
	response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("secure comparator creation failed"));
	con->http_status = 500;
	con->mode = DIRECT;
	return HANDLER_FINISHED;	
      }
      char* sc_data=NULL;
      size_t sc_data_length=0;
      secure_comparator_t* comp=((handler_ctx*)(con->plugin_ctx[pd->id]))->comparator;	
      if(THEMIS_BUFFER_TOO_SMALL != secure_comparator_proceed_compare(comp, pd->tmp_buf->ptr, pd->tmp_buf->used, NULL, &sc_data_length)){
	response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("secure comparator proceed compare (length determination) failed"));
	con->http_status = 403;
	con->mode = DIRECT;
	return HANDLER_FINISHED;	
      }
      sc_data=malloc(sc_data_length);
      if(!sc_data || (THEMIS_SCOMPARE_SEND_OUTPUT_TO_PEER != secure_comparator_proceed_compare(comp, pd->tmp_buf->ptr, pd->tmp_buf->used, sc_data, &sc_data_length))){
	response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("secure comparator proceed compare failed"));
	con->http_status = 500;
	con->mode = DIRECT;
	return HANDLER_FINISHED;		
      }
      buffer_reset(pd->tmp_buf);
      if(NULL == buffer_append_base64_encode(pd->tmp_buf, (const unsigned char*)sc_data, sc_data_length, BASE64_STANDARD)){
	response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("base64 encode failed"));
	con->http_status = 500;
	con->mode = DIRECT;
	return HANDLER_FINISHED;
      }
      free(sc_data);
      con->mode=pd->id;
      response_header_insert(srv, con, CONST_STR_LEN("Authorization"), CONST_BUF_LEN(pd->tmp_buf));
      con->http_status = 308;
      con->file_finished = 1;
      fprintf(stderr, "themis_auth: %f\n", (float)(clock()-start)/CLOCKS_PER_SEC);
      
      return HANDLER_FINISHED;
    } else {
      buffer_reset(pd->tmp_buf);
      if( NULL == buffer_append_base64_decode(pd->tmp_buf, themis_auth_data+1, strlen(themis_auth_data+1), BASE64_STANDARD)){
	response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("Authorization header consist not base64 encoded themis sc data"));
	con->http_status = 500;
	con->mode = DIRECT;
	return HANDLER_FINISHED;
      }
      char* sc_data=NULL;
      size_t sc_data_length=0;
      secure_comparator_t* comp=((handler_ctx*)(con->plugin_ctx[pd->id]))->comparator;	
      if(THEMIS_BUFFER_TOO_SMALL != secure_comparator_proceed_compare(comp, pd->tmp_buf->ptr, pd->tmp_buf->used, NULL, &sc_data_length)){
	response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("secure comparator proceed compare (length determination) failed"));
	con->http_status = 403;
	con->mode = DIRECT;
	return HANDLER_FINISHED;	
      }
      sc_data=malloc(sc_data_length);
      if(!sc_data
	 || (THEMIS_SCOMPARE_SEND_OUTPUT_TO_PEER != secure_comparator_proceed_compare(comp, pd->tmp_buf->ptr, pd->tmp_buf->used, sc_data, &sc_data_length))
	 || (THEMIS_SCOMPARE_MATCH != secure_comparator_get_result(comp))){
	con->http_status = 403;
	con->mode = DIRECT;
	return HANDLER_FINISHED;		
      }
      buffer_reset(pd->tmp_buf);
      if(NULL == buffer_append_base64_encode(pd->tmp_buf, (const unsigned char*)sc_data, sc_data_length, BASE64_STANDARD)){
	response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("base64 encode failed"));
	con->http_status = 500;
	con->mode = DIRECT;
	return HANDLER_FINISHED;
      }
      free(sc_data);
      con->mode = DIRECT;
      response_header_insert(srv, con, CONST_STR_LEN("Authorization"), CONST_BUF_LEN(pd->tmp_buf));
      fprintf(stderr, "themis_auth: %f\n", (float)(clock()-start)/CLOCKS_PER_SEC);
      return HANDLER_GO_ON;
    }
    con->http_status=500; 
    con->mode = DIRECT;
    return HANDLER_FINISHED;
}

SETDEFAULTS_FUNC(module_set_defaults) {
    plugin_data *pd = p_d;
    size_t i;

    config_values_t cv[] = {
        { "themis-auth.loglevel", NULL, T_CONFIG_INT,    T_CONFIG_SCOPE_CONNECTION },
	{ "themis-auth.enable", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
	{ "themis-auth.username", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
	{ "themis-auth.password", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
        { NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    pd->config = calloc(1, srv->config_context->used * sizeof(specific_config *));

    for (i = 0; i < srv->config_context->used; i++) {
        plugin_config *pc;

        pc = pd->config[i] = calloc(1, sizeof(plugin_config));
        pc->loglevel = 1;
	pc->enable = buffer_init();
	pc->username = buffer_init();
	pc->password = buffer_init();

        cv[0].destination = &(pc->loglevel);
	cv[1].destination = pc->enable;
        cv[2].destination = pc->username;
	cv[3].destination = pc->password;
        array *ca = ((data_config *)srv->config_context->data[i])->value;
        if (config_insert_values_global(srv, ca, cv, T_CONFIG_SCOPE_CONNECTION) != 0) {
            return HANDLER_ERROR;
        }
    }
    return HANDLER_GO_ON;
}

int
mod_themis_auth_plugin_init(plugin *p) {
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("themis-auth");
    p->init             = module_init;
    p->set_defaults     = module_set_defaults;
    p->cleanup          = module_free;
    p->handle_uri_clean = module_uri_handler;
    p->handle_connection_close = module_con_close;
    p->connection_reset = module_con_reset;
    p->data             = NULL;

    return 0;
}
