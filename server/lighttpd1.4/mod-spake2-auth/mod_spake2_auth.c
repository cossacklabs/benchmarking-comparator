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
#include <time.h>

#include "plugin.h"
#include "log.h"
#include "response.h"
#include "base64.h"

#include "curve25519.h"

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
            MERGE("spake2-auth.loglevel", loglevel);
            MERGE("spake2-auth.enable", enable);
            MERGE("spake2-auth.username", username);
            MERGE("spake2-auth.password", password);
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

URIHANDLER_FUNC(module_uri_handler) {
  clock_t start = clock();
    plugin_data   *pd = p_d;
    UNUSED(srv);
    plugin_config *pc = merge_config(srv, con, pd);
    if(buffer_is_empty(pc->enable) || strcmp(pc->enable->ptr, "yes")!=0){
      return HANDLER_GO_ON;
    }
    //    fprintf(stderr, "enable:%s username:%s pass:%s\n", pc->enable->ptr, pc->username->ptr, pc->password->ptr);
    data_string *ds;
    if ((ds = HEADER(con, "Authorization")) == NULL){
      con->http_status = 401;
      con->mode = DIRECT;
      response_header_insert(srv, con, CONST_STR_LEN("WWW-Authenticate"), CONST_STR_LEN("Spake2"));
      response_header_insert(srv, con, CONST_STR_LEN("WWW-Authenticate-Spake2-Name"), CONST_STR_LEN("Spake2-server"));
      fprintf(stderr, "spake2_auth: %f\n", (float)(clock()-start)/CLOCKS_PER_SEC);
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
	|| (0 != strncasecmp(authorization_header->value->ptr, "Spake2", themis_auth_data - authorization_header->value->ptr))) {
      response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("Authorization header type is not Themis"));
      con->http_status = 403;
      con->mode = DIRECT;
      return HANDLER_FINISHED;
    }
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
    SPAKE2_CTX* spake=SPAKE2_CTX_new(spake2_role_bob, (const unsigned char*)("Spake2-server"), 13, (const unsigned char*)(themis_auth_data+1), themis_auth_sc_data - themis_auth_data - 1);
    if(!spake){
      response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("spake context creation failed"));
      con->http_status = 500;
      con->mode = DIRECT;
      return HANDLER_FINISHED;	
    }
    
    char data[SPAKE2_MAX_MSG_SIZE+1];
    data[0]='B';
    size_t data_length=0;
    if(!SPAKE2_generate_msg(spake, (uint8_t*)data+1, &data_length, SPAKE2_MAX_MSG_SIZE+1, (const uint8_t*)(pc->password->ptr), pc->password->used)){
      response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("spake message creation failed"));
      con->http_status = 500;
      con->mode = DIRECT;
      return HANDLER_FINISHED;	
    }
    char key[64];
    size_t key_length=0;
    if(!SPAKE2_process_msg(spake, (uint8_t*)key, &key_length, 64, (const uint8_t*)(pd->tmp_buf->ptr+1), pd->tmp_buf->used-2)){
      response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("spake message process failed"));
      con->http_status = 500;
      con->mode = DIRECT;
      return HANDLER_FINISHED;	
    }

    buffer_reset(pd->tmp_buf);
    if(NULL == buffer_append_base64_encode(pd->tmp_buf, (const unsigned char*)data, data_length+1, BASE64_STANDARD)){
      response_header_insert(srv, con, CONST_STR_LEN("Error"), CONST_STR_LEN("base64 encode failed"));
      con->http_status = 500;
      con->mode = DIRECT;
      return HANDLER_FINISHED;
    }
    //fprintf(stderr, "%u\n",key_length);

    SPAKE2_CTX_free(spake);
    response_header_insert(srv, con, CONST_STR_LEN("Authorization"), CONST_BUF_LEN(pd->tmp_buf));
    con->mode = DIRECT;

    fprintf(stderr, "spake2_auth: %f\n", (float)(clock()-start)/CLOCKS_PER_SEC);
    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(module_con_close){
    plugin_data   *pd = p_d;
    UNUSED(srv);
    fprintf(stderr, "in: %u\n", con->bytes_read);
    fprintf(stderr, "out: %u\n", con->bytes_written);
    con->bytes_read=0;
    con->bytes_written=0;
    return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(module_set_defaults) {
    plugin_data *pd = p_d;
    size_t i;

    config_values_t cv[] = {
        { "spake2-auth.loglevel", NULL, T_CONFIG_INT,    T_CONFIG_SCOPE_CONNECTION },
	{ "spake2-auth.enable", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
	{ "spake2-auth.username", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
	{ "spake2-auth.password", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
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
mod_spake2_auth_plugin_init(plugin *p) {
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("spake2-auth");
    p->init             = module_init;
    p->set_defaults     = module_set_defaults;
    p->cleanup          = module_free;
    p->handle_uri_clean = module_uri_handler;
    p->connection_reset = module_con_close;
    p->data             = NULL;

    return 0;
}
