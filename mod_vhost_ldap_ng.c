/* ============================================================
 * Copyright (c) 2010-2011, Simone Caruso <info@simonecaruso.com>
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

#define CORE_PRIVATE

#ifdef APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_version.h"
#include "apr_reslist.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "util_ldap.h"

#include "mod_vhost_ldap_ng.h"
#include "ctype.h"
#if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
#define HAVE_UNIX_SUEXEC
#endif

#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"              /* Contains the suexec_identity hook used on Unix */
#include "pwd.h"
#include "grp.h"
#endif

module AP_MODULE_DECLARE_DATA vhost_ldap_ng_module;
static apr_shm_t *shm_addr = NULL;
static apr_rmm_t *rmm_addr = NULL;
static apr_global_mutex_t *mtx = NULL;
static int total_modules;
#if APR_HAS_THREADS
static apr_thread_mutex_t *tmtx = NULL;
#endif
//From mod_alias
static int alias_matches(const char *uri, const char *alias_fakename)
{
	const char *aliasp = alias_fakename, *urip = uri;
	while (*aliasp)
		if (*aliasp == '/'){
            if(*urip != '/')
				return 0;
			do{
				++aliasp;
			}while(*aliasp == '/');
			do{
				++urip;
			}while(*urip == '/');
		}else
			if(*urip++ != *aliasp++)
				return 0;
	if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
		return 0;
	return urip - uri;
}

static apr_status_t cleanup(void *var)
{
	if (rmm_addr){
		apr_rmm_destroy(rmm_addr);
		rmm_addr = NULL;
    }
	if (shm_addr){
		apr_shm_destroy(shm_addr);
		shm_addr = NULL;
	}
	if (mtx){
		apr_global_mutex_destroy(mtx);
		mtx = NULL;
	}
#if APR_HAS_THREADS
	if(tmtx)
		apr_thread_mutex_destroy(tmtx);
#endif
	return APR_SUCCESS;
}

static int
mod_vhost_ldap_post_config(
	apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	module **m;
	apr_size_t tsize;
	apr_status_t result;
	apr_rmm_off_t offset;
	char message[60], *lock;
	void *data = NULL;
	cache_t *tmp;
	mod_vhost_ldap_config_t *conf = NULL;
	server_rec *cur_vhost;
	//mod_vhost_ldap_request_t *reqc;

	for (m = ap_preloaded_modules, total_modules = 0; *m != NULL; m++)
		total_modules++;

	apr_pool_userdata_get(&data, "shm_counter_ldap_post_config", s->process->pool);
	if(data == NULL){
		apr_pool_userdata_set((const void *)1, "shm_counter_ldap_post_config",
			apr_pool_cleanup_null, s->process->pool);
		return OK;
	}
	
	cur_vhost = s;
	
	ap_add_version_component(p, MOD_VHOST_LDAP_VERSION);
	
	conf = (mod_vhost_ldap_config_t *)ap_get_module_config(
		cur_vhost->module_config, &vhost_ldap_ng_module);
	lock = ap_server_root_relative(p, "mod_vhost_ldap_ng.lck");
	result = apr_global_mutex_create(&mtx, lock, APR_LOCK_DEFAULT, p);
	if(result != APR_SUCCESS)
		ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, s,
			"[mod_vhost_ldap_ng.c] mutex_create: `%s'",
			apr_strerror(result, message, sizeof(message)));
#ifdef AP_NEED_SET_MUTEX_PERMS
	result = unixd_set_global_mutex_perms(mtx);
	if(result != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, result, s,
		"[mod_vhost_ldap_ng.c] Could not set permissions on global parent mutex %s",
		lock);
		return result;
	}
#endif
	
	if(!shm_addr){
		result = apr_shm_create(&shm_addr, conf->cache_size, NULL, p);
		if (result != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, s,
			"[mod_vhost_ldap_ng.c] apr_shm_create(): `%s'",
			apr_strerror(result, message, sizeof(message)));
			return result;
		}
	}

	tsize = apr_shm_size_get(shm_addr);
	if(!rmm_addr){
		result = apr_rmm_init(&rmm_addr, NULL,  apr_shm_baseaddr_get(shm_addr), tsize, p);
		if(result != APR_SUCCESS)
			return result;
	}

	offset = apr_rmm_calloc(rmm_addr, sizeof(cache_t));
	if(!offset){
		 ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, s,
            "[mod_vhost_ldap_ng.c] apr_shm_create(): `Can not alloc segment'");
		return APR_EGENERAL;
	}

	tmp = apr_rmm_addr_get(rmm_addr, offset);
	tmp->node = NULL;
	tmp->numentries = 1;
	tmp->used += sizeof(cache_t);
	tmp->size = tsize;
	while(cur_vhost){
		conf = (mod_vhost_ldap_config_t *)ap_get_module_config(
        	cur_vhost->module_config, &vhost_ldap_ng_module);
		conf->cache = tmp;
/*		conf->cache->node = NULL;
		conf->cache->numentries = 1;
		conf->cache->used += sizeof(cache_t)+apr_rmm_overhead_get(conf->cache->numentries);
		conf->cache->size = tsize;*/
		cur_vhost = cur_vhost->next;
	}
	apr_pool_cleanup_register(p, NULL, cleanup, apr_pool_cleanup_null);
	return OK;
}

static void mod_vhost_ldap_child_init(apr_pool_t * p, server_rec * s)
{
	char *lock = ap_server_root_relative(p, "mod_vhost_ldap_ng.lck");
	apr_status_t ret;
	ret = apr_rmm_attach(&rmm_addr, NULL, apr_shm_baseaddr_get(shm_addr), p);
	ret = apr_global_mutex_child_init(&mtx, lock, p);
#if APR_HAS_THREADS
	apr_thread_mutex_create(&tmtx, APR_THREAD_MUTEX_DEFAULT, p);
#endif
}

static void *
mod_vhost_ldap_create_server_config(apr_pool_t *p, server_rec *s)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)apr_pcalloc(p, sizeof (mod_vhost_ldap_config_t));
	conf->url = NULL;
	conf->enabled = MVL_UNSET;
	conf->binddn = NULL;
	conf->bindpw = NULL;
	conf->fallback_name = NULL;
	conf->fallback_docroot = NULL;
	conf->rootdir = NULL;
	conf->php_includepath = ".:/usr/share/php";
	conf->cache_size = SHM_CACHE_SIZE;
	return conf;
}

static void *
mod_vhost_ldap_merge_server_config(apr_pool_t *p, void *parentv, void *childv)
{
	mod_vhost_ldap_config_t *parent = (mod_vhost_ldap_config_t *)parentv;
	mod_vhost_ldap_config_t *child  = (mod_vhost_ldap_config_t *)childv;
	mod_vhost_ldap_config_t *conf =
		apr_pcalloc(p, sizeof(mod_vhost_ldap_config_t));

	if(child->enabled == MVL_UNSET){
		conf->enabled = parent->enabled;
	}else{
		conf->enabled = child->enabled;
	}

	//conf->cache = parent->cache;
	conf->url = parent->url;
	conf->basedn = parent->basedn;
	conf->scope = parent->scope;
	conf->filter = parent->filter;
	conf->binddn = parent->binddn;
	conf->bindpw = parent->bindpw;
	conf->fallback_name = parent->fallback_name;
	conf->fallback_docroot = parent->fallback_docroot;
	conf->rootdir = parent->rootdir;
	conf->php_includepath = parent->php_includepath;
	conf->cache_size = parent->cache_size;
	return conf;
}

/*
static void*
mod_vhost_ldap_merge_dir_config(apr_pool_t *p, void *pv, void *cv)
{
	mod_vhost_ldap_config_t *parent = (mod_vhost_ldap_config_t *)pv;
	//mod_vhost_ldap_config_t *child  = (mod_vhost_ldap_config_t *)cv;
	mod_vhost_ldap_config_t *conf =
		apr_pcalloc(p, sizeof(mod_vhost_ldap_config_t));

	memcpy(conf, parent, sizeof(mod_vhost_ldap_config_t));
	return conf;
}
*/

static const char
*mod_vhost_ldap_set_basedn(cmd_parms *cmd, void *dummy,const char *param)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)ap_get_module_config(
			cmd->server->module_config, &vhost_ldap_ng_module);
	conf->basedn = apr_pstrdup(cmd->pool, param);
	return NULL;
}

static const char
*mod_vhost_ldap_set_searchscope(cmd_parms *cmd, void *dummy, const char *param)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)ap_get_module_config(
			cmd->server->module_config, &vhost_ldap_ng_module);
	if(strcmp(param, "one") == 0)
		conf->scope = LDAP_SCOPE_ONELEVEL;
	else if(strcmp(param, "sub") == 0)
		conf->scope = LDAP_SCOPE_SUBTREE;
	else if(strcmp(param, "children") == 0)	
		conf->scope = LDAP_SCOPE_CHILDREN;
	else
		conf->scope = LDAP_SCOPE_SUBTREE;
	return NULL;
}

static const char
*mod_vhost_ldap_set_filter(cmd_parms *cmd, void *dummy, const char *param)
{
	mod_vhost_ldap_config_t *conf =
		ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	conf->filter = apr_pstrdup(cmd->pool, param);
	return NULL;
}

static const char
*mod_vhost_ldap_parse_url(cmd_parms *cmd, void *dummy, const char *url)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)ap_get_module_config(
			cmd->server->module_config, &vhost_ldap_ng_module);
	conf->url = apr_pstrdup(cmd->pool, url);
	return NULL;
}

static const char
*mod_vhost_ldap_set_enabled(cmd_parms *cmd, void *dummy, int enabled)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(
		cmd->server->module_config,	&vhost_ldap_ng_module);
	conf->enabled = (enabled) ? MVL_ENABLED : MVL_DISABLED;
	return NULL;
}

static const char
*mod_vhost_ldap_set_rootdir(cmd_parms *cmd, void *dummy, const char *rootdir)
{
    int len = 0;
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)ap_get_module_config(
			cmd->server->module_config, &vhost_ldap_ng_module);
	len = strlen(rootdir);
	if(strcmp(rootdir+len-1, "/") != 0)
		rootdir = apr_pstrcat(cmd->pool, rootdir, "/", NULL);
	conf->rootdir = apr_pstrdup(cmd->pool, rootdir);
	return NULL;
}

static const char
*mod_vhost_ldap_set_binddn(cmd_parms *cmd, void *dummy, const char *binddn)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(
		cmd->server->module_config, &vhost_ldap_ng_module);
	conf->binddn = apr_pstrdup(cmd->pool, binddn);
	return NULL;
}

static const char
*mod_vhost_ldap_set_bindpw(cmd_parms *cmd, void *dummy, const char *bindpw)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(
		cmd->server->module_config,	&vhost_ldap_ng_module);
	conf->bindpw = apr_pstrdup(cmd->pool, bindpw);
	return NULL;
}

static const char
*mod_vhost_ldap_set_fallback_name(cmd_parms *cmd, void *dummy, const char *fallback)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(
		cmd->server->module_config, &vhost_ldap_ng_module);
	conf->fallback_name = apr_pstrdup(cmd->pool, fallback);
	return NULL;
}

static const char
*mod_vhost_ldap_set_fallback_docroot(cmd_parms *cmd, void *dummy, const char *fallback)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(
		cmd->server->module_config, &vhost_ldap_ng_module);
	conf->fallback_docroot = apr_pstrdup(cmd->pool, fallback);
	return NULL;
}

static const char
*mod_vhost_ldap_set_phpincludepath(cmd_parms *cmd, void *dummy, const char *path)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(
		cmd->server->module_config, &vhost_ldap_ng_module);
	conf->php_includepath = apr_pstrdup(cmd->pool, path);
	return NULL;
}

static const char
*mod_vhost_ldap_set_cache_size(cmd_parms *cmd, void *dummy, const char *size)
{
	mod_vhost_ldap_config_t *conf =
    (mod_vhost_ldap_config_t *)ap_get_module_config(
        cmd->server->module_config, &vhost_ldap_ng_module);
	conf->cache_size = atoi(size);
	if(!conf->cache_size)
		return "Invalid cache size in configuration";
	return NULL;
}

command_rec mod_vhost_ldap_cmds[] = {
	AP_INIT_TAKE1("VhostLDAPURL", mod_vhost_ldap_parse_url, NULL, RSRC_CONF,
					"URL to define LDAP connection.\n"),
	AP_INIT_TAKE1("VhostLDAPBaseDN", mod_vhost_ldap_set_basedn, NULL,
					RSRC_CONF, "LDAP Hostname."),
	AP_INIT_TAKE1("VhostLDAPSearchScope", mod_vhost_ldap_set_searchscope, NULL,
					RSRC_CONF, "LDAP Hostname."),
	AP_INIT_TAKE1("VhostLDAPFilter", mod_vhost_ldap_set_filter, NULL, RSRC_CONF,
					"LDAP Hostname."),
	AP_INIT_TAKE1("VhostLDAPBindDN", mod_vhost_ldap_set_binddn, NULL, RSRC_CONF,
					"DN to use to bind to LDAP server. Leave empty for anonymous bind."),
	AP_INIT_TAKE1("VhostLDAPBindPassword", mod_vhost_ldap_set_bindpw, NULL, RSRC_CONF,
					"Password to use to bind to LDAP server. Leave empty for anonymous bind."),
	AP_INIT_FLAG("VhostLDAPEnabled", mod_vhost_ldap_set_enabled, NULL, RSRC_CONF,
					"Set to off to disable vhost_ldap, even if it's been enabled in a higher tree"),
	AP_INIT_TAKE1("VhostLDAPFallbackName", mod_vhost_ldap_set_fallback_name, NULL, RSRC_CONF,
					"Set default virtual host which will be used when requested hostname"
					"is not found in LDAP database. This option can be used to display"
					"\"virtual host not found\" type of page."),
	AP_INIT_TAKE1("VhostLDAPFallbackDocumentRoot", mod_vhost_ldap_set_fallback_docroot,
					NULL, RSRC_CONF,
					"Set default virtual host Document Root which will be used when requested hostname"
					"is not found in LDAP database. This option can be used to display"
					"\"virtual host not found\" type of page."),
	AP_INIT_TAKE1("VhostLDAProotdir", mod_vhost_ldap_set_rootdir, NULL, RSRC_CONF,
					"Configurable rootDir for vhosts"),
	AP_INIT_TAKE1("phpIncludePath",mod_vhost_ldap_set_phpincludepath, NULL, RSRC_CONF,
					"php include_path configuration for vhost"),
	AP_INIT_TAKE1("VhostLDAPcacheSize", mod_vhost_ldap_set_cache_size, NULL, RSRC_CONF, "Cache size"),
	{NULL}
};

static int ldapconnect(LDAP **ldapconn, mod_vhost_ldap_config_t *conf)
{
	int ldapversion = LDAP_VERSION3;
	int ret;
	if(*ldapconn == NULL){
		if((ret = ldap_initialize(ldapconn, conf->url)) > 0){
			*ldapconn = NULL;
			return ret;
		}
		if((ret = ldap_set_option(*ldapconn, LDAP_OPT_PROTOCOL_VERSION, &ldapversion)) > 0){
			*ldapconn = NULL;
			return ret;
		}
		if ((ret = ldap_simple_bind_s(*ldapconn, conf->binddn, conf->bindpw)) != LDAP_SUCCESS){
			ldap_unbind(*ldapconn);
			*ldapconn = NULL;
			return ret;
		}
	}
	return 0;
}

static void ldapdestroy(LDAP **ldapconn)
{
	ldap_unbind(*ldapconn);
	*ldapconn = NULL;
}

static int free_aliases(alias_cache_node_t **root)
{
	alias_cache_node_t *cur;
	if(*root){
		if((*root)->next){
			cur = (*root)->next;
			free_aliases(&cur);
		}
		if(apr_rmm_free(rmm_addr, apr_rmm_offset_get(rmm_addr, *root)) != APR_SUCCESS)
			return 1;
		*root = NULL;
	}
	return 0;
}

static apr_status_t prune_vhost_cache(int entries, mod_vhost_ldap_config_t *c)
{
	vhost_cache_node_t **cur, *next;
	int i = 0;
	cur = &c->cache->node;
	next = (*cur)->next;
	while(i < entries){
		free_aliases(&(*cur)->data.aliases);
		free_aliases(&(*cur)->data.redirects);
		if(APR_SUCCESS ==
				apr_rmm_free(rmm_addr, apr_rmm_offset_get(rmm_addr, *cur))){
			c->cache->numentries--;
			c->cache->nvhosts--;
			c->cache->used -= sizeof(vhost_cache_node_t);
			if(next)
				*cur = next;
			else
				*cur = NULL;
			if(c->cache->nvhosts < 1)
				return APR_SUCCESS;
			next = (*cur)->next;
			i++;
		}else
			return APR_EINVAL;
	}
	return APR_SUCCESS;
}

static void *cache_insert_vhost(server_rec *s, mod_vhost_ldap_config_t *conf)
{
	vhost_cache_node_t *cur;
	int overhead = 0;
	apr_rmm_off_t off = apr_rmm_calloc(rmm_addr, sizeof(vhost_cache_node_t));
	if(!off)
		return NULL;
	if(conf->cache->node == NULL){// add first node
		cur = apr_rmm_addr_get(rmm_addr, off);
		conf->cache->node = cur;
	}else{//append
		cur = conf->cache->node;
		while(cur->next != 0){
			cur=cur->next;
		}
		cur->next = apr_rmm_addr_get(rmm_addr, off);
		cur = cur->next;
		cur->next = 0;
	}
	conf->cache->numentries++;
	conf->cache->nvhosts++;
	conf->cache->used += sizeof(vhost_cache_node_t);
	overhead = apr_rmm_overhead_get(conf->cache->numentries);

	//If more then 90% is used prune the cache
	if(((float)(conf->cache->used + overhead) / conf->cache_size) > 0.9){
		 ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, s,
            "[mod_vhost_ldap_ng.c] Cache is almost full, i'm pruning it");
		prune_vhost_cache(3, conf);
	}
	cur->data.expires = apr_time_now() + apr_time_from_sec(1800);
	return &cur->data;
}

static alias_t *cache_insert_alias(alias_cache_node_t **root, cache_t *cache)
{
	alias_cache_node_t *cur = NULL;
	apr_off_t block;
	cache->used += sizeof(alias_cache_node_t);
	block = apr_rmm_calloc(rmm_addr,  sizeof(alias_cache_node_t));
	if(*root){
		cur = *root;
		while(cur->next)
			cur = cur->next;
		//Alloc from shm
		cur->next = apr_rmm_addr_get(rmm_addr, block);
		return &cur->next->data;
	}else{
		*root = apr_rmm_addr_get(rmm_addr, block);
		return &(*root)->data;
	}
}

static mod_vhost_ldap_request_t
*cache_fetch_vhost(vhost_cache_node_t *parent, request_rec *r)
{
	vhost_cache_node_t *node = NULL;
	node = parent;
	if(node){
		if(strcmp(node->data.name, r->hostname) == 0)
			return &(node->data);
		else if(node->next)
			return cache_fetch_vhost(node->next, r);
	}
	return NULL;
}

static alias_t *cache_fetch_alias(alias_cache_node_t *root, request_rec *r)
{
	alias_cache_node_t *cur;
	cur = root;
	while(cur){
		if(alias_matches(r->uri, cur->data.src))
			return &cur->data;
		else
			cur = cur->next;
	}
	return NULL;
}

#define FILTER_LENGTH MAX_STRING_LEN
static int mod_vhost_ldap_translate_name(request_rec *r)
{
	mod_vhost_ldap_request_t *reqc = NULL;
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)ap_get_module_config(
			r->server->module_config, &vhost_ldap_ng_module);
	core_server_config *core =
		(core_server_config *)ap_get_module_config(
			r->server->module_config, &core_module);
	LDAP *ld = NULL;
	char *realfile = NULL;
	alias_t *alias = NULL;
	int i = 0;
	unsigned long int ti;
	apr_status_t ret = 0;
	char *str[] = { NULL, NULL, NULL };
	LDAPMessage *ldapmsg = NULL, *vhostentry = NULL;
	// mod_vhost_ldap is disabled or we don't have LDAP Url
	if(r->handler && strcmp(r->handler, "mvl-status")==0)
        return OK;
	
	if ((conf->enabled != MVL_ENABLED)||(!conf->url)||(!r->hostname)){
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
				"[mod_vhost_ldap_ng.c] Module disabled");
		return DECLINED;
	}
	
	while(APR_STATUS_IS_EBUSY(apr_global_mutex_trylock(mtx))){ //Locking main process
		ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r,
            "[mod_vhost_ldap_ng.c] Can not acquire lock");
		apr_sleep(10000);
	}
	
#if APR_HAS_THREADS
	ret = apr_thread_mutex_lock(tmtx); //Locking threads
	if(ret != APR_SUCCESS)
		ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r,"[mod_vhost_ldap_ng.c] apr_thread_mutex_lock: %s",
			apr_strerror(ret, apr_pcalloc(r->pool, 50), 50));
#endif



	if ((r->server = apr_pmemdup(r->pool, r->server, sizeof(*r->server))) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap.c] translate: "
			"translate failed; Unable to copy r->server structure");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((r->server->module_config = apr_pmemdup(r->pool, r->server->module_config,
						sizeof(void *) *
						(total_modules + DYNAMIC_MODULE_LIMIT))) == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
                      "[mod_vhost_ldap.c] translate: "
                      "translate failed; Unable to copy r->server->module_config structure");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
	if ((core = apr_pmemdup(r->pool, core, sizeof(*core))) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap.c] translate: "
			"translate failed; Unable to copy r->core structure");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	ap_set_module_config(r->server->module_config, &core_module, core);
//END
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "[mod_vhost_ldap_ng.c] Traslating host %s", r->hostname);

	reqc = (mod_vhost_ldap_request_t *)cache_fetch_vhost(conf->cache->node, r);
	if(!reqc){
		ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, 
				"[mod_vhost_ldap_ng.c] Can not resolve data from cache");
	}

	if (reqc == NULL || reqc->expires < apr_time_now()){//Lets do the query
		if(reqc){
			reqc->expires = apr_time_now() + apr_time_from_sec(1800);
			if(reqc->aliases)
				free_aliases(&reqc->aliases);
			if(reqc->redirects)
				free_aliases(&reqc->redirects);
		}
		while((ret = ldapconnect(&ld, conf)) != 0 && i < 2){
			i++;
			ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
				"[mod_vhost_ldap_ng.c] ldapconnect(): %s searching %s", ldap_err2string(ret), r->hostname);
		}
		if(ret != 0){
			ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
							"[mod_vhost_ldap_ng.c] Cannot connect to LDAP Server: %s searching %s, MVL is disabled",  ldap_err2string(ret), r->hostname);
			conf->enabled = MVL_DISABLED;
#if APR_HAS_THREADS
			apr_thread_mutex_unlock(tmtx);
#endif
			apr_global_mutex_unlock(mtx);
			return HTTP_GATEWAY_TIME_OUT;
		}

		realfile =
			apr_psprintf(r->pool,"(&(%s)(|(apacheServerName=%s)(apacheServerAlias=%s)))",
							conf->filter, r->hostname, r->hostname);

		i = ldap_search_s(ld, conf->basedn, conf->scope, realfile, (char **)attributes,
							0, &ldapmsg);
		if(i != LDAP_SUCCESS){//SIGPIPE?
#if APR_HAS_THREADS
			apr_thread_mutex_unlock(tmtx);
#endif
			apr_global_mutex_unlock(mtx);
			if(ldapmsg)
				ldap_msgfree(ldapmsg);
			ldapdestroy(&ld);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		if(ldap_count_entries(ld, ldapmsg)!=1){
#if APR_HAS_THREADS
                apr_thread_mutex_unlock(tmtx);
#endif
                apr_global_mutex_unlock(mtx);
			if(ldapmsg)
				ldap_msgfree(ldapmsg);
			ldapdestroy(&ld);
			if(!conf->fallback_name || !conf->fallback_docroot){
/*
				apr_cpystrn(reqc->name, r->hostname, MAX_PAR_LENGHT);
				apr_cpystrn(reqc->docroot, "/aa", MAX_PAR_LENGHT);
*/
				core->ap_document_root = apr_pstrdup(r->pool, "/aa");
				r->server->server_hostname = apr_pstrdup(r->pool, "default_fallback");
				//reqc->decline = DECLINED;
			}else{
/*
				apr_cpystrn(reqc->name, conf->fallback_name, MAX_PAR_LENGHT);
				apr_cpystrn(reqc->docroot, conf->fallback_docroot, MAX_PAR_LENGHT);
*/
				core->ap_document_root = apr_pstrdup(r->pool, conf->fallback_docroot);
				r->server->server_hostname = apr_pstrdup(r->pool, conf->fallback_name);
			}
			return DECLINED;
			//aggiunto 22feb reqc->expires = apr_time_now() + apr_time_from_sec(1800);
		}else{
			if(reqc == NULL)
				reqc = cache_insert_vhost(r->server, conf);
	        if(!reqc){
    			ap_log_rerror(APLOG_MARK, APLOG_CRIT|APLOG_NOERRNO, 0, r,
					"[mod_vhost_ldap_ng.c] Cannot alloc in shared memory! used: %lu, total: %lu",
					conf->cache->used, conf->cache->size);
#if APR_HAS_THREADS
				apr_thread_mutex_unlock(tmtx);
#endif
				apr_global_mutex_unlock(mtx);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			reqc->decline = 0;
			//sempre stato qui 
			//reqc->expires = apr_time_now() + apr_time_from_sec(1800);
			vhostentry = ldap_first_entry(ld, ldapmsg);
			apr_cpystrn(reqc->dn,ldap_get_dn(ld, vhostentry), MAX_PAR_LENGHT);
			i=0;
			while(attributes[i]){
				int k = 0, j = 0;
				char **eValues = ldap_get_values(ld, vhostentry, attributes[i]);
				if (eValues){
					k = ldap_count_values (eValues);
					if (strcasecmp(attributes[i], "apacheServerName") == 0){
						apr_cpystrn(reqc->name, r->hostname, MAX_PAR_LENGHT);
						apr_cpystrn(reqc->servername, eValues[0], MAX_PAR_LENGHT);
					}else if(strcasecmp(attributes[i], "apacheServerAdmin") == 0){
						apr_cpystrn(reqc->admin, eValues[0], MAX_PAR_LENGHT);
					}else if(strcasecmp(attributes[i], "apacheDocumentRoot") == 0){
						apr_cpystrn(reqc->docroot, eValues[0], MAX_PAR_LENGHT);
						/* Make it absolute, relative to ServerRoot */
						if(conf->rootdir && (strncmp(reqc->docroot, "/", 1) != 0)){
							apr_cpystrn(reqc->docroot, 
								apr_pstrcat(r->pool, conf->rootdir, reqc->docroot, NULL),
								MAX_PAR_LENGHT);
						}
						apr_cpystrn(reqc->docroot,
							ap_server_root_relative(r->pool, reqc->docroot), MAX_PAR_LENGHT);
					}else if(strcasecmp(attributes[i], "apacheAlias") == 0){
						while(k){
							k--;
							for(j = 0; j < 2; j++)
								str[j] = ap_getword_conf(r->pool, (const char **)&eValues[k]);
							if(str[--j] == '\0')
								ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r,
								"[mod_vhost_ldap_ng.c]: Wrong apacheAlias parameter: %s",
								eValues[k]);
							else{
								alias = cache_insert_alias(&reqc->aliases, conf->cache);
								apr_cpystrn(alias->src, str[0], MAX_PAR_LENGHT);
								apr_cpystrn(alias->dst, str[1], MAX_PAR_LENGHT);
							}
						}
					}else if(strcasecmp(attributes[i], "apacheScriptAlias") == 0){
						while(k){
							k--;
							for(j = 0; j < 2; j++)
								str[j] = ap_getword_conf(r->pool, (const char **)&eValues[k]);
							if(str[--j] == '\0')
								ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r,
								"[mod_vhost_ldap_ng.c]: Wrong apacheScriptAlias parameter: %s",
								eValues[k]);
							else{
								alias = cache_insert_alias(&reqc->aliases, conf->cache);
								apr_cpystrn(alias->src, str[0], MAX_PAR_LENGHT);
								apr_cpystrn(alias->dst, str[1], MAX_PAR_LENGHT);
								alias->flags |= ISCGI;
							}
						}
					}else if(strcasecmp(attributes[i], "apacheRedirect") == 0){
						while(k){
							k--;
							for(j = 0; j < 3; j++)
								str[j] = ap_getword_conf(r->pool, (const char **)&eValues[k]);
							if(str[1] == '\0')
								ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r,
								"[mod_vhost_ldap_ng.c]: Missing apacheRedirect parameter: %s",
								eValues[k]);
							else{
								alias = cache_insert_alias(&reqc->redirects, conf->cache);
								apr_cpystrn(alias->src, str[0], MAX_PAR_LENGHT);
								if(str[2] != '\0'){
									if (strcasecmp(str[1], "gone") == 0)
										alias->flags |= REDIR_GONE;
									else if (strcasecmp(str[1], "permanent") == 0)
										alias->flags |= REDIR_PERMANENT;
									else if (strcasecmp(str[1], "temp") == 0)
										alias->flags |= REDIR_TEMP;
									else if (strcasecmp(str[1], "seeother") == 0)
										alias->flags |= REDIR_SEEOTHER;
									else{
										ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r,
										"[mod_vhost_ldap_ng.c]: Wrong apacheRedirect type: %s",
										str[2]);
										alias->flags |= REDIR_PERMANENT;
									}
									apr_cpystrn(alias->dst, str[2], MAX_PAR_LENGHT);
								}else{
									alias->flags |= REDIR_PERMANENT;
									apr_cpystrn(alias->dst, str[1], MAX_PAR_LENGHT);
								}
							}
						}
					}else if(strcasecmp(attributes[i], "apacheSuexecUid") == 0){
						apr_cpystrn(reqc->uid, eValues[0], 15);
					}else if(strcasecmp(attributes[i], "apacheSuexecGid") == 0){
						apr_cpystrn(reqc->gid, eValues[0], 15);
					}else if(strcasecmp (attributes[i], "apacheErrorLog") == 0){
						if(conf->rootdir && (strncmp(eValues[0], "/", 1) != 0))
							r->server->error_fname = apr_pstrcat(r->pool,
													conf->rootdir, eValues[0], NULL);
						else
							r->server->error_fname = apr_pstrdup(r->pool, eValues[0]);;
						apr_file_open(&r->server->error_log, r->server->error_fname,
								APR_APPEND | APR_WRITE | APR_CREATE | APR_LARGEFILE,
								APR_OS_DEFAULT, r->pool);
					}
#ifdef HAVEPHP
					else if(strcasecmp(attributes[i], "phpIncludePath") == 0){
						apr_cpystrn(reqc->php_includepath, eValues[0], strlen(eValues[0])+1);
					}else if(strcasecmp(attributes[i], "phpOpenBasedir") == 0){
						if(conf->rootdir && (strncmp(eValues[0], "/", 1) != 0)){
							str[0] = apr_pstrcat(r->pool, conf->rootdir, eValues[0], NULL);
							apr_cpystrn(reqc->php_openbasedir, str[0], MAX_PAR_LENGHT);
						}else
							apr_cpystrn(reqc->php_openbasedir, eValues[0], MAX_PAR_LENGHT);
					}
#endif
				}
				i++;
			}
			if(ldapmsg)
				ldap_msgfree(ldapmsg);
			ldapdestroy(&ld);
		}
	}
#if APR_HAS_THREADS
	apr_thread_mutex_unlock(tmtx);
#endif
	apr_global_mutex_unlock(mtx);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		"[mod_vhost_ldap_ng.c]: XXX reqc->docroot=%s, r->hostname=%s reqc->name=%s reqc->decline=%d DECLINED = %d",
		reqc->docroot, r->hostname, reqc->name, reqc->decline, DECLINED);

	ti = reqc->hits;
	if(++reqc->hits <= ti)
		ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, "[mod_vhost_ldap_ng.c] Hits overflow, old: %lu, new: %lu", ti, reqc->hits);
	

	//VHost is disabled, return NOT_FOUND
	if(reqc->decline == DECLINED){
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
					"[mod_vhost_ldap_ng.c]: Decline %s for %s",
					reqc->docroot, r->hostname);
		return 404;
	}

#ifdef HAVEPHP
	char *openbasedir, *include;
	
	if(strncmp(reqc->php_includepath, "\0", 1) == 0)
		include = apr_pstrcat(r->pool, conf->php_includepath, ":", reqc->docroot, NULL);
	else
		include = apr_pstrcat(r->pool, reqc->php_includepath, ":", conf->php_includepath,
								":", reqc->docroot, NULL);
	if(zend_alter_ini_entry("include_path", strlen("include_path") + 1, (void *)include,
							strlen(include), PHP_INI_SYSTEM, PHP_INI_STAGE_RUNTIME) != 0)
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "[mod_vhost_ldap.c] zend_alter_ini_entry failed, include_path: %s", include);

	if(strncmp(reqc->php_openbasedir, "\0", 1) != 0)
		openbasedir = apr_pstrcat(r->pool, reqc->php_openbasedir, ":", include, NULL);
	else
		openbasedir = apr_pstrdup(r->pool, include);
	
	/* 
	 * Moved from PHP_INI_STAGE_RUNTIME to PHP_INI_STAGE_ACTIVATE because
	 * zend_alter_ini_entry in php5.3 returns FAILURE modifing open_basedir
	 */
	if(zend_alter_ini_entry("open_basedir", strlen("open_basedir") + 1,
		(void *)openbasedir, strlen(openbasedir), PHP_INI_SYSTEM, PHP_INI_STAGE_ACTIVATE) != 0)
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "[mod_vhost_ldap.c] zend_alter_ini_entry failed, open_basedir: %s", openbasedir);
	ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, "PhpIncludePath: %s, PhpOpenBasedir %s", include, openbasedir);
#endif
	if ((reqc->name == NULL)||(reqc->docroot == NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap_ng.c] translate: translate failed; ServerName %s or DocumentRoot %s not defined",
			reqc->name, reqc->docroot);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                    "[mod_vhost_ldap_ng.c]: Serving docroot: %s for %s",
                    reqc->docroot, r->hostname);

	core->ap_document_root = apr_pstrdup(r->pool, reqc->docroot);
	if (!ap_is_directory(r->pool, reqc->docroot))
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		"[mod_vhost_ldap.c] set_document_root: Warning: DocumentRoot [%s] does not exist",
		core->ap_document_root);
	
	r->server->server_hostname = reqc->servername;

	if(reqc->admin)
		r->server->server_admin = apr_pstrdup(r->pool, reqc->admin);

	/*
	 * From mod_alias: checking for redirects
	 */
	if(reqc->redirects){
		if ((alias = cache_fetch_alias(reqc->redirects, r))) {
			apr_table_setn(r->headers_out, "Location", alias->dst);
			if(alias->flags & REDIR_GONE) return HTTP_GONE;
			else if(alias->flags & REDIR_TEMP) return HTTP_MOVED_TEMPORARILY;
			else if(alias->flags & REDIR_SEEOTHER) return HTTP_SEE_OTHER;
			else return HTTP_MOVED_PERMANENTLY;
		}
	}
	
	/*
	 * Checking for aliases 
	 */
	if(reqc->aliases){
		if ((alias = cache_fetch_alias(reqc->aliases, r))) {
			realfile =
				apr_pstrcat(r->pool, alias->dst, r->uri + strlen(alias->src), NULL);
			if(conf->rootdir && (strncmp(alias->dst, "/", 1) != 0))
				realfile = apr_pstrcat(r->pool, conf->rootdir, realfile, NULL);
			if((realfile = ap_server_root_relative(r->pool, realfile))) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
					"[mod_vhost_ldap_ng.c]: ap_document_root is: %s",
					ap_document_root(r));
				r->filename = realfile;
				if(alias->flags & ISCGI){
					r->handler = "Script";
					apr_table_setn(r->notes, "alias-forced-type", r->handler);
				}
			}
			return OK;
		} else if (r->uri[0] != '/') {
			return DECLINED;
		}
	}

	if ((r->server = apr_pmemdup(r->pool, r->server, sizeof(*r->server))) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap_ng.c] translate: "
			"translate failed; Unable to copy r->server structure");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	/* Hack to allow post-processing by other modules (mod_rewrite, mod_alias) */
	return DECLINED;
}

#ifdef HAVE_UNIX_SUEXEC
static
ap_unix_identity_t *mod_vhost_ldap_get_suexec_id_doer(const request_rec * r)
{
	struct passwd *passwdp;
	struct group *groupp;
	ap_unix_identity_t *ugid = NULL;
	mod_vhost_ldap_config_t *conf = 
		(mod_vhost_ldap_config_t *)ap_get_module_config(r->server->module_config,
		&vhost_ldap_ng_module);
	mod_vhost_ldap_request_t *req =
			(mod_vhost_ldap_request_t *)ap_get_module_config(r->request_config,
			&vhost_ldap_ng_module);

  // mod_vhost_ldap is disabled or we don't have LDAP Url
	if ((conf->enabled != MVL_ENABLED)||(!conf->url))
		return NULL;
		
	if ((req == NULL)||(req->uid == NULL)||(req->gid == NULL)) 
		return NULL;

	if ((ugid = apr_palloc(r->pool, sizeof(ap_unix_identity_t))) == NULL)
		return NULL;

	passwdp = getpwnam(req->uid); //Get UID and GID from aliases in LDAP
	groupp = getgrnam(req->gid);

	if ((passwdp->pw_uid < MIN_UID)||(groupp->gr_gid < MIN_GID))
		return NULL;

	ugid->uid = passwdp->pw_uid;
	ugid->gid = groupp->gr_gid;
	ugid->userdir = 0;

	return ugid;
}
#endif

static int shmout_handler(request_rec *r){
	int overhead = 0;
	int i = 0;
	vhost_cache_node_t *node = NULL;
	//alias_cache_node_t *anode = NULL;
	vhost_cache_node_t *root = NULL;
	vhost_cache_node_t *cur = NULL;
	if(strcmp(r->handler, "mvl-status")!=0)
		return DECLINED;
	mod_vhost_ldap_config_t *conf =
        (mod_vhost_ldap_config_t *)ap_get_module_config(
            r->server->module_config, &vhost_ldap_ng_module);
	if(!conf->cache){
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
			"[mod_vhost_ldap_ng.c] Not configured for host %s.", r->hostname);
		return 404;
	}

	ap_set_content_type(r, "text/html; charset=ISO-8859-1");
    ap_rputs(DOCTYPE_HTML_3_2
        "<html>\n<head>\n<title>Apache MVL Status</title>\n</head><body>\n", r);

    ap_rputs("<b>Mod_vhost_ldap_ng SHM Status</b>:<br />\n", r);

	ap_rprintf(r, "Total: %lu bytes<br />", (unsigned long int)conf->cache_size);
	overhead =  apr_rmm_overhead_get(conf->cache->numentries);
	ap_rprintf(r, "Used: %lu bytes, %.2f%% of total<br />",
		(unsigned long int)conf->cache->used + overhead, (float)(conf->cache->used + overhead) * 100/conf->cache_size);
	ap_rprintf(r, "Entries: %lu<br />", (unsigned long int)(conf->cache->numentries - 1));
	if(!conf->cache->node){
		ap_rputs("\n<br />No entries<br />", r);
	}else{
		char *exp = apr_pcalloc(r->pool, 80);
		
		while(APR_STATUS_IS_EBUSY(apr_global_mutex_trylock(mtx))){ //Locking main process
			ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r,
            "[mod_vhost_ldap_ng.c] Can not acquire lock");
			apr_sleep(10000);
    	}

		node = conf->cache->node;
	    while(node){
			vhost_cache_node_t *new = apr_palloc(r->pool, sizeof(vhost_cache_node_t));
			vhost_cache_node_t *prev = NULL;
			memcpy(new, node, sizeof(vhost_cache_node_t));
			new->next = NULL;
			if(!root){
				root = new;
			}else{
				prev = NULL;
				cur = root;
				while(cur){
					if(new->data.hits >= cur->data.hits ){
						new->next = cur;
						if(prev == NULL){
							root = new;
						}else{
							prev->next = new;
						}
						cur = NULL;//exit while
					}else{
						prev = cur;
						cur = cur->next;
						if(cur == NULL)
							prev->next = new;
					}
				}
			}
			node = node->next;
		}
		apr_global_mutex_unlock(mtx);
		node = root;
		while(node){
			i++;
			apr_rfc822_date(exp, node->data.expires);
			ap_rputs("\n<br />-------------------------<br />", r);
			ap_rprintf(r, "\nHostname: %s<br />", node->data.name);
			ap_rprintf(r, "\nHITS: %lu<br />", node->data.hits);
			ap_rprintf(r, "\nDocroot: %s<br />", node->data.docroot);
			if(node->data.php_includepath[0] != '\0')
				ap_rprintf(r, "\nPHP include_path: %s<br />",node->data.php_includepath);
			if(node->data.php_openbasedir[0] != '\0')
				ap_rprintf(r, "\nPHP open_basedir: %s<br />",node->data.php_openbasedir);
			ap_rprintf(r, "\nExpire: %s<br />", exp);
			ap_rprintf(r, "\nDecline: %d<br />", (int) node->data.decline == DECLINED);
	/*		if(node->data.aliases){
				ap_rputs("\nAliases<br />", r);
				anode = node->data.aliases;	
				ap_rputs("\n<ul>", r);
				while(anode){
					ap_rprintf(r, "\n<li>Src: %s, Dst: %s</li>", anode->data.src, anode->data.dst);
					anode = anode->next;
				}
				ap_rputs("\n</ul>", r);
			}*/
			node = node->next;
	    }
	}
	ap_rprintf(r, "\n<br><b>count: %d</b></body>\n</html>", i);
	return APR_SUCCESS;
}

static void mod_vhost_ldap_register_hooks (apr_pool_t * p)
{
	/*
	* Run before mod_rewrite
	*/
	static const char * const aszRewrite[]={ "mod_rewrite.c", NULL };
//	static const char * const PostConf[]={ "http_core.c", NULL };
	ap_hook_post_config(mod_vhost_ldap_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
	ap_hook_child_init(mod_vhost_ldap_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	//ap_hook_post_config(mod_vhost_ldap_post_config, NULL, PostConf, APR_HOOK_MIDDLE);
	ap_hook_translate_name(
		mod_vhost_ldap_translate_name, NULL, aszRewrite, APR_HOOK_FIRST);
	//ap_hook_handler(shmout_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(shmout_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
#ifdef HAVE_UNIX_SUEXEC
	ap_hook_get_suexec_identity(
		mod_vhost_ldap_get_suexec_id_doer, NULL, NULL, APR_HOOK_MIDDLE);
#endif

}

module AP_MODULE_DECLARE_DATA vhost_ldap_ng_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	mod_vhost_ldap_create_server_config,
	mod_vhost_ldap_merge_server_config,
	mod_vhost_ldap_cmds,
	mod_vhost_ldap_register_hooks,
};
