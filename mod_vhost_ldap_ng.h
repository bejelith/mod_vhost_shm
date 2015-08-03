/* ============================================================
 * Copyright (c) 2003-2004, Simone Caruso <info@simonecaruso.com>
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
 */

#define MIN_UID 100
#define MIN_GID 100

#define PHP_INI_USER    (1<<0)
#define PHP_INI_PERDIR  (1<<1)
#define PHP_INI_SYSTEM  (1<<2)

#define PHP_INI_STAGE_STARTUP           (1<<0)
#define PHP_INI_STAGE_SHUTDOWN          (1<<1)
#define PHP_INI_STAGE_ACTIVATE          (1<<2)
#define PHP_INI_STAGE_DEACTIVATE        (1<<3)
#define PHP_INI_STAGE_RUNTIME           (1<<4)

#define REDIR_GONE      (1<<0)
#define REDIR_PERMANENT (1<<1)
#define REDIR_TEMP      (1<<2)
#define REDIR_SEEOTHER  (1<<3)
#define ISCGI           (1<<4)

#define	MAX_PAR_LENGHT	120
#define MAX_ALIASES		10
#define SHM_CACHE_SIZE		500000

extern int zend_alter_ini_entry (char *, uint, char *, uint, int, int);

typedef enum {
	MVL_UNSET, MVL_DISABLED, MVL_ENABLED
} mod_vhost_ldap_status_e;

typedef struct alias_t {
	char src[MAX_PAR_LENGHT];
	char dst[MAX_PAR_LENGHT];
	char redir_status[10];
	uint8_t flags;
} alias_t;

typedef struct  alias_cache_node_t {
	alias_t data;
	struct alias_cache_node_t *next;
} alias_cache_node_t;

typedef struct mod_vhost_ldap_request_t {
	char dn[MAX_PAR_LENGHT];				/* The saved dn from a successful search */
	char name[MAX_PAR_LENGHT];				/* ServerName */
	char servername[MAX_PAR_LENGHT];
	char admin[MAX_PAR_LENGHT];				/* ServerAdmin */
	char docroot[MAX_PAR_LENGHT];			/* DocumentRoot */
	char cgiroot[MAX_PAR_LENGHT];			/* ScriptAlias */
	char uid[15];							/* Suexec Uid */
	char gid[15];							/* Suexec Gid */
	short int decline;
	apr_time_t expires;						/* Expire time from cache */
	int naliases;
	int nredirects;
	unsigned long int hits;
	alias_cache_node_t *aliases;
	alias_cache_node_t *redirects;
	char php_includepath[MAX_PAR_LENGHT];
	char php_openbasedir[MAX_PAR_LENGHT];
} mod_vhost_ldap_request_t;

typedef struct vhost_cache_node_t {
	mod_vhost_ldap_request_t data;
	struct vhost_cache_node_t *next;
} vhost_cache_node_t;

typedef struct cache_t {
	vhost_cache_node_t *node;
	unsigned long size;
	int numentries;
	int nvhosts;
	unsigned long used;
} cache_t;

typedef struct mod_vhost_ldap_config_t {
	mod_vhost_ldap_status_e enabled;			/* Is vhost_ldap enabled? */
	/* These parameters are all derived from the VhostLDAPURL directive */
	char *url;				/* String representation of LDAP URL */
	char *basedn;			/* Base DN to do all searches from */
	int scope;				/* Scope of the search */
	char *filter;			/* Filter to further limit the search  */
	char *binddn;			/* DN to bind to server (can be NULL) */
	char *bindpw;			/* Password to bind to server (can be NULL) */
	char *fallback_name;    /* Fallback virtual host ServerName*/
	char *fallback_docroot;	/* Fallback virtual host documentroot*/
	char *rootdir;
	char *php_includepath;
	cache_t *cache;
	apr_size_t cache_size;
} mod_vhost_ldap_config_t;

char *attributes[] = {
	"apacheServerName", "apacheDocumentRoot", "apacheScriptAlias",
	"apacheSuexecUid", "apacheSuexecGid", "apacheServerAdmin",
	"apacheAlias", "apacheRedirect",
#ifdef HAVEPHP
	"phpOpenBasedir", "phpIncludePath",
#endif
	0 };

