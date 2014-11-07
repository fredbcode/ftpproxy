/*
 * $Id: ftp-ldap.c,v 1.7.2.3 2004/03/10 16:07:13 mt Exp $
 *
 * FTP Proxy LDAP interface handling
 *
 * Author(s): Jens-Gero Boehm <jens-gero.boehm@suse.de>
 *            Pieter Hollants <pieter.hollants@suse.de>
 *            Marius Tomaschewski <mt@suse.de>
 *            Volker Wiegand <volker.wiegand@suse.de>
 *
 * This file is part of the SuSE Proxy Suite
 *            See also  http://proxy-suite.suse.de/
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * A history log can be found at the end of this file.
 */

#ifndef lint
static char rcsid[] = "$Id: ftp-ldap.c,v 1.7.2.3 2004/03/10 16:07:13 mt Exp $";
#endif

#include <config.h>

#define _GNU_SOURCE		/* needed for crypt in Linux... */

#if defined(STDC_HEADERS)
#  include <stdio.h>
#  include <string.h>
#  include <stdlib.h>
#  include <stdarg.h>
#  include <errno.h>
#  include <ctype.h>
#endif

#if defined(HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#if defined(TIME_WITH_SYS_TIME)
#  include <sys/time.h>
#  include <time.h>
#else
#  if defined(HAVE_SYS_TIME_H)
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#if defined(HAVE_LIBLDAP)
#  if defined(HAVE_LDAP_UMICH)
#    include <lber.h>
#  endif
#  include <ldap.h>
#  if !defined(LDAP_PORT)
#    define LDAP_PORT		389
#  endif
#endif

#include "com-config.h"
#include "com-debug.h"
#include "com-misc.h"
#include "com-socket.h"
#include "com-syslog.h"
#include "ftp-client.h"
#include "ftp-cmds.h"
#include "ftp-ldap.h"

/* ------------------------------------------------------------ */

#if defined(HAVE_LIBLDAP)
#   if defined(HAVE_LDAP_GET_LDERRNO)
	/*
	** Netscape
	*/
#       define GET_LDERROR(ld,le) le = ldap_get_lderrno(ld, NULL, NULL)

#   elif defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
	/*
	** OpenLDAP 2.x
	*/
#       define GET_LDERROR(ld,le) ldap_get_option(ld,LDAP_OPT_ERROR_NUMBER,&le)

#   elif defined __sun__
	/*
	** there is only a forward declaration of the LDAP
	** connection handle struct in ldap.h on Solaris7,
	** so we have no access to ld_errno.
	*/
#	define GET_LDERROR(ld,le)   le = LDAP_OTHER

#   else
	/*
	** UmichLDAP or OpenLDAP 1.x
	*/
#       define GET_LDERROR(ld,le) le = (ld)->ld_errno
#   endif
#endif


/* ------------------------------------------------------------ */

#if defined(HAVE_LIBLDAP)
static int   ldap_fetch(LDAP *ld, CONTEXT *ctx, char *who, char *pwd);
static char *ldap_attrib(LDAP *ld, LDAPMessage *e, char *attr, char *dflt);
static int   ldap_exists(LDAP *ld, LDAPMessage *e, char *attr,
                                                   char *vstr, int cs);
static int   ldap_auth(LDAP *ld, LDAPMessage *e, char *who, char *pwd, CONTEXT *);
//Fred patch
void patch_ldapgroup(LDAP *ld, char *who, CONTEXT *ctx);
static char* prep_bind_auto(LDAP *ld, char *flt, char *base, char *peer);
static char* prep_bind_fmt(char *str, char *who);
#endif

/* ------------------------------------------------------------ **
**
**	Function......:	ldap_setup_user
**
**	Parameters....:	ctx		Pointer to user context
**			who		Pointer to user auth name
**			pwd		Pointer to user auth pwd
**
**	Return........:	0 on success
**
**	Purpose.......: Read the user specific parameters from
**			LDAP Server if one is known.
**
** ------------------------------------------------------------ */

int  ldap_setup_user(CONTEXT *ctx, char *who, char *pwd)
{
	char      *ptr = 0;
	int        ver = 0;

	/*
	** avoid unused... compiler warnings
	*/
	ver = ver;
	ptr = ptr;
	pwd = pwd;

	/*
	** Basic sanity check
	*/
	if( !(ctx && who && *who))
		misc_die(FL, "ldap_setup_user: ?ctx? ?who?");

#if defined(HAVE_LIBLDAP)
	/*
	** use configured ldap version or prefer v3 since
	** OpenLDAP 2.x library defaults to v2, but the
	** server does not accept v2 binds per default...
	*/
#if   defined(LDAP_VERSION3)
	ver = LDAP_VERSION3;
#elif defined(LDAP_VERSION2)
	ver = LDAP_VERSION2;
#else
	ver = 0;
#endif
	ptr = config_str(NULL, "LDAPVersion", NULL);
	if(NULL != ptr) {
		ver = atoi(ptr);
	}

	// Patch Fred Bug mot de passe nul
	
	if (*pwd == '\0') {
	syslog_write(U_ERR, "No Ldap password");
	exit(-1);
	}
	/*
	** If an LDAP server is configured, insist on using it
	*/
	if((ptr = config_str(NULL, "LDAPServer", NULL)) != NULL) {
		char       temp[MAX_PATH_SIZE];
		char      *host;
		u_int16_t  port;
		int        rc;
		LDAP      *ld;

		misc_strncpy(temp, ptr, sizeof(temp));
		/*
		** Determine LDAP server and port
		*/
		host = temp;
		if(NULL != (ptr = strchr(temp, ':'))) {
			*ptr++ = '\0';
			port = (int) socket_str2port(ptr, LDAP_PORT);
		} else {
			port = (int) LDAP_PORT;
		}

#if defined(COMPILE_DEBUG)
		debug(2, "LDAP server: %s:%d", host, port);
#endif

		/*
		** Ready to contact the LDAP server
		*/
		if((ld = ldap_init(host, port)) == NULL) {
			syslog_write(T_ERR,
			             "[ %s ] can't reach LDAP server %s:%u for %s",
			            ctx->cli_ctrl->peer, host, port, ctx->cli_ctrl->peer);
			return -1;
		} else {
			syslog_write(T_DBG,
			             "[ %s ] LDAP server %s:%u: initialized for %s",
			             ctx->cli_ctrl->peer, host, port, ctx->cli_ctrl->peer);
		}

		if(ver > 0) {
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_PROTOCOL_VERSION)
			ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
#else
			ld->ld_version = ver;
#endif
		}

		rc = ldap_fetch(ld, ctx, who, pwd);
		ldap_unbind(ld);
		return rc;
	}
#endif
	return 0;
}


#if defined(HAVE_LIBLDAP)
/* ------------------------------------------------------------ **
**
**	Function......:	prep_bind_auto
**
**	Parameters....:	ld		Pointer ldap struct
**			flt		LDAP search filter
**			base		BaseDN to search in
**			peer		Peer name for syslog
**
**	Return........:	bind-dn or NULL
**
**	Purpose.......:	Searches using anonymous bind
**			for a dn we want to bind later.
**
** ------------------------------------------------------------ */

static char* prep_bind_auto(LDAP *ld, char *flt, char *base, char *peer)
{
	LDAPMessage *result, *e;
	char        *attrs[] = {0, 0};
	char        *bind_dn, *p, *d;
	int          err;

	if(NULL == base || '\0' == base[0]) {
		misc_die(FL,"prep_bind_auto: ?base?");
	}

	/*
	** pre-bind (anonymously)
	*/
	if((d = config_str(NULL, "LDAPPreBindDN", NULL)) &&
	   (p = config_str(NULL, "LDAPPreBindPW", NULL))) {
	    err = ldap_simple_bind_s(ld, d, p);
	} else {
	    err = ldap_simple_bind_s(ld, 0, 0);
	}
	if(LDAP_SUCCESS != err) {
		syslog_write(T_ERR,
		       "can't bind LDAP anonymously for %s: %.512s",
		       peer, ldap_err2string(err));
		return NULL;
	}

	result   = 0;
	attrs[0] = config_str(NULL, "LDAPIdentifier", "CN");

	err = ldap_search_s(ld,  base,  LDAP_SCOPE_SUBTREE,
	                    flt, attrs, 1, &result);
	if(LDAP_SUCCESS != err) {
		syslog_write(T_ERR,
		       "can't find valid bind-dn for %s: %.512s",
		       peer, ldap_err2string(err));
		return NULL;
	}

	e = ldap_first_entry(ld, result);
	if(NULL == e) {
		GET_LDERROR(ld, err);
		syslog_write(T_ERR,
		       "can't find valid bind-dn for %s", peer);
		return NULL;
	}

	/*
	** OK, we have a DN
	*/
	if(NULL != (p = ldap_get_dn(ld, e))) {
		bind_dn = misc_strdup(FL, p);
		ldap_memfree(p);
	} else {
		bind_dn = NULL;
	}
	ldap_msgfree(result);
	syslog_write(T_DBG, "auto bind-dn='%.256s' for %s",
		             NIL(bind_dn), peer);
	return bind_dn;
}


/* ------------------------------------------------------------ **
**
**	Function......:	prep_bind_fmt
**
**	Parameters....:	str		Bind-DN fmt string
**			who		Current user name
**
**	Return........:	bind-dn or NULL
**
**	Purpose.......:	Checks if str contains a fmt
**			and constructs a new base-dn.
**
** ------------------------------------------------------------ */

static char* prep_bind_fmt(char *str, char *who)
{
	char   *bind_dn, *p;
	int    fmt = 0;
	size_t len;

	/*
	** search for exactly one %s; if any other
	** fmt's are present report an parse error.
	*/
	for(p=str; p && p[0] && (p = strchr(p, '%')); p++) {
		if(!fmt && ('s' == p[1] || 'S' == p[1])) {
			fmt = 1;
		} else {
			errno = 0;
			misc_die(FL,"prep_bind_fmt: ?str?");
		}
	}

	if(fmt) {
		/*
		** constuct LDAPBind DN and PW
		*/
		len = strlen(who) + strlen(str);
		bind_dn = misc_alloc(FL, len);
#if defined(HAVE_SNPRINTF)
		snprintf(bind_dn, len, str, who);
#else
		sprintf(bind_dn, str, who);
#endif
		return bind_dn;
	}
	return 0;
}

/* ------------------------------------------------------------ **
**
**	Function......:	ldap_fetch
**
**	Parameters....:	ld		Pointer ldap struct
**			ctx		Pointer to user context
**			who		Pointer to user/auth name
**			pwd		Pointer to user/auth pwd
**
**	Return........:	0 on success
**
**	Purpose.......: Read the user specific parameters from
**			an LDAP Server.
**
** ------------------------------------------------------------ */

static int ldap_fetch(LDAP *ld, CONTEXT *ctx, char *who, char *pwd)
{
	char str[MAX_PATH_SIZE];
	char *bind_dn, *bind_pw;
	char *base_dn, *auth_dn;
	char *idnt, *objc, *ptr, *p, *q;
	char  lderr, auth_ok;
	u_int16_t l, u;
	LDAPMessage *result, *e;

	/* Basic sanity */
	if(ctx == NULL || ld == NULL || who == NULL) {
		if(ld) ldap_unbind(ld);
		misc_die(FL, "ldap_fetch: ?ctx? ?ld? ?who?");
	}

	/*
	** construct filter for the search
	**	(by LDAPIdentifier, maybe also ObjectClass)
	*/
	idnt = config_str(NULL, "LDAPIdentifier", "CN");
	objc = config_str(NULL, "LDAPObjectClass", NULL);
	if(NULL != objc) {
#if defined(HAVE_SNPRINTF)
		snprintf(str, sizeof(str),
			  "(&(ObjectClass=%.256s)(%.256s=%.256s))",
			  objc,  idnt, who);
#else
		sprintf(str,
			  "(&(ObjectClass=%.256s)(%.256s=%.256s))",
			  objc,  idnt, who);
#endif
	} else {
#if defined(HAVE_SNPRINTF)
		snprintf(str, sizeof(str), "(%.256s=%.256s)",
			  idnt, who);
#else
		sprintf(str, "(%.256s=%.256s)", idnt, who);
#endif
	}

	auth_ok = 0; /* OK if non-anonymous bind */
	auth_dn = config_str(NULL, "LDAPAuthDN", NULL);
	base_dn = config_str(NULL, "LDAPBaseDN", NULL);
	if(NULL != (ptr = config_str(NULL, "LDAPBindDN", NULL))) {
		/*
		** check if we should use auth-/base-dn for bind
		*/
		bind_pw = pwd;
		bind_dn = 0;
		if(0 == strcasecmp(ptr, "auto")) {
			bind_dn = prep_bind_auto(ld, str, auth_dn ?
			                         auth_dn : base_dn,
			                         ctx->cli_ctrl->peer);
			auth_ok = 1;
			if(NULL == bind_dn) return -1;
		} else
		if(0 == strcasecmp(ptr, "AuthDN")) {
			bind_dn = prep_bind_auto(ld, str, auth_dn,
			                         ctx->cli_ctrl->peer);
			auth_ok = 1;
			if(NULL == bind_dn) return -1;
		} else
		if(0 == strcasecmp(ptr, "BaseDN")) {
			bind_dn = prep_bind_auto(ld, str, base_dn,
			                         ctx->cli_ctrl->peer);
			auth_ok = 1;
			if(NULL == bind_dn) return -1;
		} else {
			/*
			** check if we have a format in BindDN
			*/
			bind_dn = prep_bind_fmt(ptr, who);
			if(NULL == bind_dn) {
				/*
				** use static LDAPBind DN and PW
				*/
				bind_dn = misc_strdup(FL, ptr);
				bind_pw = config_str(NULL, "LDAPBindPW", NULL);
			} else {
				auth_ok = 1;
			}
		}

		/*
		** bind usind a dn & pw
		*/
		lderr = ldap_simple_bind_s(ld, bind_dn, bind_pw);
		if(LDAP_SUCCESS != lderr) {
			syslog_write(U_ERR,
			      "can't bind LDAP dn='%.256s' for %s: %.512s",
			      bind_dn, ctx->cli_ctrl->peer,
			      ldap_err2string(lderr));
			return -1;
		}
		syslog_write(T_DBG,
		             "[ %s ] LDAP bind to dn='%.256s': succeed", ctx->cli_ctrl->peer, bind_dn);
	} else {
		/*
		** bind anonymously
		*/
		lderr = ldap_simple_bind_s(ld, 0, 0);
		if(LDAP_SUCCESS != lderr) {
			syslog_write(T_ERR,
			       "[ %s ] can't bind LDAP anonymously for %s: %.512s",
			      ctx->cli_ctrl->peer, ctx->cli_ctrl->peer, ldap_err2string(lderr));
			return -1;
		}
	}

	syslog_write(U_INF, "[ % s ] reading data for '%s' from LDAP",ctx->cli_ctrl->peer, who);
	if(NULL != base_dn) {
		syslog_write(T_DBG,
		             "[ %s ] LDAP search: base='%.256s' filter='%.256s'",
		             ctx->cli_ctrl->peer, base_dn, str);
		result = 0;
		lderr  = ldap_search_s(ld, base_dn, LDAP_SCOPE_SUBTREE,
		                      str, NULL, 0, &result);
				      
		if(LDAP_SUCCESS != lderr) {
			syslog_write(T_ERR,
			             "[ %s ] can't read LDAP data for %s: %.512s",
			             ctx->cli_ctrl->peer,ctx->cli_ctrl->peer,
			             ldap_err2string(lderr));
			return -1;
		}

		

		/*
		** Check if we have a user data
		** (else return 'error' or 'empty')
		*/
		if(NULL == (e = ldap_first_entry(ld, result))) {
			GET_LDERROR(ld,lderr);
			syslog_write(T_DBG,
			             "empty LDAP result for %s in base-dn='%s'",
			             ctx->cli_ctrl->peer, base_dn);
			e = result = NULL;
		}
	} else {
		e = result = NULL;
	}

	/*
	** Preform auth on userauth if type is ldap
	*/
	ptr = config_str(NULL, "UserAuthType", NULL);
	if( ptr && 0 == strcasecmp(ptr, "ldap")) {
		LDAPMessage *res=0, *a=e;
		int rc = 0;

		/*
		** if LDAPAuthDN set, do auth on a different base...
		*/
		if(NULL != auth_dn) {
			syslog_write(T_DBG,
			       "LDAP auth: base='%.256s' filter='%.256s'",
			       auth_dn, str);

			lderr = ldap_search_s(ld, auth_dn, LDAP_SCOPE_SUBTREE,
			                      str, NULL, 0, &res);
			if(LDAP_SUCCESS != lderr) {
				syslog_write(T_ERR,
				    "can't read LDAP auth-data for %s: %.512s",
				    ctx->cli_ctrl->peer,
				    ldap_err2string(lderr));
				if(result) ldap_msgfree(result);
				return -1;
			}

			if(NULL == (a = ldap_first_entry(ld, res))) {
				GET_LDERROR(ld,lderr);
				syslog_write(T_WRN,
				    "empty LDAP result for %s in auth-dn='%s'",
				    ctx->cli_ctrl->peer, auth_dn);
				if(result) ldap_msgfree(result);
				return -1;
			}
		} else
		if(NULL == base_dn || NULL == e) {
			ldap_unbind(ld);
			misc_die(FL, "ldap_fetch: ?LDAPBaseDN?");
		}

		/*
		** OK, let's check the user auth now
		*/
		rc = ldap_auth(ld, a, who, pwd, ctx);
		if(res) ldap_msgfree(res);
		if(0 > rc)  {
			syslog_write(U_ERR,
			             "LDAP user auth failed for %s from %s",
			             who, ctx->cli_ctrl->peer);
			if(result) ldap_msgfree(result);
			return -1;
		}
		/*
		** do not allow to configure UserAuthType=ldap
		** and to skip all manual ldap checks without
		** an sufficient ldap-bind.
		*/
		if(0 == rc && 0 == auth_ok) {
			syslog_write(T_ERR, "LDAP auth config not sufficient");
			if(result) ldap_msgfree(result);
			return -1;
		}

	}

	/*
	** read proxy user profile data ...
	** if we have a base_dn and result
	*/
	if(NULL == base_dn || NULL == e) {
		return 0;
	}

	/*
	** Evaluate the destination FTP server address.
	*/
	p = ldap_attrib(ld, e, "DestinationAddress", NULL);
	if(NULL != p && ctx->magic_addr == INADDR_ANY) {
		ctx->srv_addr = socket_str2addr(p, INADDR_ANY);
		if(INADDR_ANY == ctx->srv_addr) {
			syslog_write(T_ERR, "can't eval DestAddr for %s",
			                    ctx->cli_ctrl->peer);
			ldap_msgfree(result);
			return -1;
		}
#if defined(COMPILE_DEBUG)
		debug(2, "ldap DestAddr for %s: '%s'", ctx->cli_ctrl->peer,
				socket_addr2str(ctx->srv_addr));
#endif
	}

	/*
	** Evaluate the destination FTP server port
	*/
	p = ldap_attrib(ld, e, "DestinationPort", NULL);
	if(NULL != p && ctx->magic_port == INPORT_ANY) {
		ctx->srv_port = socket_str2port(p, INPORT_ANY);
		if(INPORT_ANY == ctx->srv_port) {
			syslog_write(T_ERR, "can't eval DestPort for %s",
			                    ctx->cli_ctrl->peer);
			ldap_msgfree(result);
			return -1;
		}
#if defined(COMPILE_DEBUG)
		debug(2, "ldap DestPort for %s: %u",
			ctx->cli_ctrl->peer, ctx->srv_port);
#endif
	}

	/*
	** Evaluate the destination transfer mode
	*/
	p = ldap_attrib(ld, e, "DestinationTransferMode", NULL);
	if(NULL != p) {
		if(strcasecmp(p, "active") == 0)
			ctx->srv_mode = MOD_ACT_FTP;
		else if (strcasecmp(p, "passive") == 0)
			ctx->srv_mode = MOD_PAS_FTP;
		else if (strcasecmp(p, "client") == 0)
			ctx->srv_mode = MOD_CLI_FTP;
		else {
			syslog_write(T_ERR, "can't eval DestMode for %s",
			                    ctx->cli_ctrl->peer);
			ldap_msgfree(result);
			return -1;
		}
#if defined(COMPILE_DEBUG)
		debug(2, "ldap DestMode for %s: %s", ctx->cli_ctrl->peer, p);
#endif
	}

	/*
	** Evaluate the port ranges
	*/
	p = ldap_attrib(ld, e, "DestinationMinPort", NULL);
	q = ldap_attrib(ld, e, "DestinationMaxPort", NULL);
	if(NULL != p && NULL != q) {
		l = socket_str2port(p, INPORT_ANY);
		u = socket_str2port(q, INPORT_ANY);
		if (l > 0 && u > 0 && u >= l) {
			ctx->srv_lrng = l;
			ctx->srv_urng = u;
		}
#if defined(COMPILE_DEBUG)
		debug(2, "ldap DestRange for %s: %u-%u", ctx->cli_ctrl->peer,
		         ctx->srv_lrng, ctx->srv_urng);
#endif
	}

	p = ldap_attrib(ld, e, "ActiveMinDataPort", NULL);
	q = ldap_attrib(ld, e, "ActiveMaxDataPort", NULL);
	if(NULL != p && NULL != q) {
		l = socket_str2port(p, INPORT_ANY);
		u = socket_str2port(q, INPORT_ANY);
		if (l > 0 && u > 0 && u >= l) {
			ctx->act_lrng = l;
			ctx->act_urng = u;
		}
#if defined(COMPILE_DEBUG)
		debug(2, "ActiveRange for %s: %u-%u", ctx->cli_ctrl->peer,
		         ctx->act_lrng, ctx->act_urng);
#endif
	}

	p = ldap_attrib(ld, e, "PassiveMinDataPort", NULL);
	q = ldap_attrib(ld, e, "PassiveMaxDataPort", NULL);
	if(NULL != p && NULL != q) {
		l = socket_str2port(p, INPORT_ANY);
		u = socket_str2port(q, INPORT_ANY);
		if (l > 0 && u > 0 && u >= l) {
			ctx->pas_lrng = l;
			ctx->pas_urng = u;
		}
#if defined(COMPILE_DEBUG)
		debug(2, "PassiveRange for %s: %u-%u", ctx->cli_ctrl->peer,
		         ctx->pas_lrng, ctx->pas_urng);
#endif
	}

	/*
	** Setup other configuration options
	*/
	p = ldap_attrib(ld, e, "SameAddress", NULL);
	if(NULL != p) {
		if (strcasecmp(p, "y") == 0)
			ctx->same_adr = 1;
		else if (strcasecmp(p, "on") == 0)
			ctx->same_adr = 1;
		else if (strcasecmp(p, "yes") == 0)
			ctx->same_adr = 1;
		else if (strcasecmp(p, "true") == 0)
			ctx->same_adr = 1;
		else if (*p >= '0' && *p <= '9')
			ctx->same_adr = (atoi(p) != 0);
		else
			ctx->same_adr = 0;
#if defined(COMPILE_DEBUG)
		debug(2, "SameAddress for %s: %s", ctx->cli_ctrl->peer,
		         ctx->same_adr ? "yes" : "no");
#endif
	}

// Fred Patch Add Timeout in ftpclient.c

	p = ldap_attrib(ld, e, "TimeOut", "900");
	if(NULL != p) {
		if (*p >= '0' && *p <= '9')
		ctx->timeout = atoi(p);
	else
		ctx->timeout = 900;

#if defined(COMPILE_DEBUG)
	debug(2, "TimeOut for %s: %d", ctx->cli_ctrl->peer,
	ctx->timeout);
#endif
}
/*
** Adjust the allow/deny flags for the commands
*/

	p = ldap_attrib(ld, e, "ValidCommands", NULL);
	if(NULL != p) {
		cmds_set_allow(p);
	}

	/*
	** All relevant attributes have been evaluated
	*/
	ldap_msgfree(result);

	return 0;
}


/* ------------------------------------------------------------ **
**
**	Function......:	ldap_auth
**
**	Parameters....:	ld		Pointer to LDAP struct
**			e		Pointer to result buffer
**			who		Pointer to user name
**			pwd		Pointer to user pwd
**
**	Return........:	0 on success
**
**	Purpose.......: Preform LDAP userauth
**
** ------------------------------------------------------------ */

static int   ldap_auth(LDAP *ld, LDAPMessage *e, char *who, char *pwd, CONTEXT *ctx )
{
	char str[MAX_PATH_SIZE];
	char *v, *p, *q;
	size_t len;
	int    xrc = 0;
        /* Basic sanity */
        if(ctx == NULL || ld == NULL || who == NULL) {
                if(ld) ldap_unbind(ld);
                misc_die(FL, "ldap_fetch: ?ctx? ?ld? ?who?");
         }

	if (ld == NULL || e == NULL)
		misc_die(FL, "ldap_checkauth: ?ld? ?e?");

	/*
	** check "user enabled" flag if present
	*/
	if( (p = config_str(NULL, "LDAPAuthOKFlag", NULL))) {
		misc_strncpy(str, p, sizeof(str));
		if( (v = strchr(str, '=')))
			*v++ = '\0';
		else	v = 0;

		if(v && strlen(v) && strlen(str)) {
			if(0 != ldap_exists(ld, e, str, v, 0)) {
				syslog_write(U_WRN,
				"access denied for %s", NIL(who));
				return -1;
			} else {
				syslog_write(T_DBG,
				"LDAP auth ok-check: '%.256s'='%.256s' passed",
				NIL(str), NIL(v));
				xrc = 1;
			}
		} else {
			errno = 0;
			misc_die(FL, "ldap_auth: ?LDAPAuthOKFlag?");
		}
	} else {
		syslog_write(T_DBG, "[ %s ] LDAP auth ok-check skipped",ctx->cli_ctrl->peer);
		// Patch Fred 1 partie //
		patch_ldapgroup(ld,who,ctx);
	}

	/*
	** check user pass match
	*/

	if( (p = config_str(NULL, "LDAPAuthPWAttr", "")) && strlen(p)) {
		if(NULL == pwd)
			pwd = "";
			return -1;
					
		v   = config_str(NULL, "LDAPAuthPWType", "plain");
		q   = ldap_attrib(ld, e, p, "");
		p   = 0;
		len = 0;

		if( !strncasecmp(v, "plain", sizeof("plain")-1)) {
			/*
			** plain passwd - no prefix
			*/
			len = sizeof("plain")-1;
			p   = pwd;
#if defined(HAVE_CRYPT)
		} else
		if( !strncasecmp(v, "crypt", sizeof("plain")-1)) {
			/*
			** crypt - no prefix
			*/
			len = sizeof("plain")-1;
			p   = crypt(pwd, q);
		} else
		if( !strncasecmp(v, "{crypt}", sizeof("{crypt}")-1)) {
			/*
			** crypt - {crypt} prefix
			*/
			len = sizeof("{crypt}")-1;
			if(strncasecmp(q, "{crypt}", len)) {
				syslog_write(T_ERR,
				             "ldap user auth - prefix missed");
				return -1;
			}
			q+=len;
			p = crypt(pwd, q);
#endif
		} else {
			errno = 0;
			misc_die(FL, "ldap_auth: ?LDAPAuthPWType?");
		}

		/*
		** check if we have different minimal length
		** it is coded in latest "char", i.e. plain9
		*/
		if(0 < len && strlen(v) == len+1 &&
		   '0' <= v[len] && '9' >= v[len])
		{
			len = (size_t)v[len] - '0';
		} else	len = PASS_MIN_LEN;

		syslog_write(T_DBG, "LDAP auth pw-type[%d]='%.256s'", len, v);
#if defined(COMPILE_DEBUG)
		debug(3,            "LDAP auth pw-check: '%.256s' ?= '%.256s'",
		                    NIL(q), NIL(p));
#endif

		/*
		** check (lenght) and compare passwds; the user
		** account is locked if LDAP-PWD is "*" or "!"
		*/
		if(p && strlen(p)>=len && strlen(q) == strlen(p) &&
		   !(1==strlen(q) && ('*' == q[0] || '!' == q[0])))
		{
			if(0 == strcmp(q, p)) {
				syslog_write(T_DBG,
				             "[ %s ] LDAP auth pw-check succeed", ctx->cli_ctrl->peer );
				return xrc + 2;
			}
		}
		syslog_write(T_DBG, "[ %s ] LDAP auth pw-check failed", ctx->cli_ctrl->peer);
		return -1;
	} else {
		syslog_write(T_DBG, "[ %s ] LDAP auth pw-check skipped", ctx->cli_ctrl->peer);
	}

	/*
	** OK, all configured manual LDAPAuth checks succeed...
	*/

	return xrc;
}


/* ------------------------------------------------------------ **
**
**	Function......:	ldap_attrib
**
**	Parameters....:	ld		Pointer to LDAP struct
**			e		Pointer to result buffer
**			attr		Name of desired option
**			dflt		Default value
**
**	Return........:	Value for attr (or dflt if not found)
**
**	Purpose.......: Search the LDAP result message for the
**			desired attribute value and return it.
**			NEVER return a NULL pointer except if
**			the dflt was taken and is NULL itself.
**
** ------------------------------------------------------------ */

static char *ldap_attrib(LDAP *ld, LDAPMessage *e, char *attr, char *dflt)
{
	static char str[MAX_PATH_SIZE];
	char **vals;

	if (ld == NULL || e == NULL || attr == NULL)
		misc_die(FL, "ldap_attrib: ?ld? ?e? ?attr?");

	/*
	** See if this attribute has values available
	*/
	if ((vals = ldap_get_values(ld, e, attr)) == NULL) {
#if defined(COMPILE_DEBUG)
		debug(3, "LDAP result: '%.256s' - '%.1024s'",
						attr, NIL(dflt));
#endif
		return dflt;
	}

	/*
	** Save value (use the first one) and free memory
	*/
	misc_strncpy(str, vals[0], sizeof(str));
	ldap_value_free(vals);

#if defined(COMPILE_DEBUG)
	debug(3, "LDAP result: '%.256s' = '%.1024s'", attr, str);
#endif
	return str;
}


/* ------------------------------------------------------------ **
**
**	Function......:	ldap_exists
**
**	Parameters....:	ld		Pointer to LDAP struct
**			e		Pointer to result buffer
**			attr		Name of desired option
**			vstr		Value of desired option
**			cs		1 for case sensitive check
**
**	Return........:	0 if value found
**
**	Purpose.......: Search the LDAP result message for the
**			desired (multivalue) attribute and check
**			if it contains a value string.
**
** ------------------------------------------------------------ */

static int  ldap_exists(LDAP *ld, LDAPMessage *e, char *attr,
                                                  char *vstr, int cs)
{
	char **vals;
	int    count, at;

	if (ld == NULL || e == NULL || attr == NULL || vstr == NULL)
		misc_die(FL, "ldap_exists: ?ld? ?e? ?attr? ?vstr?");

	/*
	** See if this attribute has values available
	*/
	if ((vals = ldap_get_values(ld, e, attr)) == NULL) {
#if defined(COMPILE_DEBUG)
		debug(3, "LDAP result: no values for '%.256s'", attr);
#endif
		return -1;
	}

	count = ldap_count_values(vals);
	if(cs) {
		for(at=0; at < count; at++) {
#if defined(COMPILE_DEBUG)
		debug(3, "LDAP result: checking[%d:%d] '%.256s'='%.1024s'",
		                              count-1, at, attr, vals[at]);
#endif
			if(misc_strequ(vals[at], vstr)) {
				ldap_value_free(vals);
				return 0;
			}
		}
	} else {
		for(at=0; at < count; at++) {
#if defined(COMPILE_DEBUG)
		debug(3, "LDAP result: checking[%d:%d] '%.256s'='%.1024s'",
		                              count-1, at, attr, vals[at]);
#endif
			if(misc_strcaseequ(vals[at], vstr)) {
				ldap_value_free(vals);
				return 0;
			}
		}
	}
	ldap_value_free(vals);

#if defined(COMPILE_DEBUG)
		debug(3, "LDAP result: '%.256s'='%.1024s' not found",
		                       attr, vstr);
#endif

	return 1;
}
#endif

/* -------------------------------
Fred-B Patch Ldap Group
--------------------------------*/ 

#if defined(HAVE_LIBLDAP)
void patch_ldapgroup(LDAP *ld, char *who, CONTEXT *ctx)
{

	char *BASE; 	 
	char *BASE_DN;
	LDAPMessage *result;
	int rc;
	int resultldap;
	char *attrib[] = {0, 0};
	attrib[0]="cn";
	char *FIN = "))";
	char *VIRGULE = ",";
	
	# define MAX_CAR_FILTRE 100

	BASE_DN = config_str(NULL, "LDAPBaseDN", NULL);
	if (NULL == BASE_DN) {
		return;
	}

	
	BASE = config_str(who, "BASE", NULL);
	if (NULL == BASE) {
		return;
	}

	char * FILTRE_LU = config_str(who, "FILTER", NULL);
		
	if (NULL == FILTRE_LU) {
		return;
	}

	char FILTRE1[MAX_CAR_FILTRE]; FILTRE1[MAX_CAR_FILTRE+1] = '\0';
	char *FILTRE;			 
	FILTRE = FILTRE1; 

	
	if (FILTRE_LU != NULL)
	{
	strncpy(FILTRE, FILTRE_LU,MAX_CAR_FILTRE);
	FILTRE[MAX_CAR_FILTRE+1] = '\0';
	}
	
	strncat(FILTRE, who, (MAX_CAR_FILTRE)- strlen(FILTRE));
	strncat(FILTRE, VIRGULE, (MAX_CAR_FILTRE)- strlen(FILTRE));
	strncat(FILTRE, BASE_DN, (MAX_CAR_FILTRE)- strlen(FILTRE));
	strncat(FILTRE, FIN, (MAX_CAR_FILTRE)- strlen(FILTRE));
	
	syslog_write(U_INF, "");
	syslog_write(U_INF,"[ %s ] Patch Fred-B LDAP Ldap Group", ctx->cli_ctrl->peer);
	syslog_write(U_INF,"[ %s ] Filter Ldap_group : %s", ctx->cli_ctrl->peer, FILTRE1); 

	rc = ldap_search_s(ld,BASE,LDAP_SCOPE_SUBTREE,FILTRE,attrib,0,&result);

	if (rc != LDAP_SUCCESS )
	   {
 	    syslog_write(T_ERR, "ldap_search_ext: %s\n", ldap_err2string(rc));
	    ldap_unbind(ld);
	    exit(1);
	    }

	resultldap = ldap_count_entries(ld,result);

	if (resultldap == 0)
	{
		syslog_write(T_ERR,"[ %s ] Bad Group User %s",ctx->cli_ctrl->peer, who);
		syslog_write(T_ERR,"[ %s ] Exit patch ldap_group \n", ctx->cli_ctrl->peer);
		exit(-1);
	}
	else
	{
		syslog_write(U_INF,"[ %s ] Group ldap ok %s", ctx->cli_ctrl->peer, who);
		syslog_write(U_INF,"[ %s ] Exit patch ldap_group \n", ctx->cli_ctrl->peer);
	}		

 }

#endif

/* ------------------------------------------------------------
 * $Log: ftp-ldap.c,v $
 * Revision 1.7.2.3  2004/03/10 16:07:13  mt
 * added LDAPPreBindDN/LDAPPreBindPW options usable
 * instead of anonymous bind while LDAPBindDN=auto
 *
 * Revision 1.7.2.2  2003/05/11 20:22:17  mt
 * simplyfied ldap version handling
 *
 * Revision 1.7.2.1  2003/05/07 11:10:00  mt
 * moved user profile-config reading to ftp-client.c
 * added LDAP_VERSION handling with LDAPv3 default
 * improved user-auth to support auth via ldap-bind
 *
 * Revision 1.7  2002/05/02 13:17:12  mt
 * implemented simple (ldap based) user auth
 *
 * Revision 1.6  2002/01/14 19:26:38  mt
 * implemented bind_dn and pwd authorized ldap_simple_bind
 * fixed ld_errno fetching macro to work with openldap 2.x
 *
 * Revision 1.5  2001/11/06 23:04:44  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
 *
 * Revision 1.4  1999/09/24 06:38:52  wiegand
 * added regular expressions for all commands
 * removed character map and length of paths
 * added flag to reset PASV on every PORT
 * added "magic" user with built-in destination
 * added some argument pointer fortification
 *
 * Revision 1.3  1999/09/21 07:14:43  wiegand
 * syslog / abort cleanup and review
 * default PASV port range to 0:0
 *
 * Revision 1.2  1999/09/17 16:32:29  wiegand
 * changes from source code review
 * added POSIX regular expressions
 *
 * Revision 1.1  1999/09/15 14:06:22  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */
