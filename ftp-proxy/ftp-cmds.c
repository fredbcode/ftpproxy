/*
 * $Id: ftp-cmds.c,v 1.10.2.2 2004/03/10 16:00:49 mt Exp $
 *
 * FTP Proxy command handling
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
static char rcsid[] = "$Id: ftp-cmds.c,v 1.10.2.2 2004/03/10 16:00:49 mt Exp $";
#endif

#include <config.h>

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

#if defined(HAVE_REGEX)
#  include <sys/types.h>
#  include <regex.h>
#endif

#include "com-config.h"
#include "com-debug.h"
#include "com-misc.h"
#include "com-socket.h"
#include "com-syslog.h"
#include "ftp-client.h"
#include "ftp-cmds.h"


/* ------------------------------------------------------------ */

static void cmds_pthr(CONTEXT *ctx, char *arg);
static void cmds_user(CONTEXT *ctx, char *arg);
static void cmds_pass(CONTEXT *ctx, char *arg);
static void cmds_quit(CONTEXT *ctx, char *arg);
static void cmds_rein(CONTEXT *ctx, char *arg);
static void cmds_port(CONTEXT *ctx, char *arg);
static void cmds_pasv(CONTEXT *ctx, char *arg);
static void cmds_xfer(CONTEXT *ctx, char *arg);
static void cmds_abor(CONTEXT *ctx, char *arg);
#if defined(ENABLE_SSL) /* <!-- SSL --> */
static void cmds_auth(CONTEXT *ctx, char *arg);
#endif /* <!-- /SSL --> */
#if defined(ENABLE_RFC1579)
static void cmds_apsv(CONTEXT *ctx, char *arg);
#endif
#if defined(ENABLE_RFC2428)
static void cmds_eprt(CONTEXT *ctx, char *arg);
static void cmds_epsv(CONTEXT *ctx, char *arg);
#endif


/* ------------------------------------------------------------ */

static int  parse_magic_dest(CONTEXT *ctx, char *dest);
static int  parse_magic_user(CONTEXT *ctx, char *uarg,
                             char a_sep, int a_first,
                             char u_sep, int u_force);

/* ------------------------------------------------------------ */

#if defined(HAVE_REGEX)
#  define REST		NULL, 0, 0
#else
#  define REST		0, 0
#endif

static CMD cmdlist[] = {
	{ "USER", cmds_user, REST },	/* Access control	*/
	{ "PASS", cmds_pass, REST },
	{ "ACCT", cmds_pthr, REST },
	{ "CWD",  cmds_pthr, REST },
	{ "CDUP", cmds_pthr, REST },
	{ "SMNT", cmds_pthr, REST },
	{ "QUIT", cmds_quit, REST },
	{ "REIN", cmds_rein, REST },
	{ "PORT", cmds_port, REST },	/* Transfer parameter	*/
	{ "PASV", cmds_pasv, REST },
	{ "TYPE", cmds_pthr, REST },
	{ "STRU", cmds_pthr, REST },
	{ "MODE", cmds_pthr, REST },
	{ "RETR", cmds_xfer, REST },	/* FTP service		*/
	{ "STOR", cmds_xfer, REST },
	{ "STOU", cmds_xfer, REST },
	{ "APPE", cmds_xfer, REST },
	{ "ALLO", cmds_pthr, REST },
	{ "REST", cmds_pthr, REST },
	{ "RNFR", cmds_pthr, REST },
	{ "RNTO", cmds_pthr, REST },
	{ "ABOR", cmds_abor, REST },
	{ "DELE", cmds_pthr, REST },
	{ "RMD",  cmds_pthr, REST },
	{ "MKD",  cmds_pthr, REST },
	{ "PWD",  cmds_pthr, REST },
	{ "LIST", cmds_xfer, REST },
	{ "NLST", cmds_xfer, REST },
	{ "SITE", cmds_pthr, REST },
	{ "SYST", cmds_pthr, REST },
	{ "STAT", cmds_pthr, REST },
	{ "HELP", cmds_pthr, REST },
	{ "NOOP", cmds_pthr, REST },
	{ "SIZE", cmds_pthr, REST },	/* Not found in RFC 959	*/
	{ "MDTM", cmds_pthr, REST },
	{ "MLFL", cmds_pthr, REST },
	{ "MAIL", cmds_pthr, REST },
	{ "MSND", cmds_pthr, REST },
	{ "MSOM", cmds_pthr, REST },
	{ "MSAM", cmds_pthr, REST },
	{ "MRSQ", cmds_pthr, REST },
	{ "MRCP", cmds_pthr, REST },
	{ "XCWD", cmds_pthr, REST },
	{ "XMKD", cmds_pthr, REST },
	{ "XRMD", cmds_pthr, REST },
	{ "XPWD", cmds_pthr, REST },
	{ "XCUP", cmds_pthr, REST },
	{ "RCMD", cmds_pthr, REST },
#if defined(ENABLE_SSL) /* <!-- SSL --> */
	{ "AUTH", cmds_auth, REST },	/* Only needed for SSL	*/
#endif /* <!-- /SSL --> */
#if defined(ENABLE_RFC1579)
	{ "APSV", cmds_apsv, REST },	/* As per RFC 1579	*/
#endif
#if defined(ENABLE_RFC2428)
	{ "EPRT", cmds_eprt, REST },	/* As per RFC 2428	*/
	{ "EPSV", cmds_epsv, REST },
#endif
	{ NULL,   NULL,      REST }
};


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_get_list
**
**	Parameters....:	(none)
**
**	Return........:	Pointer to command list
**
**	Purpose.......: Make command list known to others.
**
** ------------------------------------------------------------ */

CMD *cmds_get_list(void)
{
	return cmdlist;
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_set_allow
**
**	Parameters....:	allow		List of allowd commands
**					(comma/space delimited)
**
**	Return........:	(none)
**
**	Purpose.......: Setup allowed/forbidden command flags
**			according to a "ValidCommands" config
**			string (from file or LDAP Server).
**
** ------------------------------------------------------------ */

void cmds_set_allow(char *allow)
{
	CMD *cmd;
	char *p, *q;
	int i;

	/*
	** Base line: if no option is given, then anything
	**   is allowed. But if there is one, everything
	**   is forbidden except those items on the list.
	*/
	if (allow == NULL) {
		for (cmd = cmdlist; cmd->name != NULL; cmd++) {
#if defined(HAVE_REGEX)
			if (cmd->regex != NULL) {
				regfree((regex_t *) cmd->regex);
				misc_free(FL, cmd->regex);
				cmd->regex = NULL;
			}
#endif
			cmd->legal = 1;
			cmd->len   = strlen(cmd->name);
		}
#if defined(COMPILE_DEBUG)
		debug(2, "allowed: '(all)'");
#endif
		return;
	}

	/*
	** Initially deny everything
	*/
	for (cmd = cmdlist; cmd->name != NULL; cmd++) {
#if defined(HAVE_REGEX)
		if (cmd->regex != NULL) {
			regfree((regex_t *) cmd->regex);
			misc_free(FL, cmd->regex);
			cmd->regex = NULL;
		}
#endif
		cmd->legal = 0;
		cmd->len   = strlen(cmd->name);
	}

	/*
	** Scan the allow list and enable accordingly
	*/
	for (p = allow; *p != '\0'; ) {
		while (*p != '\0' && isalpha((int)*p) == 0)
			p++;
		if (*p == '\0')
			break;
		for (q = p, i = 0; isalpha((int)*q); q++, i++)
			;
		for (cmd = cmdlist; cmd->name; cmd++) {
			if (cmd->len != i)
				continue;
			if (strncasecmp(cmd->name, p, i) != 0)
				continue;
			cmd->legal = 1;
#if defined(HAVE_REGEX)
			if (*q == '=') {	/* RegEx to follow? */
				char *r;
				r = cmds_reg_comp(&(cmd->regex), ++q);
#if defined(COMPILE_DEBUG)
				debug(2, "allowed: '%s' -> '%s'",
						cmd->name, NIL(r));
#endif
				while (*q && *q != ' ' && *q != '\t')
					q++;
				break;
			}
#endif
#if defined(COMPILE_DEBUG)
			debug(2, "allowed: '%s'", cmd->name);
#endif
			break;
		}
		p = q;
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_pthr
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon pass-through FTP commands.
**
** ------------------------------------------------------------ */

static void cmds_pthr(CONTEXT *ctx, char *arg)
{
	char *cmd;

	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_pthr: ?ctx?");
	if ((cmd = ctx->curr_cmd) == NULL)
		misc_die(FL, "cmds_pthr: ?curr_cmd?");

	if (ctx->srv_ctrl == NULL) {
		client_respond(530, NULL, "Not logged in");
		syslog_write(U_WRN, "[ %s ] '%s' without login from %s",
				ctx->cli_ctrl->peer,cmd, ctx->cli_ctrl->peer);
		return;
	}

	if (arg == NULL || *arg == '\0') {
		socket_printf(ctx->srv_ctrl, "%s\r\n", cmd);
		syslog_write(U_INF, "[ %s ] '%s' from %s",
					ctx->cli_ctrl->peer, cmd, ctx->cli_ctrl->peer);
	} else {
		socket_printf(ctx->srv_ctrl, "%s %.1024s\r\n", cmd, arg);
		syslog_write(U_INF, "[ %s ] '%s %.1024s' from %s",
					ctx->cli_ctrl->peer, cmd, arg, ctx->cli_ctrl->peer);
	}

	ctx->expect = EXP_PTHR;		/* Expect Response	*/
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_user
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'USER' command.
**
** ------------------------------------------------------------ */

static void cmds_user(CONTEXT *ctx, char *arg)
{
	CMD  *cmd;

	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_user: ?ctx?");

	/*
	** Check for the user name
	*/
	if (arg == NULL || *arg == '\0') {
		client_respond(501, NULL, "Missing user name");
		syslog_write(U_WRN, "[ %s ] 'USER' without name from %s",
				ctx->cli_ctrl->peer,ctx->cli_ctrl->peer);
		return;
	}

	/*
	** Abort any previous service
	*/
	client_reinit();

#if defined(HAVE_REGEX)
	/*
	** Check for a RegEx constraint on the USER command
	*/
	cmds_set_allow(config_str(NULL, "ValidCommands", NULL));
	for (cmd = cmdlist; cmd->name != NULL; cmd++) {
		char *p;
		if (strcasecmp("USER", cmd->name) != 0)
			continue;
		if (cmd->regex == NULL)
			break;
		if ((p = cmds_reg_exec(cmd->regex, arg)) != NULL) {
			client_respond(501, NULL,
				"'USER': syntax error in arguments");
			syslog_write(U_WRN,
				"[ %s ] bad arg '%.128s'%s for "
				"'USER' from %s: %s", ctx->cli_ctrl->peer, arg,
				(strlen(arg) > 128) ?  "..." : "",
				ctx->cli_ctrl->peer, p);
			return;
		}
		break;
	}
#endif


	/*
	** Check for permission and existence of "transparent proxy"
	** magic destination address and port from the client socket
	**
	** "fall through" on error and proceed to check magic user
	** or use DestinationAddress from config...
	*/
	ctx->magic_addr = INADDR_ANY;
	ctx->magic_port = INPORT_ANY;

	if(config_bool(NULL, "AllowTransProxy", 0)) {
		u_int32_t addr = INADDR_ANY;
		u_int16_t port = INPORT_ANY;

		if(!socket_orgdst(ctx->cli_ctrl, &addr, &port) &&
		   INADDR_ANY != addr && INADDR_NONE != addr &&
		   INPORT_ANY != port)
		{
			/*
			** check if destination is a local IP;
			** ignore to loop-protection...
			*/
			int rc = socket_chkladdr(addr);

			switch( rc) {
			case -1:
				syslog_write(T_ERR,
				"check of transparent destination failed");
			break;
			case 0:
				ctx->magic_addr = ntohl(addr);
				ctx->magic_port = ntohs(port);
				syslog_write(T_INF,
				"transparent proxy request to %s:%d from %s",
				socket_addr2str(ctx->magic_addr),
				ctx->magic_port, ctx->cli_ctrl->peer);
			break;
			default:
			syslog_write(T_DBG,
				"requested transparent destination %s is local",
				socket_addr2str(ntohl(addr)));
			break;
			}
		} else {
			syslog_write(T_DBG,
				"no transparent proxy destination found");
		}
	}

	/*
	** Check if we need auth and should use the auth-user mode
	*/
	if(NULL != config_str(NULL, "UserAuthType", NULL)) {
		ctx->auth_mode = UAUTH_FTP;
		ctx->magic_auth = config_str(NULL, "UserAuthMagic", NULL);
		if(NULL != ctx->magic_auth) {
			if( sizeof("auth") != strlen(ctx->magic_auth)) {
				syslog_write(T_ERR, "invalid UserAuthMagic");
				client_respond(530, NULL, "Not logged in");
				client_reinit();
				return;
			}
			if(strncasecmp(ctx->magic_auth, "auth", sizeof("auth")-1))
				ctx->auth_mode = UAUTH_MUA; /* user%auth */
			else
				ctx->auth_mode = UAUTH_MAU; /* auth%user */
		}
	}

	/*
	** Check if we have to parse 'auth' user name...
	*/
	if(NULL != ctx->magic_auth) {
		int   is_ok = 1;
		char  a_sep = ctx->auth_mode == UAUTH_MAU
		            ? ctx->magic_auth[sizeof("auth")-1]
		            : ctx->magic_auth[0];
#if defined(COMPILE_DEBUG)
		debug(2, "parsing '%s' using auth-magic '%.512s'",
			arg, ctx->magic_auth);
#endif

		if(config_bool(NULL, "ForceMagicUser", 0) != 0) {
			char *u_sep = config_str(NULL, "UserMagicChar",
			              config_str(NULL, "UseMagicChar", "@"));
			is_ok = parse_magic_user(ctx, arg,   a_sep,
			                         ctx->auth_mode == UAUTH_MAU,
			                         u_sep[0], 1);
		} else
		if(config_bool(NULL, "AllowMagicUser", 0) != 0) {
			char *u_sep = config_str(NULL, "UserMagicChar",
			              config_str(NULL, "UseMagicChar", "@"));
			is_ok = parse_magic_user(ctx, arg,   a_sep,
			                         ctx->auth_mode == UAUTH_MAU,
			                         u_sep[0], 0);
		} else {
			is_ok = parse_magic_user(ctx, arg,   a_sep,
			                         ctx->auth_mode == UAUTH_MAU,
			                         0,        0);
		}

		if(is_ok || NULL == ctx->userauth || NULL == ctx->username ||
		            '\0' == ctx->userauth || '\0' == ctx->username) {
			if(1 == is_ok) {
				syslog_write(U_ERR,
				             "[ %s ] missed magic dest in 'USER' from %s", ctx->cli_ctrl->peer,
				             ctx->cli_ctrl->peer);
			} else {
				syslog_write(U_ERR,
				             "[ %s ] invalid magic in 'USER' from %s, bad Server name ?", ctx->cli_ctrl->peer,
				             ctx->cli_ctrl->peer);
			}
			client_respond(530, NULL, "Not logged in");
			client_reinit();
			return;
		}
	} else {
		/*
		** USER="user[<u_sep>host[:port]]"
		*/
		if(config_bool(NULL, "ForceMagicUser", 0) != 0) {
			char *p, *u_sep = config_str(NULL, "UserMagicChar",
			                  config_str(NULL, "UseMagicChar", "@"));
			if( (p = strrchr(arg, u_sep[0]))) {
				*p++ = '\0';
				if(-1 == parse_magic_dest(ctx, p)) {
					syslog_write(U_ERR,
					             "[ %s ] invalid magic in 'USER' from %s", ctx->cli_ctrl->peer,
					             ctx->cli_ctrl->peer);
					client_respond(530, NULL,
					               "Not logged in");
					client_reinit();
					return;
				}
			} else {
				syslog_write(U_ERR,
					"[ %s ] magic dest missed in 'USER' from %s", ctx->cli_ctrl->peer,
					ctx->cli_ctrl->peer);
				client_respond(530, NULL, "Not logged in");
				client_reinit();
				return;
			}
		} else
		if(config_bool(NULL, "AllowMagicUser", 0) != 0) {
			char *p, *u_sep = config_str(NULL, "UserMagicChar",
			                  config_str(NULL, "UseMagicChar", "@"));
			if( (p = strrchr(arg, u_sep[0]))) {
				*p++ = '\0';
				if(-1 == parse_magic_dest(ctx, p)) {
					syslog_write(U_ERR,
					             "[ %s ] invalid magic in 'USER' from %s", ctx->cli_ctrl->peer,
					             ctx->cli_ctrl->peer);
					client_respond(530, NULL,
					               "Not logged in");
					client_reinit();
					return;
				}
			}
		}
		ctx->username = misc_strdup(FL, arg);
		if(NULL == ctx->username || '\0' == ctx->username) {
			client_respond(501, NULL, "Missing user name");
			syslog_write(U_WRN, "[ %s ] 'USER' without name from %s", ctx->cli_ctrl->peer,
			                    ctx->cli_ctrl->peer);
			return;
		}
	}

	/*
	** Retrieve the relevant user information
	*/
	if (ctx->magic_addr != INADDR_ANY &&
	    ctx->magic_addr != INADDR_NONE)
	{
		syslog_write(U_INF, "[ %s ] 'USER %s' dest %s:%d from %s", ctx->cli_ctrl->peer,
				arg, socket_addr2str(ctx->magic_addr),
				(int)ctx->magic_port, ctx->cli_ctrl->peer);
	} else
	if(config_str(NULL, "DestinationAddress", NULL) == NULL) {
		syslog_write(U_ERR, "[ %s ] unknown destination address", ctx->cli_ctrl->peer);
		client_respond(501, NULL,"Unknown destination address");
		client_reinit();
		return;
	} else {
		syslog_write(U_INF, "[ %s ] 'USER %s' from %s",ctx->cli_ctrl->peer,
				arg, ctx->cli_ctrl->peer);
	}

	if(UAUTH_NONE != ctx->auth_mode) {
		/*
		** anable PASS command only...
		*/
		cmds_set_allow("PASS");

		/*
		** hmm... a USER name is there, but we need
		** PASS+auth as well, because it may be needed
		** for auth itself and for profile reading...
		*/
		client_respond(331, NULL, "User name okay, need password.");
	} else {
		/*
		** read user's profile, connect the server
		*/
		if(0 == client_setup(NULL)) {
			client_srv_open();
		} else {
			/*
			** FIXME: client_respond required? checkit!!
			*/
			client_respond(530, NULL, "Not logged in");
			client_reinit();
		}
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_pass
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'PASS' command.
**
** ------------------------------------------------------------ */

static void cmds_pass(CONTEXT *ctx, char *arg)
{
	char *pass = NULL, *q = NULL;

	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_pass: ?ctx?");

	/*
	** inform auditor...
	*/
	syslog_write(U_INF, "[ %s ] 'PASS XXXX' from %s",ctx->cli_ctrl->peer, ctx->cli_ctrl->peer);
	/*
	** should never be NULL, but ...
	** if no password supplied, send none either
	*/
	if(NULL == arg)
		pass = "";
	else
		pass = arg;

	/*
	** Check if we are in auth mode...
	*/
	if(UAUTH_NONE != ctx->auth_mode) {
		/*
		** Check if we should do auth using
		** the normal FTP PASS comand.
		*/
		if(UAUTH_FTP == ctx->auth_mode) {
			ctx->userpass = misc_strdup(FL, pass);
		} else
		/*
		** Check if have to parse for magic
		** auth pass in the FTP PASS command.
		*/
		if(NULL != ctx->magic_auth && pass[0] != '\0') {
			if(ctx->auth_mode == UAUTH_MAU) {
				q = strchr(pass, ctx->magic_auth[sizeof("auth")-1]);
				if(NULL != q) {
					*q++ = '\0';
					ctx->userpass = misc_strdup(FL, q);
				}
			} else {
				q = strrchr(pass, ctx->magic_auth[0]);
				if(NULL != q) {
					*q++ = '\0';
					ctx->userpass = misc_strdup(FL, pass);
					pass          = q;
				}
			}
			if(NULL == q) {
				syslog_write(U_ERR,
				             "invalid magic in 'PASS' from %s",
				             ctx->cli_ctrl->peer);
				client_respond(530, NULL, "Not logged in");
				client_reinit();
				return;
			}
		}

		/*
		** OK, we have all data to auth user, read his
		** proxy-profile (if any) and connect to server
		*/
		if(0 == client_setup(pass)) {
			client_srv_open();
		} else {
			client_respond(530, NULL, "Not logged in");
			client_reinit();
		}
	} else {
		/*
		** paranoia check...
		*/
		if (ctx->srv_ctrl == NULL) {
			client_respond(530, NULL, "Not logged in");
			syslog_write(U_WRN, "'PASS' without login from %s",
			             ctx->cli_ctrl->peer);
			return;
		}

		/*
		** Send to server, but do not display
		*/
		socket_printf(ctx->srv_ctrl, "PASS %.1024s\r\n", pass);
		syslog_write(U_INF, "'PASS XXXX' from %s",
		             ctx->cli_ctrl->peer);

		/* Expect Response */
		ctx->expect = EXP_PTHR;
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_rein
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'REIN' command.
**
** ------------------------------------------------------------ */

static void cmds_rein(CONTEXT *ctx, char *arg)
{
	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_rein: ?ctx?");
	arg = arg;		/* Calm down picky compilers	*/

	syslog_write(U_INF, "'REIN' from %s", ctx->cli_ctrl->peer);

	/*
	** Abort any running service
	*/
	client_reinit();
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_quit
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'QUIT' command.
**
** ------------------------------------------------------------ */

static void cmds_quit(CONTEXT *ctx, char *arg)
{
	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_quit: ?ctx?");
	arg = arg;		/* Calm down picky compilers	*/

	/*
	** Close all dependent connections
	*/
	if (ctx->srv_data != NULL) {
		socket_kill(ctx->srv_data);
		ctx->srv_data = NULL;
	}
	if (ctx->cli_data != NULL) {
		socket_kill(ctx->cli_data);
		ctx->cli_data = NULL;
	}
	if (ctx->srv_ctrl != NULL) {
		socket_printf(ctx->srv_ctrl, "QUIT\r\n");
		ctx->srv_ctrl->kill = 1;
	}

	/*
	** Say good-bye
	*/
	client_respond(221, NULL, "Goodbye");
	syslog_write(U_INF, "[ %s ] 'QUIT' from %s", ctx->cli_ctrl->peer, ctx->cli_ctrl->peer);
	ctx->expect = EXP_IDLE;
	ctx->cli_ctrl->kill = 1;
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_port
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'PORT' command.
**
** ------------------------------------------------------------ */

static void cmds_port(CONTEXT *ctx, char *arg)
{
	int h1, h2, h3, h4, p1, p2;
	u_int32_t addr;
	u_int16_t port;
	char *peer;

	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_port: ?ctx?");

	/*
	** Evaluate the arguments
	*/
	if (arg == NULL || sscanf(arg, "%d,%d,%d,%d,%d,%d",
			&h1, &h2, &h3, &h4, &p1, &p2) != 6 ||
			h1 < 0 || h1 > 255 || h2 < 0 || h2 > 255 ||
			h3 < 0 || h3 > 255 || h4 < 0 || h4 > 255 ||
			p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255) {
		client_respond(501, NULL, "Syntax error in arguments");
		syslog_write(U_WRN,
			"syntax error in 'PORT' from %s",
			ctx->cli_ctrl->peer);
		client_data_reset(MOD_RESET);
		return;
	}
	addr = (h1 << 24) + (h2 << 16) + (h3 << 8) + h4;
	port = (p1 <<  8) +  p2;
	peer = socket_addr2str(addr);

	/*
	** If requested, validate the IP address
	*/
	if (ctx->same_adr != 0 && addr != ctx->cli_ctrl->addr) {
		client_respond(501, NULL,
			"PORT address does not match originator");
		syslog_write(U_WRN,
			"different address in 'PORT' from %s",
			ctx->cli_ctrl->peer);
		client_data_reset(MOD_RESET);
		return;
	}

	/*
	** The common behaviour seems to be that PORT cancels
	** a previous PASV. Hmmm, we do it only on "request".
	*/
	if (config_bool(NULL, "PortResetsPasv", 1)) {
		if (ctx->cli_data != NULL) {
			syslog_write(U_WRN,
				"killing old PASV socket for %s",
				ctx->cli_ctrl->peer);
			socket_kill(ctx->cli_data);
			ctx->cli_data = NULL;
		}
		ctx->cli_mode = MOD_ACT_FTP;
	}

	/*
	** All is well, memorize and respond.
	*/
	ctx->cli_addr = addr;
	ctx->cli_port = port;

	client_respond(200, NULL, "PORT command successful");
	syslog_write(U_INF, "[ %s ] 'PORT %s:%d' from %s",
			ctx->cli_ctrl->peer, peer, (int) port, ctx->cli_ctrl->peer);
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_pasv
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'PASV' command. The BSD
**			ftpd.c source says that the 425 code
**			has been "blessed by Jon Postel".
**
** ------------------------------------------------------------ */

static void cmds_pasv(CONTEXT *ctx, char *arg)
{
	u_int32_t addr;
	u_int16_t port;
	char str[1024], *p, *q;
	FILE *fp;
	int  incr;

	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_pasv: ?ctx?");
	arg = arg;		/* Calm down picky compilers	*/

	/*
	** If we already have a listening socket, kill it
	*/
	if (ctx->cli_data != NULL) {
		syslog_write(U_WRN, "killing old PASV socket for %s",
						ctx->cli_ctrl->peer);
		socket_kill(ctx->cli_data);
		ctx->cli_data = NULL;
	}

	/*
	** should we bind a rand(port-range) or increment?
	*/
	incr = !config_bool(NULL,"SockBindRand", 0);

	/*
	** Open a socket that is good for listening
	**
	** TransProxy mode: check if we can use our real
	** ip instead of the server's one as our local ip,
	** we bind the socket/ports to.
	*/
	addr = INADDR_ANY;
	if(config_bool(NULL, "AllowTransProxy", 0)) {
		addr = config_addr(NULL, "Listen", (u_int32_t)INADDR_ANY);
	}
	if(INADDR_ANY == addr) {
		addr = socket_sck2addr(ctx->cli_ctrl->sock, LOC_END, NULL);
	}
	if ((port = socket_d_listen(addr, ctx->pas_lrng, ctx->pas_urng,
			&(ctx->cli_data), "Cli-Data", incr)) == 0)
	{
		syslog_error("Cli-Data: can't bind to %s:%d-%d for %s",
			socket_addr2str(addr), (int) ctx->pas_lrng,
			(int) ctx->pas_urng, ctx->cli_ctrl->peer);
		client_respond(425, NULL, "Can't open data connection");
		return;
	}

	/*
	** Consider address "masquerading" (e.g. within a
	** Cisco LocalDirector environment). In this case
	** we have to present a different logical address
	** to the client. The router will re-translate.
	*/
	p = config_str(NULL, "TranslatedAddress", NULL);
	if (p != NULL) {
		if (*p == '/') {
			if ((fp = fopen(p, "r")) != NULL) {
				while (fgets(str, sizeof(str),
							fp) != NULL) {
					q = misc_strtrim(str);
					if (q == NULL || *q == '#' ||
							 *q == '\0')
						continue;
					addr = socket_str2addr(q, addr);
					break;
				}
				fclose(fp);
			} else {
				syslog_write(U_WRN,
					"can't open NAT file '%*s'",
					MAX_PATH_SIZE, p);
			}
		} else
			addr = socket_str2addr(p, addr);
	}

	/*
	** Tell the user where we are listening
	*/
	client_respond(227, NULL,
			"Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
			(int) ((addr >> 24) & 0xff),
			(int) ((addr >> 16) & 0xff),
			(int) ((addr >>  8) & 0xff),
			(int) ( addr        & 0xff),
			(int) ((port >>  8) & 0xff),
			(int) ( port        & 0xff));
	syslog_write(U_INF, "[ %s ] PASV set to %s:%d for %s",
		ctx->cli_ctrl->peer,socket_addr2str(addr), (int) port,
			ctx->cli_ctrl->peer);

	ctx->cli_mode = MOD_PAS_FTP;
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_xfer
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the data transfer commands.
**
** ------------------------------------------------------------ */

static void cmds_xfer(CONTEXT *ctx, char *arg)
{
	int mode = MOD_ACT_FTP;
	char *cmd;
	u_int32_t addr;
	u_int16_t port;

	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_xfer: ?ctx?");
	if ((cmd = ctx->curr_cmd) == NULL)
		misc_die(FL, "cmds_xfer: ?curr_cmd?");
	if (arg == NULL)		/* Protect the strncpy	*/
		arg = "";

	/*
	** Remember command and arguments for the time when
	** we have established the data connection with the
	** server.
	*/
	if (*arg == '\0') {
		syslog_write(U_INF, "[ %s ] '%s' from %s",
				ctx->cli_ctrl->peer, cmd, ctx->cli_ctrl->peer);
	} else {
		syslog_write(U_INF, "[ %s ] '%s %.*s' from %s",ctx->cli_ctrl->peer, cmd,
			MAX_PATH_SIZE, arg, ctx->cli_ctrl->peer);
	}
	misc_strncpy(ctx->xfer_cmd, cmd, sizeof(ctx->xfer_cmd));
	misc_strncpy(ctx->xfer_arg, arg, sizeof(ctx->xfer_arg));

	/*
	** Check if we want to follow the client mode
	*/
	if ((mode = ctx->srv_mode) == MOD_CLI_FTP)
		mode = ctx->cli_mode;

	/*
	** In passive mode we wait for the server to listen
	*/
	if (mode == MOD_PAS_FTP) {
		socket_printf(ctx->srv_ctrl, "PASV\r\n");
		ctx->expect = EXP_PASV;		/* Expect 227	*/
		return;
	}

	/*
	** In active mode we listen and the server connects
	*/
	if (mode == MOD_ACT_FTP) {
		/*
		** should we bind a rand(port-range) or increment?
		*/
		int incr = !config_bool(NULL,"SockBindRand", 0);

		addr = socket_sck2addr(ctx->srv_ctrl->sock,
						LOC_END, NULL);

		if ((port = socket_d_listen(addr, ctx->srv_lrng,
				ctx->srv_urng, &(ctx->srv_data),
				"Srv-Data", incr)) == 0) {
			syslog_error("Srv-Data: can't bind to "
					"%s:%d-%d for %s",
					socket_addr2str(addr),
					(int) ctx->srv_lrng,
					(int) ctx->srv_urng,
					ctx->cli_ctrl->peer);
			client_respond(425, NULL,
					"Can't open data connection");
			client_data_reset(MOD_RESET);
			return;
		}

		/*
		** Tell the server where we are listening
		*/
		socket_printf(ctx->srv_ctrl,
				"PORT %d,%d,%d,%d,%d,%d\r\n",
				(int) ((addr >> 24) & 0xff),
				(int) ((addr >> 16) & 0xff),
				(int) ((addr >>  8) & 0xff),
				(int) ( addr        & 0xff),
				(int) ((port >>  8) & 0xff),
				(int) ( port        & 0xff));
		syslog_write(T_INF, "[ %s ] 'PORT %s:%d' for %s",
				ctx->cli_ctrl->peer,
				socket_addr2str(addr), (int) port,
				ctx->cli_ctrl->peer);
		ctx->expect = EXP_PORT;		/* Expect 200	*/
		return;
	}

	/*
	** Oops, this should not happen ...
	*/
	misc_die(FL, "cmds_xfer: ?mode %d?", mode);
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_abor
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'ABOR' command.
**
** ------------------------------------------------------------ */

static void cmds_abor(CONTEXT *ctx, char *arg)
{
	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_abor: ?ctx?");
	arg = arg;		/* Calm down picky compilers	*/

	/*
	** Tell the auditor (with slightly more attention)
	*/
	syslog_write(U_WRN, "'ABOR' from %s", ctx->cli_ctrl->peer);

	/*
	** Reset data connection variables (esp. PASV)
	*/
	client_data_reset(MOD_RESET);

	/*
	** If no transfer is in progress, don't worry
	*/
	if (ctx->cli_data == NULL && ctx->srv_data == NULL) {
		client_respond(225, NULL, "ABOR command successful");
		return;
	}

	/*
	** If we have a data connection to the client, kill it
	*/
	if (ctx->cli_data != NULL) {
		socket_kill(ctx->cli_data);
		ctx->cli_data = NULL;
		client_respond(426, NULL,
			"Connection closed; transfer aborted");
		client_respond(226, NULL, "ABOR command successful");
	}

	/*
	** Finally propagate the ABOR to the server
	** (We follow the crowd and send only IAC-IP-IAC as OOB)
	*/
	if (ctx->srv_ctrl != NULL) {
#if defined(MSG_OOB)
		char str[4];
		socket_flag(ctx->srv_ctrl, MSG_OOB);
		str[0] = IAC;
		str[1] = IP;
		str[2] = IAC;
		socket_write(ctx->srv_ctrl, str, 3);
		socket_flag(ctx->srv_ctrl, 0);
		str[0] = DM;
		socket_write(ctx->srv_ctrl, str, 1);
#endif
		socket_printf(ctx->srv_ctrl, "ABOR\r\n");
		ctx->expect = EXP_ABOR;
	}
}


#if defined(ENABLE_RFC1579)
/* ------------------------------------------------------------ **
**
**	Function......:	cmds_apsv
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'APSV' command.
**
** ------------------------------------------------------------ */

static void cmds_apsv(CONTEXT *ctx, char *arg)
{
	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_apsv: ?ctx?");
	arg = arg;		/* Calm down picky compilers	*/

	/* TODO */
}
#endif


#if defined(ENABLE_RFC2428)
/* ------------------------------------------------------------ **
**
**	Function......:	cmds_eprt
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'EPRT' command.
**
** ------------------------------------------------------------ */

static void cmds_eprt(CONTEXT *ctx, char *arg)
{
	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_eprt: ?ctx?");
	arg = arg;		/* Calm down picky compilers	*/

	/* TODO */
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_epsv
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'EPSV' command.
**
** ------------------------------------------------------------ */
static void cmds_epsv(CONTEXT *ctx, char *arg)
{
	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_epsv: ?ctx?");
	arg = arg;		/* Calm down picky compilers	*/

	/* TODO */
}
#endif


#if defined(ENABLE_SSL) /* <!-- SSL --> */
/* ------------------------------------------------------------ **
**
**	Function......:	cmds_auth
**
**	Parameters....:	ctx		Pointer to user context
**			arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Act upon the 'AUTH' command.
**			This is for SSL authentication.
**
** ------------------------------------------------------------ */

static void cmds_auth(CONTEXT *ctx, char *arg)
{
	if (ctx == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_auth: ?ctx?");

	if (arg == NULL || strcasecmp(arg, "SSL") != 0) {
		client_respond(501, NULL,
				"Missing or bad auth method");
		return;
	}

	/* TODO */
}


#endif /* <!-- /SSL --> */
#if defined(HAVE_REGEX)
/* ------------------------------------------------------------ **
**
**	Function......:	cmds_reg_comp
**
**	Parameters....:	ppre		Pointer to pattern pointer
**			ptr		String to be compiled
**
**	Return........:	Pointer to De-HTML-ized string
**
**	Purpose.......: Compiles string as regular expression.
**
** ------------------------------------------------------------ */

char *cmds_reg_comp(void **ppre, char *ptr)
{
	static char str[1024];
	char tmp[1024];
	int c;
	size_t i;
	regex_t *re;

	if (ppre == NULL)		/* Basic sanity check	*/
		misc_die(FL, "cmds_reg_comp: ?ppre?");

	/*
	** Remove any previous pattern buffer
	*/
	if (*ppre != NULL) {
		regfree((regex_t *) *ppre);
		misc_free(FL, *ppre);
		*ppre = NULL;
	}

	/*
	** If no pattern is given, disable the feature
	*/
	if (ptr == NULL)
		return NULL;

	/*
	** Preprocess the pattern, i.e. "De-HTML-ize" it
	*/
	memset(str, 0, sizeof(str));
	for (i = 0; *ptr != '\0' && i < (sizeof(str) - 64); ptr++) {
		if (*ptr == ' ' || *ptr == '\t')
			break;
		if (*ptr != '%') {
			str[i++] = *ptr;
			continue;
		}
		if (isxdigit((int)ptr[1]) && isxdigit((int)ptr[2])) {
#if defined(HAVE_SNPRINTF)
			snprintf(tmp, sizeof(tmp), "%.2s", ptr + 1);
#else
			sprintf(tmp, "%.2s", ptr + 1);
#endif
			sscanf(tmp, "%x", &c);
			str[i++] = (char) c;
			ptr += 2;
			continue;
		}
		str[i++] = '%';		/* no special meaning	*/
	}

	/*
	** Time to do the actual compilation
	*/
	re = (regex_t *) misc_alloc(FL, sizeof(regex_t));
	if ((i = regcomp(re, str, REG_EXTENDED | REG_NEWLINE |
						REG_NOSUB)) != 0) {
		regerror(i, re, tmp, sizeof(tmp));
		syslog_error("can't eval RegEx '%s': %s", str, tmp);
		regfree(re);
		misc_free(FL, (void *) re);
		return NULL;
	}

	/*
	** all is well
	*/
	*ppre = (void *) re;
	return str;
}


/* ------------------------------------------------------------ **
**
**	Function......:	cmds_reg_exec
**
**	Parameters....:	regex		Pointer to RegEx pattern
**			str		String to check
**
**	Return........:	NULL=success, else pointer to error msg
**
**	Purpose.......: Check if a given string (argument) is legal.
**
** ------------------------------------------------------------ */

char *cmds_reg_exec(void *regex, char *str)
{
	static char err[1024];
	int i;

	if (regex == NULL || str == NULL)	/* Sanity check	*/
		misc_die(FL, "cmds_reg_exec: ?regex? ?str?");

#if defined(COMPILE_DEBUG)
	debug(2, "trying RegEx for '%.*s'", MAX_PATH_SIZE, str);
#endif
	if ((i = regexec((regex_t *) regex, str, 0, NULL, 0)) != 0) {
		regerror(i, (regex_t *) regex, err, sizeof(err));
		return err;
	}

	/*
	** All is well
	*/
	return NULL;
}
#endif /* !HAVE_REGEX */

static int parse_magic_user(CONTEXT *ctx, char *uarg,
                            char a_sep, int a_first,
                            char u_sep, int u_force)
{
	char *p, *q;

	if(NULL == uarg || '\0' == uarg || '\0' == a_sep) {
		misc_die(FL, "parse_magic_user: ?uarg? ?a_sep?");
	}

#if defined(COMPILE_DEBUG)
	debug(2, "parse_magic_user: uarg='%.512s' as=%c af=%d us=%c uf=%d",
	         uarg, a_sep, a_first, 0 == u_sep? '0' : u_sep, u_force);
#endif

	if('\0' == u_sep) {
		if(a_first) {
			/*
			** USER="auth<a_sep>user"
			*/
			p = strchr(uarg, a_sep);
			if(NULL == p) {
#if defined(COMPILE_DEBUG)
				debug(3, "parse_magic_user: a_sep => NULL");
#endif
				return -1;
			}
			*p++ = '\0';
			if('\0' == p[0] || '\0' == uarg) {
#if defined(COMPILE_DEBUG)
				debug(3, "parse_magic_user: a_sep => ''");
#endif
				return -1;
			}
			ctx->userauth = misc_strdup(FL, uarg);
			ctx->username = misc_strdup(FL, p);
		} else {
			/*
			** USER="user<a_sep>auth"
			*/
			p = strrchr(uarg, a_sep);
			if(NULL == p) {
#if defined(COMPILE_DEBUG)
				debug(3, "parse_magic_user: a_sep => NULL");
#endif
				return -1;
			}
			*p++ = '\0';
			if('\0' == p[0] || '\0' == uarg) {
#if defined(COMPILE_DEBUG)
				debug(3, "parse_magic_user: a_sep => ''");
#endif
				return -1;
			}
			ctx->username = misc_strdup(FL, uarg);
			ctx->userauth = misc_strdup(FL, p);
		}
#if defined(COMPILE_DEBUG)
		debug(2, "magic user='%.256s' auth='%.256s'",
		         NIL(ctx->username), NIL(ctx->userauth));
#endif
		return 0;
	}

	if(a_first) {
		/*
		** USER="auth<a_sep>user[<u_sep>host[:port]]"
		*/
		p = strchr(uarg, a_sep);
		if(NULL == p) {
#if defined(COMPILE_DEBUG)
			debug(3, "parse_magic_user: a_sep => NULL");
#endif
			return -1;
		}
		*p++ = '\0';
		if('\0' == p[0] || '\0' == uarg) {
#if defined(COMPILE_DEBUG)
			debug(3, "parse_magic_user: a_sep => ''");
#endif
			return -1;
		}
		q = strrchr(p, u_sep);
		if(NULL == q) {
#if defined(COMPILE_DEBUG)
			debug(3, "parse_magic_user: u_sep => NULL, user => '%.512s'", p);
#endif
			if(u_force)
				return  1;
		} else {
			*q++ = '\0';
			if('\0' == p[0] || '\0' == q[0]) {
#if defined(COMPILE_DEBUG)
				debug(3, "parse_magic_user: u_sep => '', user => '%.512s'", p);
#endif
				return -1;
			}
			if(-1 == parse_magic_dest(ctx, q))
				return -1;
		}
		ctx->userauth = misc_strdup(FL, uarg);
		ctx->username = misc_strdup(FL, p);
#if defined(COMPILE_DEBUG)
		debug(2, "magic user='%.256s' auth='%.256s'",
		         NIL(ctx->username), NIL(ctx->userauth));
#endif
		return 0;
	}

	/*
	** USER="user<a_sep>auth[<u_sep>host[:port]]"
	*/
	p = strrchr(uarg, a_sep);
	if(NULL == p) {
#if defined(COMPILE_DEBUG)
		debug(3, "parse_magic_user: a_sep => NULL");
#endif
		return -1;
	}
	*p++ = '\0';
	if('\0' == p[0] || '\0' == uarg) {
#if defined(COMPILE_DEBUG)
		debug(3, "parse_magic_user: a_sep => ''");
#endif
		return -1;
	}
	if(a_sep == u_sep) {
		q = strrchr(uarg, u_sep);
		if(NULL == q) {
#if defined(COMPILE_DEBUG)
			debug(3, "parse_magic_user: u_sep => NULL, user => '%.512s', dest => '%.512s'", uarg, p);
#endif
			if(u_force)
				return 1;
			ctx->username = misc_strdup(FL, uarg);
			ctx->userauth = misc_strdup(FL, p);
		} else {
			*q++ = '\0';
			if('\0' == uarg[0] || '\0' == q[0]) {
#if defined(COMPILE_DEBUG)
				debug(3, "parse_magic_user: u_sep => '', user => '%.512s', auth => '%.512s', dest => '%.512s'", uarg, q, p);
#endif
				return -1;
			}
			if(-1 == parse_magic_dest(ctx, p))
				return -1;
			ctx->username = misc_strdup(FL, uarg);
			ctx->userauth = misc_strdup(FL, q);
		}
	} else {
		q = strchr(p, u_sep);
		if(NULL == q) {
#if defined(COMPILE_DEBUG)
			debug(3, "parse_magic_user: u_sep => NULL, user => '%.512s', auth => '%.512s'", uarg, p);
#endif
			if(u_force)
				return 1;
		} else {
			*q++ = '\0';
			if('\0' == p[0] || '\0' == q[0]) {
#if defined(COMPILE_DEBUG)
				debug(3, "parse_magic_user: u_sep => '', user => '%.512s', auth => '%.512s', dest => '%.512s'", uarg, p, q);
#endif
				return -1;
			}
			if(-1 == parse_magic_dest(ctx, q))
				return -1;
		}
		ctx->username = misc_strdup(FL, uarg);
		ctx->userauth = misc_strdup(FL, p);
	}
#if defined(COMPILE_DEBUG)
	debug(2, "magic user='%.256s' auth='%.256s'",
	         NIL(ctx->username), NIL(ctx->userauth));
#endif
	return 0;
}

static int parse_magic_dest(CONTEXT *ctx, char *dest)
{
	char *ptr;

	if(dest && dest[0]) {
		if( (ptr = strrchr(dest, ':'))) {
			*ptr++ = '\0';
			ctx->magic_port = socket_str2port(ptr, IPPORT_FTP);
		} else {
			ctx->magic_port = IPPORT_FTP;
		}
		ctx->magic_addr = socket_str2addr(dest, INADDR_ANY);
#if defined(COMPILE_DEBUG)
		debug(2, "parse magic host='%.256s' port='%d'",
		         socket_addr2str(ctx->magic_addr),
		                         ctx->magic_port);
#endif
		if(ctx->magic_addr != INADDR_ANY &&
		   ctx->magic_addr != INADDR_NONE) {
			return 0;
		}
#if defined(COMPILE_DEBUG)
	} else {
		debug(2, "parse magic dest => NONE");
#endif
	}
	return -1;
}


/* ------------------------------------------------------------
 * $Log: ftp-cmds.c,v $
 * Revision 1.10.2.2  2004/03/10 16:00:49  mt
 * added support for RCMD command (pass-through)
 *
 * Revision 1.10.2.1  2003/05/07 11:10:45  mt
 * - fixed user magic parsing to allow emal-address in
 *   username while @ is used as user magic separator
 * - added ForceUserMagic config variable to enforce
 *   host[:port] presence in FTP USER command
 *
 * Revision 1.10  2002/05/02 13:16:35  mt
 * implemented simple (ldap based) user auth
 *
 * Revision 1.9.2.1  2002/04/04 14:23:32  mt
 * improved transparent proxy log messages
 *
 * Revision 1.9  2002/01/14 19:39:30  mt
 * implemented workarround for Netscape (4.x) directory symlink handling
 * changed to socket_orgdst usage to get ransparent proxy destination
 *
 * Revision 1.8  2001/11/06 23:04:44  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
 *
 * Revision 1.7  1999/10/19 10:19:15  wiegand
 * use port range also for control connection to server
 *
 * Revision 1.6  1999/09/30 09:48:36  wiegand
 * added global RegEx check for USER command
 * added dynamic TranslatedAddress via file
 *
 * Revision 1.5  1999/09/24 06:38:52  wiegand
 * added regular expressions for all commands
 * removed character map and length of paths
 * added flag to reset PASV on every PORT
 * added "magic" user with built-in destination
 * added some argument pointer fortification
 *
 * Revision 1.4  1999/09/21 07:13:34  wiegand
 * syslog / abort cleanup and review
 * remove previous PASV socket
 *
 * Revision 1.3  1999/09/17 16:32:29  wiegand
 * changes from source code review
 * added POSIX regular expressions
 *
 * Revision 1.2  1999/09/16 16:29:57  wiegand
 * minor updates improving code quality
 *
 * Revision 1.1  1999/09/15 14:06:22  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

