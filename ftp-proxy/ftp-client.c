/*
 * $Id: ftp-client.c,v 1.9.2.3 2005/01/11 13:00:01 mt Exp $
 *
 * Functions for the FTP Proxy client handling
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
static char rcsid[] = "$Id: ftp-client.c,v 1.9.2.3 2005/01/11 13:00:01 mt Exp $";
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

#include <signal.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "com-config.h"
#include "com-debug.h"
#include "com-misc.h"
#include "com-socket.h"
#include "com-syslog.h"
#include "ftp-client.h"
#include "ftp-cmds.h"
#include "ftp-ldap.h"


/* ------------------------------------------------------------ */

static void client_cli_ctrl_read(char *str);
static void client_srv_ctrl_read(char *str);
static void client_srv_passive  (char *arg);
static void client_xfer_fireup  (void);
static int  client_setup_file(CONTEXT *ctx, char *who);


/* ------------------------------------------------------------ */

static int close_flag  = 0;	/* Program termination request	*/

static CONTEXT ctx;		/* The general client context	*/


/* ------------------------------------------------------------ **
**
**	Function......:	client_signal
**
**	Parameters....:	signo		Signal to be handled
**
**	Return........:	(most probably, none)
**
**	Purpose.......: Handler for signals, mainly killing.
**
** ------------------------------------------------------------ */

static RETSIGTYPE client_signal(int signo)
{
#if defined(COMPILE_DEBUG)
	debug(2, "client signal %d", signo);
#endif

	close_flag  = 1;

	signal(signo, client_signal);
#if RETSIGTYPE != void
	return 0;
#endif
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_run
**
**	Parameters....:	(stdin/stdout is the User-PI)
**
**	Return........:	(none)
**
**	Purpose.......: Main function for client operation.
**
** ------------------------------------------------------------ */

void client_run(void)
{
	int  sock, need, diff;
	char str[MAX_PATH_SIZE * 2];
	char *p, *q;
	FILE *fp;
	BUF  *buf;
	
	/*
	** Setup client signal handling (mostly graceful exit)
	*/
	signal(SIGINT,  client_signal);
	signal(SIGTERM, client_signal);
	signal(SIGQUIT, client_signal);
	signal(SIGHUP,  client_signal);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);

	/*
	** Prepare our general client context
	*/
	memset(&ctx, 0, sizeof(ctx));
	ctx.sess_beg = time(NULL);
	ctx.cli_mode = MOD_ACT_FTP;
	ctx.expect   = EXP_IDLE;
	ctx.timeout  = config_int(NULL, "TimeOut", 900);

	sock = fileno(stdin);		/* "recover" our socket */

/* Fred Patch Timeout */

        static int timeout = -1;
        if ((timeout = config_int(NULL, "TimeOut", 0)) == 0) {
        	ctx.timeout  = config_int(NULL, "TimeOut", 900);
        } else {
         	ctx.timeout  = config_int(NULL, "TimeOut", 0);
	} 

	/*
	** Check whether a DenyMessage file exists. This
	** indicates that we are currently not willing
	** to serve any clients.
	*/
	p = config_str(NULL, "DenyMessage", NULL);
	if (p != NULL && (fp = fopen(p, "r")) != NULL) {
		while (fgets(str, sizeof(str) - 4, fp) != NULL) {
			p = socket_msgline(str);
			if ((q = strchr(p, '\n')) != NULL)
				strcpy(q, "\r\n");
			else
				strcat(p, "\r\n");
			send(sock, "421-", 4, 0);
			send(sock, p, strlen(p), 0);
		}
		fclose(fp);
		if ((p = config_str(NULL, "DenyString", NULL)) != NULL)
			p = socket_msgline(p);
		else
			p = "Service not available";
		send(sock, "421 ", 4, 0);
		send(sock, p, strlen(p), 0);
		send(sock, ".\r\n", 3, 0);
		p = socket_addr2str(socket_sck2addr(sock, REM_END, NULL));
		close(sock);
		syslog_write(U_ERR, "reject: '%s' (DenyMessage)", p);
		exit(EXIT_SUCCESS);
	}

	/*
	** Create a High Level Socket for the client's User-PI
	*/
	if ((ctx.cli_ctrl = socket_init(sock)) == NULL)
		misc_die(FL, "client_run: ?cli_ctrl?");
	ctx.cli_ctrl->ctyp = "Cli-Ctrl";

	/*
	** Announce the connection request
	*/
	syslog_write(U_INF, "[ %s ] connect from %s", ctx.cli_ctrl->peer, ctx.cli_ctrl->peer);
	syslog_write(U_INF, "[ %s ] Timeout activity [%d s]", ctx.cli_ctrl->peer, ctx.timeout);

	/*
	** Display the welcome message (invite the user to login)
	*/
	if ((p = config_str(NULL, "WelcomeString", NULL)) == NULL)
		p = "%h FTP server (Version %v - %b) ready";
	misc_strncpy(str, socket_msgline(p), sizeof(str));
	client_respond(220,
		config_str(NULL, "WelcomeMessage", NULL), str);
	/*
	** Enter the client mainloop
	*/
	while (close_flag == 0) {
		/*
		** We need to go into select() only
		** if all input has been processed
		**   or
		** we wait for more data to get a line
		** complete (partially sent, no EOL).
		**
		** (data buffers are never splited)
		*/
		need = 1;
		if (ctx.cli_ctrl && ctx.cli_ctrl->rbuf)
			need = 0;
		if (ctx.srv_ctrl && ctx.srv_ctrl->rbuf)
			need = 0;
		if((ctx.cli_ctrl && ctx.cli_ctrl->more>0) ||
		   (ctx.srv_ctrl && ctx.srv_ctrl->more>0))
			need = 1;

		/*
		** use higher priority to writes;
		** read only if nothing to write...
		*/
		if(ctx.srv_data && ctx.cli_data) {
			if(ctx.srv_data->wbuf) {
				ctx.cli_data->more = -1;
			} else {
				ctx.cli_data->more = 0;
			}
			if(ctx.cli_data->wbuf) {
				ctx.srv_data->more = -1;
			} else {
				ctx.srv_data->more = 0;
			}
		}

	if (need != 0) {
			if (socket_exec(ctx.timeout, &close_flag) <= 0) {
				syslog_write(U_INF, "[ %s ] Timeout closing connection [%d s]", ctx.cli_ctrl->peer, ctx.timeout);
				break;
				}
		}
#if defined(COMPILE_DEBUG)
		debug(4, "client-loop ...");
#endif

		/*
		** Check if any zombie sockets can be removed
		*/
		if (ctx.cli_ctrl != NULL && ctx.cli_ctrl->sock == -1)
			close_flag = 1;		/* Oops, forget it ... */

		if (ctx.srv_ctrl != NULL && ctx.srv_ctrl->sock == -1) {
#if defined(COMPILE_DEBUG)
			debug(3, "about to destroy Srv-Ctrl");
#endif
			/*
			** If we have any open data connections,
			** make really sure they don't survive.
			*/
			if (ctx.cli_data != NULL)
				ctx.cli_data->kill = 1;
			if (ctx.srv_data != NULL)
				ctx.srv_data->kill = 1;

			/*
			** Our client should be informed
			*/
			if (ctx.cli_ctrl->kill == 0) {
				client_respond(421, NULL,
					"Service not available, "
					"closing control connection");
			}

			/*
			** Don't forget to remove the dead socket
			*/
			socket_kill(ctx.srv_ctrl);
			ctx.srv_ctrl = NULL;
		}

		if (ctx.cli_data != NULL && ctx.cli_data->sock == -1) {
#if defined(COMPILE_DEBUG)
			debug(3, "about to destroy Cli-Data");
#endif
			/*
			** If we have an outstanding server reply
			** (e.g. 226 Transfer complete), send it.
			*/
			if (ctx.xfer_rep[0] != '\0') {
				socket_printf(ctx.cli_ctrl,
					"%s\r\n", ctx.xfer_rep);
				memset(ctx.xfer_rep, 0,
					sizeof(ctx.xfer_rep));
			} else {
				if(ctx.expect == EXP_XFER)
					ctx.expect = EXP_PTHR;
			}

			/*
			** Good time for statistics and data reset
			*/
			if (ctx.xfer_beg == 0)
				ctx.xfer_beg = time(NULL);
			diff = (int) (time(NULL) - ctx.xfer_beg);
			if (diff < 1)
				diff = 1;

			/*
			** print our current statistic
			*/
			syslog_write(U_INF,
				"[ %s ] Transfer for %s %s: %s '%s' %s %u/%d byte/sec",
				ctx.cli_ctrl->peer,
				ctx.cli_ctrl->peer,
				ctx.cli_data->ernr ?  "failed" : "completed",
				ctx.xfer_cmd, ctx.xfer_arg,
				ctx.cli_data->rcnt ? "sent" : "read",
				ctx.cli_data->rcnt ? ctx.cli_data->rcnt
				                   : ctx.cli_data->wcnt,
				diff);

			/*
			** update session statistics data
			*/
			if(ctx.cli_data->rcnt)
				ctx.xfer_rsec += diff;
			ctx.xfer_rcnt += ctx.cli_data->rcnt;
			if(ctx.cli_data->wcnt)
				ctx.xfer_wsec += diff;
			ctx.xfer_wcnt += ctx.cli_data->wcnt;

			/*
			** reset data transfer state
			*/
			client_data_reset(MOD_RESET);

			/*
			** Doom the corresponding server socket
			*/
			if (ctx.srv_data != NULL)
				ctx.srv_data->kill = 1;

			/*
			** Don't forget to remove the dead socket
			*/
			socket_kill(ctx.cli_data);
			ctx.cli_data = NULL;
		}

		if (ctx.srv_data != NULL && ctx.srv_data->sock == -1) {

#if defined(COMPILE_DEBUG)
			debug(3, "about to destroy Srv-Data");
#endif
			/*
			** Doom the corresponding client socket if an
			** error occured, FailResetsPasv=yes or we
			** expect other response than PASV (Netscape!)
			*/
			if(ctx.cli_data != NULL) {
				if(0 != ctx.srv_data->ernr) {
					ctx.cli_data->ernr = -1;
					ctx.cli_data->kill =  1;
				}
				if(config_bool(NULL,"FailResetsPasv", 0)) {
					ctx.cli_data->kill = 1;
				} else if(ctx.expect != EXP_PASV) {
					ctx.cli_data->kill = 1;
				}
			}

			/*
			** Don't forget to remove the dead socket
			*/
			socket_kill(ctx.srv_data);
			ctx.srv_data = NULL;
		}

		/*
		** Serve the control connections
		*/
		if (ctx.cli_ctrl != NULL && ctx.cli_ctrl->rbuf != NULL) {
			if (socket_gets(ctx.cli_ctrl,
					str, sizeof(str)) != NULL)
				client_cli_ctrl_read(str);
		}
		if (ctx.srv_ctrl != NULL && ctx.srv_ctrl->rbuf != NULL) {
			if (socket_gets(ctx.srv_ctrl,
					str, sizeof(str)) != NULL)
				client_srv_ctrl_read(str);
		}

		/*
		** Serve the data connections. This is a bit tricky,
		** since all we do is move the buffer pointers.
		*/
		if (ctx.cli_data != NULL && ctx.srv_data != NULL) {
			if (ctx.cli_data->rbuf != NULL) {
#if defined(COMPILE_DEBUG)
				debug(2, "Cli-Data -> Srv-Data");
#endif
				if (ctx.srv_data->wbuf == NULL) {
					ctx.srv_data->wbuf =
						ctx.cli_data->rbuf;
				} else {
					for (buf = ctx.srv_data->wbuf;
							buf && buf->next;
							buf = buf->next)
						;
					buf->next = ctx.cli_data->rbuf;
				}
				ctx.cli_data->rbuf = NULL;
			}
			if (ctx.srv_data->rbuf != NULL) {
#if defined(COMPILE_DEBUG)
				debug(2, "Srv-Data -> Cli-Data");
#endif
				if (ctx.cli_data->wbuf == NULL) {
					ctx.cli_data->wbuf =
						ctx.srv_data->rbuf;
				} else {
					for (buf = ctx.cli_data->wbuf;
							buf && buf->next;
							buf = buf->next)
						;
					buf->next = ctx.srv_data->rbuf;
				}
				ctx.srv_data->rbuf = NULL;
			}
		}
		/* at this point the main loop resumes ... */
	}

	/*
	** Display basic session statistics...
	**   in secs since session begin
	**   downloads / read (xfer-reads from server)
	**   uploads   / send (xfer-sends from server)
	*/
	syslog_write(U_INF, "[ %s ] closing connect from %s after %d secs - "
	                    "read %d/%d, sent %d/%d byte/sec",ctx.cli_ctrl->peer,
	             ctx.cli_ctrl ? ctx.cli_ctrl->peer : "unknown peer",
	             time(NULL)-ctx.sess_beg,
	             ctx.xfer_wcnt, ctx.xfer_wsec,
	             ctx.xfer_rcnt, ctx.xfer_rsec);

	/*
	** Free allocated memory
	*/
	ctx.magic_auth = NULL;
	if (ctx.userauth != NULL) {
		misc_free(FL, ctx.userauth);
		ctx.userauth = NULL;
	}
	if (ctx.username != NULL) {
		misc_free(FL, ctx.username);
		ctx.username = NULL;
	}
	if(ctx.userpass != NULL) {
		misc_free(FL, ctx.userpass);
		ctx.userpass = NULL;
	}

#if defined(COMPILE_DEBUG)
	debug(1, "}}}}} %s client-exit", misc_getprog());
#endif
	exit(EXIT_SUCCESS);
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_cli_ctrl_read
**
**	Parameters....:	str		Buffer with data
**
**	Return........:	(none)
**
**	Purpose.......: Decode and execute client PI commands.
**
** ------------------------------------------------------------ */

static void client_cli_ctrl_read(char *str)
{
	char *arg;
	CMD *cmd;
	int c;

	if (str == NULL) {		/* Basic sanity check	*/
#if defined(COMPILE_DEBUG)
		debug(2, "null User-PI msg: nothing to do");
#endif
		return;
	}

	/*
	** Handle a minimum amount of Telnet line control
	*/
	while ((arg = strchr(str, IAC)) != NULL) {
		c = (arg[1] & 255);
		switch (c) {
			case WILL:
			case WONT:
				/*
				** RFC 1123, 4.1.2.12
				*/
				syslog_write(U_WRN,
					"WILL/WONT refused for %s",
					ctx.cli_ctrl->peer);
				socket_printf(ctx.cli_ctrl,
					"%c%c%c", IAC, DONT, arg[2]);
				if(arg[2])
					memmove(arg, arg + 3, strlen(arg) - 2);
				else
					memmove(arg, arg + 1, strlen(arg));
				break;

			case DO:
			case DONT:
				/*
				** RFC 1123, 4.1.2.12
				*/
				syslog_write(U_WRN,
					"DO/DONT refused for %s",
					ctx.cli_ctrl->peer);
				socket_printf(ctx.cli_ctrl,
					"%c%c%c", IAC, WONT, arg[2]);
				if(arg[2])
					memmove(arg, arg + 3, strlen(arg) - 2);
				else
					memmove(arg, arg + 1, strlen(arg));
				break;

			case IAC:
				memmove(arg, arg + 1, strlen(arg));
				break;

			case IP:
			case DM:
				syslog_write(U_INF, "IAC-%s from %s",
						(c == IP) ? "IP" : "DM",
						ctx.cli_ctrl->peer);
				memmove(arg, arg + 2, strlen(arg) - 1);
				break;

			default:
				memmove(arg, arg + 1, strlen(arg));
		}
	}

	/*
	** If there is nothing left to process, please call again
	*/
	if (str[0] == '\0') {
#if defined(COMPILE_DEBUG)
		debug(2, "empty User-PI msg: nothing to do");
#endif
		return;
	}

	/*
	** Separate arguments if given
	*/
	if ((arg = strchr(str, ' ')) == NULL)
		arg = strchr(str, '\t');
	if (arg == NULL)
		arg = "";
	else {
		while (*arg == ' ' || *arg == '\t')
			*arg++ = '\0';
	}

#if defined(COMPILE_DEBUG)
	debug(1, "from User-PI (%d): cmd='%.32s' arg='%.512s'",
				ctx.cli_ctrl->sock, str, NIL(arg));
#endif

	/*
	** Try to execute the given command. The "USER" command
	**   must be enabled in any case, since it's the one to
	**   setup allow/deny (let's call it bootstrapping) ...
	*/
	for (cmd = cmds_get_list(); cmd->name != NULL; cmd++) {
		if (strcasecmp("USER", cmd->name) == 0)
			cmd->legal = 1;		/* Need this one! */
		if (strcasecmp(str, cmd->name) != 0)
			continue;
		if ((cmd->legal == 0) && strcasecmp("QUIT", cmd->name)) {
			client_respond(502, NULL, "'%.32s': "
				"command not implemented", str);
			syslog_write(U_WRN,
				"'%.32s' from %s not allowed",
				str, ctx.cli_ctrl->peer);
			return;
		}
#if defined(HAVE_REGEX)
		if (cmd->regex != NULL) {
			char *p;
			p = cmds_reg_exec(cmd->regex, arg);
			if (p != NULL) {
				client_respond(501, NULL,
					"'%.32s': syntax error "
					"in arguments", str);
				syslog_write(U_WRN,
					"bad arg '%.128s'%s for "
					"'%s' from %s: %s", arg,
					(strlen(arg) > 128) ?
					"..." : "", cmd->name,
					ctx.cli_ctrl->peer, p);
				return;
			}
		}
#endif
		ctx.curr_cmd = str;
		(*cmd->func)(&ctx, arg);
		return;
	}

	/*
	** Arriving here means the command was not found...
	*/
	client_respond(500, NULL, "'%.32s': command unrecognized", str);
	syslog_write(U_WRN, "[ %s ] unknown '%.32s' from %s",
					ctx.cli_ctrl->peer, str, ctx.cli_ctrl->peer);
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_srv_ctrl_read
**
**	Parameters....:	str		Buffer with data
**
**	Return........:	(none)
**
**	Purpose.......: Decode and execute server responses.
**
** ------------------------------------------------------------ */

static void client_srv_ctrl_read(char *str)
{
	int code, c1, c2;
	char *arg;

	if (str == NULL)		/* Basic sanity check	*/
		return;

	syslog_write(T_DBG, "[ %s ] from Server-PI (%d): '%.512s'",
		     ctx.cli_ctrl->peer,
	             ctx.srv_ctrl->sock, str);
#if defined(COMPILE_DEBUG)
	debug(1, "[ %s ] from Server-PI (%d): '%.512s'",
				ctx.cli_ctrl->peer,ctx.srv_ctrl->sock, str);
#endif

	/*
	** Intermediate responses can usually be forwarded
	*/
	if (*str < '2' || *str > '5' || str[3] != ' ') {
		/*
		** If this is the destination host's
		** welcome message let's discard it.
		*/
		if (ctx.expect == EXP_CONN)
			return;
		if (ctx.expect == EXP_USER && UAUTH_NONE != ctx.auth_mode)
			return;

#if defined(COMPILE_DEBUG)
		debug(2, "'%.4s'... forwarded to %s %d=%s", str,
			ctx.cli_ctrl->ctyp, ctx.cli_ctrl->sock,
			ctx.cli_ctrl->peer);
#endif
		socket_printf(ctx.cli_ctrl, "%s\r\n", str);
		return;
	}

	/*
	** Consider only valid final response codes
	*/
	if ((code = atoi(str)) < 200 || code > 599) {
		syslog_error("[ %s ] bad response %d from server for %s",
					ctx.srv_ctrl->peer, code, ctx.srv_ctrl->peer);
		return;
	}
	c1 =  code / 100;
	c2 = (code % 100) / 10;
	for (arg = str + 3; *arg == ' '; arg++)
		;

	/*
	** We have a response code, go see what we expected
	*/
	switch (ctx.expect) {
		case EXP_CONN:
			/*
			** Waiting for a 220 Welcome
			*/
			if (c1 == 2) {
				socket_printf(ctx.srv_ctrl,
				              "USER %s\r\n",
				              ctx.username);
				ctx.expect = EXP_USER;
			} else {
				if(UAUTH_NONE != ctx.auth_mode) {
					client_respond(530, NULL,
					               "Login incorrect");
				} else {
					socket_printf(ctx.cli_ctrl,
					              "%s\r\n", str);
				}
				ctx.expect = EXP_IDLE;
				ctx.cli_ctrl->kill = 1;
			}
			break;

		case EXP_USER:
			/*
			** Only the following codes are useful:
			**	230=logged in,
			**	331=need password,
			**	332=need password+account
			*/
			if(UAUTH_NONE != ctx.auth_mode) {
				/*
				** logged in, NO password needed
				*/
				if(c1 == 2 && c2 == 3) {
					client_respond(230, NULL,
					               "User logged in, proceed.");
					ctx.expect = EXP_IDLE;
					break;
				} else
				/*
				** OK, password (+account) needed
				*/
				if(c1 == 3 && c2 == 3) {
					if(ctx.userpass) {
						socket_printf(ctx.srv_ctrl,
						              "PASS %s\r\n",
						              ctx.userpass);
						misc_free(FL, ctx.userpass);
						ctx.userpass = NULL;
					} else {
						socket_printf(ctx.srv_ctrl,
						              "PASS \r\n");
					}
					ctx.expect = EXP_PTHR;
					break;
				}
			}
			/*
			** pass server response through to client
			*/
			socket_printf(ctx.cli_ctrl, "%s\r\n", str);
			if (c1 != 2 && c1 != 3) {
				ctx.cli_ctrl->kill = 1;
			}
			ctx.expect = EXP_IDLE;
			break;

		case EXP_ABOR:
			if (c1 == 2) {
				client_data_reset(MOD_RESET);
				ctx.expect = EXP_IDLE;
			}
			break;

		case EXP_PASV:
			if (code == 227 && *arg != '\0') {
				client_srv_passive(arg);
			} else {
				socket_printf(ctx.cli_ctrl,
						"%s\r\n", str);
				client_data_reset(MOD_RESET);
				ctx.expect = EXP_IDLE;
			}
			break;

		case EXP_PORT:
			if (code == 200) {
				client_xfer_fireup();
			} else {
				socket_printf(ctx.cli_ctrl,
						"%s\r\n", str);
				client_data_reset(MOD_RESET);
				ctx.expect = EXP_IDLE;
			}
			break;

		case EXP_XFER:
			/*
			** Distinguish between success and failure
			*/
			if (c1 == 2) {
				misc_strncpy(ctx.xfer_rep, str,
					sizeof(ctx.xfer_rep));
			} else {
				socket_printf(ctx.cli_ctrl,
						"%s\r\n", str);
				if(config_bool(NULL,"FailResetsPasv", 0)) {
					client_data_reset(MOD_RESET);
				} else {
					client_data_reset(ctx.cli_mode);
				}
			}
			ctx.expect = EXP_IDLE;
			break;

		case EXP_PTHR:
			socket_printf(ctx.cli_ctrl, "%s\r\n", str);
			ctx.expect = EXP_IDLE;
			break;

		case EXP_IDLE:
			socket_printf(ctx.cli_ctrl, "%s\r\n", str);
			if (code == 421) {
				syslog_write(T_WRN, "[ %s ] server closed connection for %s", ctx.cli_ctrl->peer, ctx.cli_ctrl->peer);
				ctx.cli_ctrl->kill = 1;
			} else {
				syslog_write(T_WRN, "[ %s ] bogus '%.512s' from Server-PI for %s", ctx.cli_ctrl->peer, ctx.cli_ctrl->peer, str);
			}
			break;
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_srv_passive
**
**	Parameters....:	arg		Command argument(s)
**
**	Return........:	(none)
**
**	Purpose.......: Evaluate the 227 response from the server.
**
** ------------------------------------------------------------ */

static void client_srv_passive(char *arg)
{
	int h1, h2, h3, h4, p1, p2;
	u_int32_t addr, ladr;
	u_int16_t port;
	int       incr;

	if (arg == NULL)		/* Basic sanity check	*/
		return;

	/*
	** Read the port. According to RFC 1123, 4.1.2.6,
	** we have to scan the string for the first digit.
	*/
	while (*arg < '0' || *arg > '9')
		arg++;
	if (sscanf(arg, "%d,%d,%d,%d,%d,%d",
			&h1, &h2, &h3, &h4, &p1, &p2) != 6) {
		syslog_error("[ %s ] bad PASV 277 response from server for %s",ctx.cli_ctrl->peer,ctx.cli_ctrl->peer);
		client_respond(425, NULL, "Can't open data connection");
		client_data_reset(MOD_RESET);
		ctx.expect = EXP_IDLE;
		return;
	}
	addr = (u_int32_t) ((h1 << 24) + (h2 << 16) + (h3 << 8) + h4);
	port = (u_int16_t) ((p1 <<  8) +  p2);
	syslog_write(T_DBG, "[ %s ] got SRV-PASV %s:%d for %s:%d",ctx.cli_ctrl->peer, socket_addr2str(addr), port, ctx.cli_ctrl->peer, ctx.cli_ctrl->port);

	/*
	** should we bind a rand(port-range) or increment?
	*/
	incr = !config_bool(NULL,"SockBindRand", 0);

	/*
	** Open a connection to the server at the given port
	*/
	ladr = socket_sck2addr(ctx.srv_ctrl->sock, LOC_END, NULL);
	if (socket_d_connect(addr, port, ladr, ctx.srv_lrng,
			ctx.srv_urng, &(ctx.srv_data),
			"Srv-Data", incr) == 0)
	{
		syslog_error("[ %s ] can't connect Srv-Data for %s",ctx.cli_ctrl->peer,ctx.cli_ctrl->peer);
		client_respond(425, NULL, "Can't open data connection");
		client_data_reset(MOD_RESET);
		ctx.expect = EXP_IDLE;
		return;
	}

	/*
	** Finally send the original command from the client
	*/
	client_xfer_fireup();
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_xfer_fireup
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Send a deferred transfer command to the
**			server if applicable. If the transfer
**			to the client is ACTIVE, we also need to
**			connect() to the client.
**
** ------------------------------------------------------------ */

static void client_xfer_fireup(void)
{
	u_int32_t ladr = INADDR_ANY;
	int       incr;

	/*
	** should we bind a rand(port-range) or increment?
	*/
	incr = !config_bool(NULL,"SockBindRand", 0);

	/*
	** If appropriate, connect to the client's data port
	*/
	if (ctx.cli_mode == MOD_ACT_FTP) {
		/*
		** TransProxy mode: check if we can use our real
		** ip instead of the server's one as our local ip,
		** we pre-bind the socket/ports to before connect.
		*/
		if(config_bool(NULL, "AllowTransProxy", 0)) {
			ladr = config_addr(NULL, "Listen",
					(u_int32_t)INADDR_ANY);
		}
		if(INADDR_ANY == ladr) {
			ladr = socket_sck2addr(ctx.cli_ctrl->sock,
						LOC_END, NULL);
		}
		if (socket_d_connect(ctx.cli_addr, ctx.cli_port,
				ladr, ctx.act_lrng, ctx.act_urng,
				&(ctx.cli_data), "Cli-Data", incr) == 0)
		{
			syslog_error("[ %s ] can't connect Cli-Data for %s",ctx.cli_ctrl->peer,
						ctx.cli_ctrl->peer);
			client_respond(425, NULL,
					"Can't open data connection");
			client_data_reset(MOD_RESET);
			ctx.expect = EXP_IDLE;
			return;
		}
	}

	/*
	** Send the original command from the client
	*/
	if (ctx.xfer_arg[0] != '\0') {
		socket_printf(ctx.srv_ctrl, "%s %s\r\n",
				ctx.xfer_cmd, ctx.xfer_arg);
		syslog_write(T_INF, "[ %s ] '%s %s' sent for %s",
			ctx.cli_ctrl->peer,ctx.xfer_cmd, ctx.xfer_arg, ctx.cli_ctrl->peer);
	} else {
		socket_printf(ctx.srv_ctrl, "%s\r\n", ctx.xfer_cmd);
		syslog_write(T_INF, "[ %s ] '%s' sent for %s",
			ctx.cli_ctrl->peer,ctx.xfer_cmd, ctx.cli_ctrl->peer);
	}

	/*
	** Prepare the handling and statistics buffers
	*/
	memset(ctx.xfer_rep, 0, sizeof(ctx.xfer_rep));
	ctx.xfer_beg = time(NULL);

	ctx.expect = EXP_XFER;		/* Expect 226 complete	*/
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_respond
**
**	Parameters....:	code		Return code
**			file		Optional file with info
**			fmt		Format string for output
**
**	Return........:	(none)
**
**	Purpose.......: Decode and execute server responses.
**
** ------------------------------------------------------------ */

void client_respond(int code, char *file, char *fmt, ...)
{
	va_list aptr;
	char str[MAX_PATH_SIZE * 2], *p, *q;
	FILE *fp;

	/*
	** Display additional info from file if found
	*/
	if (file != NULL && (fp = fopen(file, "r")) != NULL) {
		while (fgets(str, sizeof(str), fp) != NULL) {
			p = socket_msgline(str);
			if ((q = strchr(p, '\n')) != NULL)
				*q = '\0';
			socket_printf(ctx.cli_ctrl,
					"%03d-%s\r\n", code, p);
		}
		fclose(fp);
	}

	/*
	** The last line carries the ultimate reponse code
	*/
	va_start(aptr, fmt);
#if defined(HAVE_VSNPRINTF)
	vsnprintf(str, sizeof(str), fmt, aptr);
#else
	vsprintf(str, fmt, aptr);
#endif
	va_end(aptr);
	socket_printf(ctx.cli_ctrl, "%03d %s.\r\n", code, str);
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_reinit
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Hard-Reset data and server connections.
**
** ------------------------------------------------------------ */

void client_reinit(void)
{
	/*
	** Remove any server or data connections
	*/
	if (ctx.srv_data != NULL) {
		socket_kill(ctx.srv_data);
		ctx.srv_data = NULL;
	}
	if (ctx.cli_data != NULL) {
		socket_kill(ctx.cli_data);
		ctx.cli_data = NULL;
	}
	if (ctx.srv_ctrl != NULL) {
		socket_kill(ctx.srv_ctrl);
		ctx.srv_ctrl = NULL;
	}
	client_data_reset(MOD_RESET);

	/*
	** Remove the current user and status
	*/
	ctx.auth_mode  = UAUTH_NONE;
	ctx.magic_auth = 0;
	if (ctx.userauth != NULL) {
		misc_free(FL, ctx.userauth);
		ctx.userauth = NULL;
	}
	if (ctx.username != NULL) {
		misc_free(FL, ctx.username);
		ctx.username = NULL;
	}
	if(ctx.userpass != NULL) {
		misc_free(FL, ctx.userpass);
		ctx.userpass = NULL;
	}
	ctx.expect = EXP_IDLE;
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_data_reset
**
**	Parameters....:	mode	reset client transfer mode
**				default value is MOD_RESET
**
**	Return........:	(none)
**
**	Purpose.......: Reset variables for data transfer.
**
** ------------------------------------------------------------ */

void client_data_reset(int mode)
{
	memset(ctx.xfer_cmd, 0, sizeof(ctx.xfer_cmd));
	memset(ctx.xfer_arg, 0, sizeof(ctx.xfer_arg));
	ctx.xfer_beg = 0;

	/*
	** reset client transfer mode to the specified one
	** or (mode==MOD_RESET) to default mode MOD_ACT_FTP
	**
	** Note: a reset to default is the normal behaviour
	*/
	ctx.cli_mode = mode ? mode : MOD_ACT_FTP;

	if (ctx.cli_ctrl != NULL) {
		ctx.cli_addr = ctx.cli_ctrl->addr;
		ctx.cli_port = ctx.cli_ctrl->port;
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_srv_open
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Open control connection to the server.
**
** ------------------------------------------------------------ */

void client_srv_open(void)
{
	struct sockaddr_in saddr;
	u_int16_t          lprt, lowrng, res;
	int                sock, incr, retry;

	/*
	** should we bind a rand(port-range) or increment?
	*/
	incr = !config_bool(NULL,"SockBindRand", 0);

	/*
	** mark socket invalid
	*/
	sock = -1;

	/*
	** Forward connection to destination
	*/
	retry = MAX_RETRIES;
	lprt  = ctx.srv_lrng;
	while(0 <= retry--) {
		/*
		** First of all, get a socket
		*/
		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			syslog_error("Srv-Ctrl: can't create socket for %s",
			             ctx.cli_ctrl->peer);
			exit(EXIT_FAILURE);
		}
		socket_opts(sock, SK_CONTROL);

		/*
		** check if we have to take care to a port range
		*/
		if( !(INPORT_ANY == ctx.srv_lrng &&
                      INPORT_ANY == ctx.srv_urng))
		{
			u_int32_t ladr = INADDR_ANY;

			/*
			** bind the socket, taking care of a given port range
			*/
			if(incr) {
				lowrng = lprt;
#if defined(COMPILE_DEBUG)
				debug(2, "Srv-Ctrl: "
				         "about to bind to %s:range(%d-%d)",
				         socket_addr2str(ladr),
				         lowrng, ctx.srv_urng);
#endif
				res = socket_d_bind(sock, ladr,
				       lowrng, ctx.srv_urng, incr);
			} else {
				lowrng = ctx.srv_lrng;
#if defined(COMPILE_DEBUG)
				debug(2, "Srv-Ctrl: "
				         "about to bind to %s:range(%d-%d)",
				         socket_addr2str(ladr),
				         lowrng, ctx.srv_urng);
#endif
				res = socket_d_bind(sock, ladr,
				           lowrng, ctx.srv_urng, incr);
			}

			if (INPORT_ANY == res) {
				/* nothing found? */
				close(sock);
				syslog_error("Srv-Ctrl: can't bind to"
				             " %s:%d for %s",
					     socket_addr2str(ladr),
					     (int)lprt, ctx.cli_ctrl->peer);
				exit(EXIT_FAILURE);
			} else {
				lprt = res;
			}
		} else lprt = INPORT_ANY;

		/*
		** Okay, now try the actual connect to the server
		*/
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_addr.s_addr = htonl(ctx.srv_addr);
		saddr.sin_family      = AF_INET;
		saddr.sin_port        = htons(ctx.srv_port);

		if (connect(sock, (struct sockaddr *)&saddr,
		            sizeof(saddr)) < 0)
		{
#if defined(COMPILE_DEBUG)
				debug(2, "Srv-Ctrl: connect failed with '%s'",
				      strerror(errno));
#endif
			close(sock);
			sock = -1;
			/* check if is makes sense to retry?
			** perhaps we only need an other
			** local port (EADDRNOTAVAIL) for
			** this destination?
			*/
			if( !(EINTR == errno ||
			      EAGAIN == errno ||
			      EADDRINUSE == errno ||
			      EADDRNOTAVAIL == errno))
			{
				/*
				** an other (real) error ocurred
				*/
				syslog_error("Srv-Ctrl: "
				             "can't connect %s:%d for %s",
				             socket_addr2str(ctx.srv_addr),
				             (int) ctx.srv_port,
				             ctx.cli_ctrl->peer);
				exit(EXIT_FAILURE);
			}
			if(incr && INPORT_ANY != lprt) {
				/* increment lower range if we use
				** increment mode and have a range
				*/
				if(lprt < ctx.srv_urng) {
					lprt++;
				} else {
				/*
				** no more ports in range we can try
				*/
				syslog_error("Srv-Ctrl: "
				             "can't connect %s:%d for %s",
				             socket_addr2str(ctx.srv_addr),
				             (int) ctx.srv_port,
				             ctx.cli_ctrl->peer);
				exit(EXIT_FAILURE);
				}
			}
		} else break;
	}

	/*
	** check if we have a valid, connected socket
	*/
	if(-1 == sock) {
		syslog_error("Srv-Ctrl: can't connect %s:%d for %s",
		             socket_addr2str(ctx.srv_addr),
		             (int) ctx.srv_port,
		             ctx.cli_ctrl->peer);
		exit(EXIT_FAILURE);
	}

	if ((ctx.srv_ctrl = socket_init(sock)) == NULL)
		misc_die(FL, "cmds_user: ?srv_ctrl?");
	ctx.srv_ctrl->ctyp = "Srv-Ctrl";

#if defined(COMPILE_DEBUG)
		debug(2, "Srv-Ctrl is %s:%d",
			ctx.srv_ctrl->peer, (int) ctx.srv_port);
#endif

	ctx.expect = EXP_CONN;		/* Expect Welcome	*/
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_setup
**
**	Parameters....:	pwd	client / user password
**
**	Return........:	0 on success
**
**	Purpose.......: setup user-profile and preform auth
**	                if configured...
**
** ------------------------------------------------------------ */

int client_setup(char *pwd)
{
	char      *type;
	char      *who;

	/*
	** Setup defaults for the client's DTP process
	*/
	ctx.cli_mode = MOD_ACT_FTP;
	ctx.cli_addr = ctx.cli_ctrl->addr;
	ctx.cli_port = ctx.cli_ctrl->port;
	ctx.srv_addr = INADDR_ANY;
	ctx.srv_port = INPORT_ANY;

	/*
	** select the proper name for user specific setup...
	*/
	if(NULL != ctx.userauth) {
		who = ctx.userauth;
	} else {
		who = ctx.username;
	}

	/*
	** don't allow empty or invalid names...
	*/
	if(NULL != who && '\0' != who[0]) {
		char *ptr;
#if defined(HAVE_REGEX)
		char *rule;
		void *preg = NULL;

		rule = config_str(NULL, "UserNameRule",
		       "^[[:alnum:]]+([%20@/\\._-][[:alnum:]]+)*$");
		       
		syslog_write(T_DBG, "[ %s ] compiling UserNameRule: '%.1024s'",ctx.cli_ctrl->peer, rule);
		if(NULL == (ptr = cmds_reg_comp(&preg, rule))) {
		    return -1;
		}
		syslog_write(T_DBG, "[ %s ] DeHTMLized UserNameRule: '%.1024s'",ctx.cli_ctrl->peer, ptr);

		ptr = cmds_reg_exec(preg, who);
		if(NULL != ptr) {
			syslog_write(U_WRN, "[ %s ] invalid user name '%.128s'%s: %s",ctx.cli_ctrl->peer, 
			             who, (strlen(who)>128 ? "..." : ""), ptr);
			cmds_reg_comp(&preg, NULL); /* free regex ptr */
			return -1;
		} else {
			cmds_reg_comp(&preg, NULL); /* free regex ptr */
		}
#else
		/*
		** Simplified "emulation" of the above regex:
		*/
		if( !(isalnum(who[0]) && isalnum(who[strlen(who)-1]))) {
		    syslog_write(U_ERR, "[ %s ] invalid user name '%.128s'%s", ctx.cli_ctrl->peer,
		                 who, (strlen(who)>128 ? "..." : ""));
		    return 1;
		}
		for(ptr=who+1; *ptr; ptr++) {
		    if( !(isalnum(*ptr) ||
		           ' ' == *ptr  || '@' == *ptr || '/' == *ptr ||
		           '.' == *ptr  || '_' == *ptr || '-' == *ptr))
		    {
			syslog_write(U_ERR, "[ %s ] invalid user name '%.128s'%s", ctx.cli_ctrl->peer,
			             who, (strlen(who)>128 ? "..." : ""));
			return -1;
		    }
		}
#endif
	} else {
		/* HUH ?! */
		syslog_write(U_ERR, "[ %s ] empty user name", ctx.cli_ctrl->peer);
		return -1;
	}

	/*
	** user specific setup from config file
	** with fallback to default values
	*/
	if(0 != client_setup_file(&ctx, who)) {
		return -1;
	}

	/*
	** check if we have to authenticate the user
	**
	** authenticate user and setup user specific
	** from ldap server if configured
	*/
	type = config_str(NULL, "UserAuthType", NULL);
	if(NULL != type) {

		if(0 == strcasecmp(type, "ldap")) {
			/*
			** ldap server is mandatory
			*/
			if(NULL == config_str(NULL, "LDAPServer", NULL)) {
				misc_die(FL, "client_setup: ?LDAPServer?");
			}

			/*
			** ldap auth + setup
			*/
			if(0 != ldap_setup_user(&ctx, who, pwd ? pwd : ""))
				return -1;
		} else {
			misc_die(FL, "client_setup: unknown ?UserAuthType?");
		}

	} /* else {
		** Fred Patch: with this block ftp-proxy doesn't work without ldap ...
		** try ldap setup only
		ldap_setup_user(&ctx, who, NULL);
		**
	} */

	/*
	** Evaluate mandatory settings or refuse to run.
	*/
	errno = 0;
	if(INADDR_ANY == ctx.srv_addr || INADDR_BROADCAST == ctx.srv_addr) {
		syslog_error("[ %s ] can't eval DestAddr for %s", ctx.cli_ctrl->peer, ctx.cli_ctrl->peer);
		return -1;
	}
	if(INPORT_ANY == ctx.srv_port) {
		syslog_error("[ %s ] can't eval DestPort for %s",ctx.cli_ctrl->peer, ctx.cli_ctrl->peer);
		return -1;
	}

	return 0; /* all right */
}


/* ------------------------------------------------------------ **
**
**	Function......:	client_setup_file
**
**	Parameters....:	ctx	Pointer to user context
**			who	Pointer to user name
**
**	Return........:	0 on success
**
**	Purpose.......: setup user-profile from config file
**
** ------------------------------------------------------------ */

static int client_setup_file(CONTEXT *ctx, char *who)
{
	char      *p;

	u_int16_t  l, u;

	/*
	** little bit sanity check
	*/
	if( !(ctx && who && *who)) {
		return -1;
	}

	/*
	** Inform the auditor that we are using the config file
	*/
	syslog_write(U_INF, "[ %s ] reading data for '%s' from cfg-file", ctx->cli_ctrl->peer, who);

	/*
	** Evaluate DestinationAddress, except we have magic_addr
	*/
	if (INADDR_ANY != ctx->magic_addr) {
		ctx->srv_addr = ctx->magic_addr;
	} else {
		ctx->srv_addr = config_addr(who, "DestinationAddress",
		                                 INADDR_ANY);
#if defined(COMPILE_DEBUG)
		debug(2, "[ %s ] file DestAddr for %s: '%s'", ctx->cli_ctrl->peer,
		      ctx->cli_ctrl->peer, socket_addr2str(ctx->srv_addr));
#endif
	}

	/*
	** Evaluate DestinationPort, except we have magic_port
	*/
	if (INPORT_ANY != ctx->magic_port) {
		ctx->srv_port = ctx->magic_port;
	} else {
		ctx->srv_port = config_port(who, "DestinationPort",
		                                 IPPORT_FTP);
#if defined(COMPILE_DEBUG)
		debug(2, "[ %s ] file DestPort for %s: %d", ctx->cli_ctrl->peer,
		      ctx->cli_ctrl->peer, (int) ctx->srv_port);
#endif
	}

	/*
	** Evaluate the destination transfer mode
	*/
	p = config_str(who, "DestinationTransferMode", "client");
	if(0 == strcasecmp(p, "active")) {
		ctx->srv_mode = MOD_ACT_FTP;
	} else
	if(0 == strcasecmp(p, "passive")) {
		ctx->srv_mode = MOD_PAS_FTP;
	} else
	if(0 == strcasecmp(p, "client")) {
		ctx->srv_mode = MOD_CLI_FTP;
	} else {
		syslog_error("can't eval DestMode for %s",
		             ctx->cli_ctrl->peer);
		return -1;
	}
#if defined(COMPILE_DEBUG)
	debug(2, "file DestMode for %s: %s", ctx->cli_ctrl->peer, p);
#endif

	/*
	** Evaluate min/max destination port range
	*/
	l = config_port(who, "DestinationMinPort", INPORT_ANY);
	u = config_port(who, "DestinationMaxPort", INPORT_ANY);
	if (l > 0 && u > 0 && u >= l) {
		ctx->srv_lrng = l;
		ctx->srv_urng = u;
	} else {
		ctx->srv_lrng = INPORT_ANY;
		ctx->srv_urng = INPORT_ANY;
	}
#if defined(COMPILE_DEBUG)
	debug(2, "file DestRange for %s: %u-%u", ctx->cli_ctrl->peer,
	         ctx->srv_lrng, ctx->srv_urng);
#endif

	/*
	** Evaluate min/max active port range
	*/
	l = config_port(who, "ActiveMinDataPort", INPORT_ANY);
	u = config_port(who, "ActiveMaxDataPort", INPORT_ANY);
	if (l > 0 && u > 0 && u >= l) {
		ctx->act_lrng = l;
		ctx->act_urng = u;
	} else {
		/* do not try to bind a port < 1024 if running as UID != 0 */
		if(0 == getuid()) {
			ctx->act_lrng = (IPPORT_FTP - 1);
			ctx->act_urng = (IPPORT_FTP - 1);
		} else {
			ctx->act_lrng = INPORT_ANY;
			ctx->act_urng = INPORT_ANY;
		}
	}
#if defined(COMPILE_DEBUG)
	debug(2, "file ActiveRange for %s: %u-%u", ctx->cli_ctrl->peer,
	         ctx->act_lrng, ctx->act_urng);
#endif

	/*
	** Evaluate min/max passive port range
	*/
	l = config_port(who, "PassiveMinDataPort", INPORT_ANY);
	u = config_port(who, "PassiveMaxDataPort", INPORT_ANY);
	if (l > 0 && u > 0 && u >= l) {
		ctx->pas_lrng = l;
		ctx->pas_urng = u;
	} else {
		ctx->pas_lrng = INPORT_ANY;
		ctx->pas_urng = INPORT_ANY;
	}
#if defined(COMPILE_DEBUG)
	debug(2, "file PassiveRange for %s: %u-%u", ctx->cli_ctrl->peer,
	         ctx->pas_lrng, ctx->pas_urng);
#endif

	/*
	** Setup other configuration options
	*/
	ctx->same_adr = config_bool(who, "SameAddress", 1);
	ctx->timeout  = config_int (who, "TimeOut",   900);
#if defined(COMPILE_DEBUG)
	debug(2, "file SameAddress for %s: %s", ctx->cli_ctrl->peer,
	                                        ctx->same_adr ? "yes" : "no");
	debug(2, "file TimeOut for %s: %d", ctx->cli_ctrl->peer, ctx->timeout);
#endif

/*** Adjust the allow/deny flags for the commands ** Fred patch */
	
	char dest[17];
	char ipdest[17];
	char ipsrc[17];
	strcpy (ipsrc,ctx->cli_ctrl->peer);
	strcpy (ipdest, socket_addr2str(ctx->srv_addr));
	syslog_write(U_INF, "\n");	
	syslog_write(U_INF, "[ %s ] Fred Patch rules dest: %s src: %s", ipsrc, ipdest, ipsrc);	

	char groupname[]="group";
	char commandename[]="ValidCommands";
	char *group;
	FILE *fp;
	group = "group1";
	int ix;
	int ix2;
	u_int32_t dnsaddr;
	for(ix=1; group != NULL; ix++) {
		sprintf (&groupname[6],"%d",ix);
		group = config_str(who, groupname, NULL);
		}
	
	syslog_write(U_INF, "[ %s ] Number of groups: %d", ipsrc, ix-2);
		
	for (ix2=1; ix2 <= ix-2; ix2++) {
		sprintf (&groupname[6],"%d",ix2);
		group = config_str(who, groupname, NULL);
		syslog_write(U_INF, "[ %s ] Reading: %s",ipsrc, group );
		if ((fp = fopen(group, "r")) == NULL)
			{
			syslog_write(U_INF, "File not found");
			return 0;
			}
		else
			{	
			fseek(fp, 0, SEEK_SET);
			while (fgets(dest, 17 , fp) != NULL)
				{	
				// Pour une IP
				// Correction Bug Ligne sans \n 
					dest[16] = '\n';
					char *c = strchr (dest, '\n');
					*c = 0;
					/*  Dns resolution */
					if (ipdest != dest) {
						dnsaddr = socket_str2addr(dest, INADDR_ANY);
						if (dnsaddr != 0) 
							strcpy (dest, socket_addr2str(dnsaddr));
						}
					if (strcmp(dest,ipdest) == 0 || strcmp(dest,ipsrc) == 0)
					{
						sprintf (&commandename[13],"%d",ix);
						p = config_str(who,commandename, NULL);
						cmds_set_allow(p);
						syslog_write(U_INF, "[ %s ] Apply rules for: %s dst: %s",ipsrc, ipsrc, ipdest);
						syslog_write(U_INF, "[ %s ] Server match %s ",ipsrc, group );
						syslog_write(U_INF, "\n");
						fclose(fp);
						return 0;
					}
			// Network
				if (strchr(dest, 'x') != NULL)
					{ 
						char *c = strchr(dest, 'x');
						*c = 0;
						int longueur;
						longueur = strlen(dest);
						if (strncmp(dest,ipdest,longueur) == 0 || strncmp(dest,ipsrc,longueur) == 0)
						{
							sprintf (&commandename[13],"%d",ix);
							p = config_str(who,commandename, NULL);
							cmds_set_allow(p);
							syslog_write(U_INF, "[ %s ] Apply rules for Network: %s src: %s",ipsrc, ipdest, ipsrc);
							syslog_write(U_INF, "[ %s ] Server match %s ",ipsrc, group );
							syslog_write(U_INF, "\n");
							fclose(fp);
							return 0;
						}
					}
				}

			fclose(fp);
			}	
		}
	syslog_write(U_INF, "[ %s ] Oh, Oh, no rule found -> defaultrules", ipsrc) ;
	p = config_str(who, "defaultrules", NULL);
	cmds_set_allow(p); 
	return 0;
}


/* ------------------------------------------------------------
 * $Log: ftp-client.c,v $
 * Revision 1.9.2.3  2005/01/11 13:00:01  mt
 * fixed default UserNameRule regexp rejecting user
 * names where the 3. character is not alphanumeric
 *
 * Revision 1.9.2.2  2004/03/22 12:40:13  mt
 * implemented a UserNameRule option allowing a regex
 * based override of the builtin user name checks
 *
 * Revision 1.9.2.1  2003/05/07 11:11:33  mt
 * removed broken ABOR sending on error while srv_data xfer still runs
 * moved user config-profile reading from ftp-ldap to client_setup_file()
 * changed to use new ctx.auth_mode flags to check if in user-auth mode
 *
 * Revision 1.9  2002/05/02 13:15:36  mt
 * implemented simple (ldap based) user auth
 *
 * Revision 1.8.2.1  2002/04/04 14:26:11  mt
 * added failed/completed transfer log message status
 *
 * Revision 1.8  2002/01/14 19:35:44  mt
 * implemented workarround for Netscape (4.x) directory symlink handling
 * implemented a MaxRecvBufSize option limiting max recv buffer size
 * extended log messages to provide basic transfer statistics data
 * added snprintf usage if supported, replaced strncpy with misc_strncpy
 *
 * Revision 1.7  2001/11/06 23:04:43  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
 *
 * Revision 1.6  1999/10/19 11:04:51  wiegand
 * make sure transfer time has reasonable value
 *
 * Revision 1.5  1999/09/24 06:38:52  wiegand
 * added regular expressions for all commands
 * removed character map and length of paths
 * added flag to reset PASV on every PORT
 * added "magic" user with built-in destination
 * added some argument pointer fortification
 *
 * Revision 1.4  1999/09/21 07:13:07  wiegand
 * syslog / abort cleanup and review
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
