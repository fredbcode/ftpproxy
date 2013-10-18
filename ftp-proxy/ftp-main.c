/*
 * $Id: ftp-main.c,v 1.6.6.1 2003/05/07 11:08:55 mt Exp $
 *
 * Main program of the FTP Proxy
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
static char rcsid[] = "$Id: ftp-main.c,v 1.6.6.1 2003/05/07 11:08:55 mt Exp $";
#endif

#include <config.h>

#if defined(STDC_HEADERS)
#  include <stdio.h>
#  include <string.h>
#  include <stdlib.h>
#  include <stdarg.h>
#  include <errno.h>
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

#include "com-config.h"
#include "com-debug.h"
#include "com-misc.h"
#include "com-socket.h"
#include "com-syslog.h"
#include "ftp-client.h"
#include "ftp-daemon.h"
#include "ftp-main.h"


/* ------------------------------------------------------------ */

#include "ftp-vers.c"		/* We need the version strings	*/

#define SELECT_TIMEOUT		60	/* Wake up regularly	*/

#if defined(COMPILE_DEBUG)
#  define DEBUG_FILE		"/tmp/ftp-proxy.debug"
#  define OPTS_LIST		"cdinf:v:V?"
#else
#  define OPTS_LIST		"cdinf:V?"
#endif


/* ------------------------------------------------------------ */

static char progname[1024];

static char *usage_arr[] = {
	progname,
	"    -c          Dump Config-File contents and exit",
	"    -d          Forced to run in standalone mode",
	"    -i          Forced to run in inetd mode",
	"    -n          Do not detach from controlling terminal",
	"    -f file     Name of the configuration file",
	"                  (Default: " DEFAULT_CONFIG ")",
#if defined(COMPILE_DEBUG)
	"    -v level    Send debuging output to " DEBUG_FILE,
	"                  (Level: 0 = silence, 4 = chatterbox)",
	"                  !!! DO NOT USE -v FOR PRODUCTION !!!",
#endif
	"    -V          Display program version and exit",
	"",
	NULL
};


/* ------------------------------------------------------------ */

static RETSIGTYPE main_signal(int signo);

static char *cfg_file  = 0;	/* Name of the config file	*/
static int close_flag  = 0;	/* Program termination request	*/
static int config_flag = 0;	/* Config refresh request	*/
static int rotate_flag = 0;	/* Log file rotation request	*/


/* ------------------------------------------------------------ */

#define ST_NONE		0	/* Unknown ServerType		*/
#define ST_INETD	1	/* Run from (x)inetd		*/
#define ST_DAEMON	2	/* Run as daemon		*/

static int srv_type;		/* The actual server type	*/


/* ------------------------------------------------------------ **
**
**	Function......:	config_filename
**
**	Parameters....:	(none)
**
**	Return........:	name of current config file
**
**	Purpose.......: read-only access to config file name
**
** ------------------------------------------------------------ */

const char* config_filename()
{
	return cfg_file;
}


/* ------------------------------------------------------------ **
**
**	Function......:	main_signal
**
**	Parameters....:	signo		Signal to be handled
**
**	Return........:	(most probably, none)
**
**	Purpose.......: Handler for signals, mainly killing.
**
** ------------------------------------------------------------ */

static RETSIGTYPE main_signal(int signo)
{
#if defined(COMPILE_DEBUG)
	debug(2, "server signal %d", signo);
#endif

	switch (signo) {
		case SIGHUP:
			config_flag = 1;
			break;
		case SIGUSR1:
			rotate_flag = 1;
			break;
		default:
			close_flag  = 1;
	}

	signal(signo, main_signal);
#if RETSIGTYPE != void
	return 0;
#endif
}


/* ------------------------------------------------------------ **
**
**	Function......:	main
**
**	Parameters....:	argc & argv	As usual
**
**	Return........:	EXIT_SUCCESS or EXIT_FAILURE
**
**	Purpose.......: Yes.
**
** ------------------------------------------------------------ */

int main(int argc, char *argv[])
{
	int c, detach, cfg_dump;
	char *p;

#if defined(SIGWINCH)
	/*
	** Make sure we don't get confused by resizing windows
	*/
	signal(SIGWINCH, SIG_IGN);
#endif

	/*
	** Set a reasonable program name for debug/logging
	*/
	p = misc_setprog(argv[0], usage_arr);
#if defined(HAVE_SNPRINTF)
	snprintf(progname, sizeof(progname),
	                  "Usage: %s [option ...]", p);
#else
	sprintf(progname, "Usage: %s [option ...]", p);
#endif
	misc_setvers(prog_vers);
	misc_setdate(prog_date);

	/*
	** Preset some variables
	*/
	cfg_file = DEFAULT_CONFIG;
	cfg_dump = 0;
	srv_type = ST_NONE;	/* Undetermined yet		*/
	detach   = 1;		/* Usually detach from CtlTerm	*/

	/*
	** Read the command line options
	*/
	while ((c = getopt(argc, argv, OPTS_LIST)) != EOF) {
		switch (c) {
		case 'c':
			cfg_dump = 1;		/* Dump config	*/
			break;
		case 'd':
			srv_type = ST_DAEMON;	/* Force daemon	*/
			break;
		case 'i':
			srv_type = ST_INETD;	/* Force inetd	*/
			break;
		case 'n':
			detach = 0;	/* Don't detach (e.g. AIX) */
			break;
		case 'f':
			cfg_file = misc_strtrim(optarg);
			break;
#if defined(COMPILE_DEBUG)
		case 'v':
			debug_init(atoi(misc_strtrim(optarg)), DEBUG_FILE);
			break;
#endif
		case 'V':
			fprintf(stderr, "%s\n", misc_getvsdt());
			exit(EXIT_SUCCESS);
			break;
		case '?':
		default:
			misc_usage(NULL);
		}
	}

	/*
	** Redirect errors and faults to stderr durring the
	** initialisation phase. The log file will be opened
	** after the chroot is done and uid/gid are dropped
	** (if they are requested....)
	*/
	syslog_stderr();

	/*
	** Read the configuration file (this will die on error)
	*/
	config_read(cfg_file, cfg_dump);

	/*
	** Complain if no default DestinationAddress is given
	** while the AllowTransProxy feature is disabled...
	**
	** FIXME: is this really needed?
	*/
	if( (NULL == config_str(NULL, "DestinationAddress", NULL)) &&
	    (0    == config_bool(NULL, "AllowTransProxy", 0))      &&
            (0    == config_bool(NULL, "AllowMagicUser", 0)))
	{
		syslog_error("can't run without an destination address");
		exit(EXIT_FAILURE);
	}

	/*
	** Determine ServerType (inetd/standalone)
	*/
	if (srv_type == ST_NONE) {
		p = config_str(NULL, "ServerType", "inetd");
		if (strcasecmp(p, "standalone") == 0)
			srv_type = ST_DAEMON;
		else
			srv_type = ST_INETD;
	}

	if (srv_type == ST_INETD) {
#if defined(COMPILE_DEBUG)
		debug(1, "{{{{{ %s client-start", misc_getprog());
#endif
		/*
		** Change root directory
		*/
		misc_chroot(config_str(NULL, "ServerRoot", NULL));

		/*
		** Change our user- and group-id if requested
		*/
		misc_uidgid(CONFIG_UID, CONFIG_GID);

		/*
		** Open the log if requested
		*/
		if ((p = config_str(NULL, "LogDestination", NULL)) != NULL)
			syslog_open(p, config_str(NULL, "LogLevel", NULL));
		else	syslog_close();

		client_run();
		exit(EXIT_SUCCESS);
	}

#if defined(COMPILE_DEBUG)
	debug(1, "{{{{{ %s daemon-start", misc_getprog());
#endif

	/*
	** The rest of this file is "daemon only" code ...
	*/
	daemon_init(detach);

	/*
	** Setup signal handling (mostly graceful exit)
	*/
	signal(SIGINT,  main_signal);
	signal(SIGTERM, main_signal);
	signal(SIGQUIT, main_signal);
	signal(SIGHUP,  main_signal);
	signal(SIGUSR1, main_signal);

	/*
	** Well, it's time for the main loop now ...
	*/
	while (close_flag == 0) {
		/*
		** Shall we re-read the config file?
		*/
		if (config_flag) {

			/*
			** reread config
			*/
			config_flag = 0;
			config_read(cfg_file, 0);

			/*
			** reopen / rotate log
			*/
			syslog_open(config_str(NULL,
			                       "LogDestination", NULL),
			            config_str(NULL, "LogLevel", NULL));
		}

		/*
		** Check for log file rotation
		*/
		if (rotate_flag) {
			rotate_flag = 0;
			syslog_rotate();
		}

		/*
		** Now perform the "real" main loop work
		*/
		socket_exec(SELECT_TIMEOUT, &close_flag);
	}

#if defined(COMPILE_DEBUG)
	debug(1, "}}}}} %s daemon-exit", misc_getprog());
#endif
	exit(EXIT_SUCCESS);
}


/* ------------------------------------------------------------
 * $Log: ftp-main.c,v $
 * Revision 1.6.6.1  2003/05/07 11:08:55  mt
 * added strtrim arround optarg
 *
 * Revision 1.6  2002/01/14 19:24:46  mt
 * reordered config reading, chroot and syslog opening
 * added config_filename function for runtime queries
 * added snprintf usage if supported on built-platform
 *
 * Revision 1.5  2001/11/06 23:04:44  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
 *
 * Revision 1.4  1999/09/29 09:58:25  wiegand
 * complain about missing DestAddr after LogOpen (incl. stderr)
 *
 * Revision 1.3  1999/09/21 07:13:07  wiegand
 * syslog / abort cleanup and review
 *
 * Revision 1.2  1999/09/16 16:29:57  wiegand
 * minor updates improving code quality
 *
 * Revision 1.1  1999/09/15 14:06:22  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

