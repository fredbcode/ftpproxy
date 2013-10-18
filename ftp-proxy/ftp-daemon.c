/*
 * $Id: ftp-daemon.c,v 1.4 2002/01/14 19:31:14 mt Exp $
 *
 * Functions for the FTP Proxy daemon mode
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
static char rcsid[] = "$Id: ftp-daemon.c,v 1.4 2002/01/14 19:31:14 mt Exp $";
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

#include <sys/types.h>
#include <sys/stat.h>

#if defined(HAVE_FCNTL_H)
#  include <fcntl.h>
#elif defined(HAVE_SYS_FCNTL_H)
#  include <sys/fcntl.h>
#endif

#include <signal.h>

#if defined(HAVE_SYS_WAIT_H)
#  include <sys/wait.h>
#endif
#if !defined(WEXITSTATUS)
#  define WEXITSTATUS(stat_val)	((unsigned)(stat_val) >> 8)
#endif
#if !defined(WIFEXITED)
#  define WIFEXITED(stat_val)	(((stat_val) & 255) == 0)
#endif

#if defined(HAVE_PATHS_H)
#  include <paths.h>
#endif
#if !defined(_PATH_DEVNULL)
#   define _PATH_DEVNULL   "/dev/null"
#endif

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
#include "ftp-daemon.h"
#include "ftp-main.h"

/* ------------------------------------------------------------ */

#define MAX_CLIENTS	512	/* Max. concurrent user limit	*/
#define LISTEN_WAIT	30	/* Wait up to 30sec for listen	*/

#define FORK_INTERVAL	60	/* Interval for ForkLimit	*/
#define MAX_FORKS	40	/* Default fork-resource-limit	*/

typedef struct {
	pid_t pid;		/* Proc-id of child (0=empty)	*/
	char  peer[PEER_LEN];	/* Dotted decimal IP address	*/
} CLIENT;

/* ------------------------------------------------------------ */

static RETSIGTYPE daemon_signal(int signo);

static void daemon_cleanup(void);


/* ------------------------------------------------------------ */

static int    initflag = 0;	/* Have we been initialized?	*/
static pid_t  daemon_pid = 0;   /* Daemon PID for cleanups, ... */
static time_t last_slice = 0;	/* Last time slice with clients	*/
static int    last_count = 0;	/* Clients in last_slice	*/

static CLIENT clients[MAX_CLIENTS];


/* ------------------------------------------------------------ **
**
**	Function......:	daemon_signal
**
**	Parameters....:	signo		Signal to be handled
**
**	Return........:	(none)
**
**	Purpose.......: Handler for signals, mainly waiting.
**
** ------------------------------------------------------------ */

static RETSIGTYPE daemon_signal(int signo)
{
	int tmperr = errno;		/* Save errno for later	*/
	pid_t pid;
	int i, status;
	CLIENT *clp;

#if defined(HAVE_WAITPID)
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
#elif defined(HAVE_WAIT3)
	while ((pid = wait3(&status, WNOHANG, NULL)) > 0)
#else
	if ((pid = wait(&status)) > 0)
#endif
	{
		for (i = 0, clp = clients; i < MAX_CLIENTS; i++, clp++) {
			if (clp->pid == pid) {
				clp->pid = (pid_t) 0;
#if defined(COMPILE_DEBUG)
				debug(1, "client pid=%d (%s) gone",
						(int) pid, clp->peer);
#endif
				memset(clp->peer, 0, PEER_LEN);
				break;
			}
		}
	}

	signal(signo, daemon_signal);
	errno = tmperr;			/* Restore errno	*/

#if RETSIGTYPE != void
	return 0;
#endif
}

/* ------------------------------------------------------------ **
**
**	Function......:	detach_signal
**
**	Parameters....:	signo		Signal to be handled
**
**	Return........:	(none)
**
**	Purpose.......: private signal handler to return proper
**	                exit status back to the shell about the
**	                initialization of the detached child in
**	                daemon_init function.
**
** ------------------------------------------------------------ */

static RETSIGTYPE detach_signal(int signo)
{
	switch(signo) {
		case SIGHUP:
			/*
			** initialization succeed
			*/
			exit(EXIT_SUCCESS);
		break;

		case SIGCHLD:
			/*
			** initialization failure
			*/
			exit(EXIT_FAILURE);
		break;
	}
#if RETSIGTYPE != void
	return 0;
#endif
}

/* ------------------------------------------------------------ **
**
**	Function......:	daemon_init
**
**	Parameters....:	detach		Detach from controlling
**					terminal if set
**
**	Return........:	(none)
**
**	Purpose.......: Initialize the FTP daemon functions.
**
** ------------------------------------------------------------ */

void daemon_init(int detach)
{
	u_int32_t laddr;
	u_int16_t lport;
	pid_t     oldpid;
	char     *p;
	int       i;

	/*
	** Cleanup the client array
	*/
	for (i = 0; i < MAX_CLIENTS; i++) {
		clients[i].pid = (pid_t) 0;
		memset(clients[i].peer, 0, PEER_LEN);
	}

	/*
	** 1. STEP: Fork, if requested
	*/
	oldpid = getpid();
	if (detach) {
		pid_t pid;

		/*
		** set detach init status signals
		*/
		signal(SIGHUP,  detach_signal);
		signal(SIGCHLD, detach_signal);

		pid = fork();
		switch (pid) {
			case -1:
				syslog_error("can't fork daemon");
				exit(EXIT_FAILURE);
			break;

			case 0:
				/******** child ********/
				/*
				** forget this status signal
				*/
				signal(SIGHUP, SIG_DFL);
			break;

			default:
				/******** parent ********/
#if defined(COMPILE_DEBUG)
				debug_forget();
#endif
				/*
				** wait for client init completed;
				** see 2. STEP of detach bellow...
				*/
				sleep(10);

				/* huh?! kill the naughty child! */
				kill(pid, SIGTERM);

				syslog_error("can't detach daemon");
				exit(EXIT_FAILURE);
			break;
		}

#if defined(COMPILE_DEBUG)
		debug(2, "fork: PID %d --> %d",
				(int) oldpid, (int) getpid());
#endif
	}

	/*
	** The initial fork (if any) is done, prepare for exit
	*/
	daemon_pid = getpid();
	if (initflag == 0) {
		atexit(daemon_cleanup);
		initflag = 1;
	}

	/*
	** Open a listening socket
	*/
	laddr = config_addr(NULL, "Listen", (u_int32_t) INADDR_ANY);
	lport = config_port(NULL, "Port",   (u_int16_t) IPPORT_FTP);
	for (i = 0; i < MAX_RETRIES; i++) {
		if (socket_listen(laddr, lport, daemon_accept) == 0)
			break;
		sleep(LISTEN_WAIT);
	}
	if (i >= MAX_RETRIES) {
		syslog_error("can't bind daemon to %d", (int) lport);
		exit(EXIT_FAILURE);
	}

	/*
	** Install the signal handler
	*/
	signal(SIGCHLD, daemon_signal);

	/*
	** Create a PID-File if requested
	*/
	misc_pidfile(config_str(NULL, "PidFile", NULL));

	/*
	** Change root directory
	*/
	if(0 == misc_chroot(config_str(NULL, "ServerRoot", NULL))) {
		struct stat st;

		/*
		** dump config file into the chroot
		** only if it does not exists there
		*/
		if(stat(config_filename(), &st)) {
			FILE       *out;
			int         fd;

			fd = open(config_filename(),
			          O_WRONLY|O_CREAT, 0644);

			if(-1 != fd && (out = fdopen(fd, "w"))) {
				config_dump(out);
				fflush(out);
				fclose(out);
			} else {
				syslog_error(
				"can't write config file into chroot");
				if(-1 != fd)
					close(fd);
				exit(EXIT_FAILURE);
			}
		}
	}


	/*
	** singal parent about successfull init;
	** we can still report errors to stderr,
	** but are unable to send a signal to
	** parent after we've dropped the UID...
	*/
	if(detach) {
		kill(oldpid, SIGHUP);
	}

	/*
	** Change (drop) user- and group-id if requested
	*/
	misc_uidgid(CONFIG_UID, CONFIG_GID);

	/*
	** Open the log if requested
	*/
	if ((p = config_str(NULL, "LogDestination", NULL)) != NULL)
		syslog_open(p, config_str(NULL, "LogLevel", NULL));
	else	syslog_close();


	/*
	** 2. STEP: Detach from controlling terminal, if requested
	*/
	if(detach) {
		freopen(_PATH_DEVNULL, "r", stdin);
		freopen(_PATH_DEVNULL, "w", stdout);
		freopen(_PATH_DEVNULL, "w", stderr);

		chdir("/");
#if defined(HAVE_SETSID)
		setsid();
#endif
	}
	syslog_write(T_DBG,
	             "daemon runs in '%.1024s' with uid=%d gid=%d",
                     config_str(NULL, "ServerRoot", "/"),
	             (int) getuid(), (int) getgid());
}


/* ------------------------------------------------------------ **
**
**	Function......:	daemon_accept
**
**	Parameters....:	sock		Accepted socket descriptor
**
**	Return........:	(none)
**
**	Purpose.......: Callback to accept a client connection.
**
** ------------------------------------------------------------ */

void daemon_accept(int sock)
{
	time_t slice;
	int cnt, i;
	CLIENT *clp;
	char str[1024], *p, *q, *peer;
	FILE *fp;

	/*
	** Get the peer address for diagnostic output
	*/
	peer = socket_addr2str(socket_sck2addr(sock, REM_END, NULL));

	/*
	** Check whether to limit the number of incoming
	** client connections per minute. Use half values
	** each to avoid "neighborhood effects". This is
	** effectively a Denial of Service prevention.
	*/
	if ((cnt = config_int(NULL, "ForkLimit", MAX_FORKS)) > 0) {
		slice = time(NULL) / (FORK_INTERVAL / 2);
		if (slice != last_slice) {
			last_slice = slice;
			last_count = 0;
		}
		if (++last_count >= (cnt / 2)) {
			close(sock);
			syslog_write(U_ERR,
				"reject: '%s' (ForkLimit %d)",
				peer, cnt);
			return;
		}
	}

	/*
	** Check if we are fully loaded already
	*/
	if ((cnt = config_int(NULL, "MaxClients", MAX_CLIENTS)) < 1)
		cnt = 1;
	else if (cnt > MAX_CLIENTS)
		cnt = MAX_CLIENTS;
	for (i = 0, clp = clients; i < cnt; i++, clp++) {
		/*
		** santoniu@libertysurf.fr:
		** Verifying if the child is alive or not.
		*/
		if ((clp->pid != (pid_t) 0) && (kill(clp->pid, 0)!=0) ) {
			syslog_write(T_WRN,
				"[ %s ] child with PID %d went away (removing it)",
			clp->peer, (pid_t)clp->pid);
			clp->pid = 0;
			break;
		}
		if (clp->pid == (pid_t) 0)
			break;
	}
	if (i >= cnt) {
		p = config_str(NULL, "MaxClientsMessage", NULL);
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
		}
		if ((p = config_str(NULL,
				"MaxClientsString", NULL)) != NULL)
			p = socket_msgline(p);
		else
			p = "Service not available";
		send(sock, "421 ", 4, 0);
		send(sock, p, strlen(p), 0);
		send(sock, ".\r\n", 3, 0);
		close(sock);
		syslog_write(U_ERR,
			"reject: '%s' (MaxClients %d)", peer, cnt);
		return;
	}

	/*
	** Fork a new client process (clp is still valid)
	*/
	switch (clp->pid = fork()) {
		case -1:
			clp->pid = (pid_t) 0;
			if (errno != EAGAIN) {
				syslog_error("can't fork client");
			}
			close(sock);
			syslog_write(T_WRN, "can't fork client now");
			return;
		case 0:
			/******** child ********/
			break;
		default:
			/******** parent ********/
			close(sock);
			strcpy(clp->peer, peer);
#if defined(COMPILE_DEBUG)
			debug(1, "client pid=%d (%s) added",
					(int) clp->pid, clp->peer);
#endif
			return;
	}

	/*
	** Maintain the init/exit message balance
	*/
	misc_setprog("ftp-child", NULL);
#if defined(COMPILE_DEBUG)
	debug(1, "{{{{{ %s client-fork", misc_getprog());
#endif

	/*
	** To be consistent with inetd-mode, make the client
	** socket our standard path. stderr is still /dev/null.
	*/
	dup2(sock, fileno(stdin));
	dup2(sock, fileno(stdout));
	close(sock);

	/*
	** Get out of the daemon's way in terms of cleanup
	*/
	misc_forget();
	socket_lclose(0);

	/*
	** Well, time to do the client job
	*/
	client_run();
}


/* ------------------------------------------------------------ **
**
**	Function......:	daemon_cleanup
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Clean up the daemon related data.
**
** ------------------------------------------------------------ */

static void daemon_cleanup(void)
{
	int i;
	CLIENT *clp;

	if(getpid() == daemon_pid) /* clean up our childs list */
	for (i = 0, clp = clients; i < MAX_CLIENTS; i++, clp++) {
		if (clp->pid == (pid_t) 0)
			continue;

#if defined(COMPILE_DEBUG)
		debug(1, "client %d=%s still alive", 
					(int) clp->pid, clp->peer);
#endif

		/*
		** Make sure this child does not survive
		*/
		kill(clp->pid, SIGTERM);
	}
}


/* ------------------------------------------------------------
 * $Log: ftp-daemon.c,v $
 * Revision 1.4  2002/01/14 19:31:14  mt
 * reordered chroot, uidgid-dropping, syslog opening in detach_init
 * implemented waiting for child-init after fork for proper exit code
 *
 * Revision 1.3  2001/11/06 23:04:44  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
 *
 * Revision 1.2  1999/09/21 07:14:19  wiegand
 * syslog / abort cleanup and review
 *
 * Revision 1.1  1999/09/15 14:06:22  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

