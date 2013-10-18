/*
 * $Id: com-syslog.c,v 1.6.2.1 2003/05/07 11:14:34 mt Exp $
 *
 * Common file/syslog logging functions
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
static char rcsid[] = "$Id: com-syslog.c,v 1.6.2.1 2003/05/07 11:14:34 mt Exp $";
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

#if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif

#if defined(HAVE_FCNTL_H)
#  include <fcntl.h>
#elif defined(HAVE_SYS_FCNTL_H)
#  include <sys/fcntl.h>
#endif

#if defined(HAVE_SYSLOG_H)
#  include <syslog.h>
#  if defined(NEED_SYS_SYSLOG_H)
#    include <sys/syslog.h>
#  endif
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include "com-debug.h"
#include "com-misc.h"
#include "com-syslog.h"

/*
** default log level is LOG_INFO (verbose)
*/
#if	!defined(DEFAULT_LOG_LEVEL)
#define		DEFAULT_LOG_LEVEL	LOG_INFO
#endif


/* ------------------------------------------------------------ */

typedef struct {
	char *name;		/* Syslog facility name		*/
	int   code;		/* The corresponding code	*/
} FACIL;


/* ------------------------------------------------------------ */

static int initflag = 0;	/* Have we been initialized?	*/

static int    log_level  = DEFAULT_LOG_LEVEL;
static char  *log_name   = NULL;
static FILE  *log_file   = NULL;
static FILE  *log_pipe   = NULL;
static FACIL *log_syslog = NULL;

static FACIL facilities[] = {
#ifdef LOG_AUTH
	{ "auth",   LOG_AUTH   },
#endif
#ifdef LOG_CRON
	{ "cron",   LOG_CRON   },
#endif
#ifdef LOG_DAEMON
	{ "daemon", LOG_DAEMON },
#endif
#ifdef LOG_FTP
	{ "ftp",    LOG_FTP    },
#endif
#ifdef LOG_KERN
	{ "kern",   LOG_KERN   },
#endif
#ifdef LOG_LOCAL0
	{ "local0", LOG_LOCAL0 },
#endif
#ifdef LOG_LOCAL1
	{ "local1", LOG_LOCAL1 },
#endif
#ifdef LOG_LOCAL2
	{ "local2", LOG_LOCAL2 },
#endif
#ifdef LOG_LOCAL3
	{ "local3", LOG_LOCAL3 },
#endif
#ifdef LOG_LOCAL4
	{ "local4", LOG_LOCAL4 },
#endif
#ifdef LOG_LOCAL5
	{ "local5", LOG_LOCAL5 },
#endif
#ifdef LOG_LOCAL6
	{ "local6", LOG_LOCAL6 },
#endif
#ifdef LOG_LOCAL7
	{ "local7", LOG_LOCAL7 },
#endif
#ifdef LOG_LPR
	{ "lpr",    LOG_LPR    },
#endif
#ifdef LOG_MAIL
	{ "mail",   LOG_MAIL   },
#endif
#ifdef LOG_NEWS
	{ "news",   LOG_NEWS   },
#endif
#ifdef LOG_USER
	{ "user",   LOG_USER   },
#endif
#ifdef LOG_UUCP
	{ "uucp",   LOG_UUCP   },
#endif
	{ NULL,     0          }
};

/* ------------------------------------------------------------ **
**
**	Function......: syslog_stderr
**
**	Parameters....: (none)
**
**	Return........: (none)
**
**	Purpose.......: Assign log destination to stderr.
**	                This allows to print errors durring the
**	                initialization phase - before the first
**	                syslog_open call is done
**
** ------------------------------------------------------------ */

void syslog_stderr()
{
	syslog_close();
	log_file = stderr;
	log_level = LOG_ERR;
}

/* ------------------------------------------------------------ **
**
**	Function......:	syslog_open
**
**	Parameters....:	name		Logfile or syslog name
**	Parameters....:	level		log level name (optional)
**
**	Return........:	(none)
**
**	Purpose.......: Open a logfile, logpipe or syslog.
**
** ------------------------------------------------------------ */

void syslog_open(char *name, char *level)
{
	int fd;

	if (initflag == 0) {
		if(stderr == log_file) {
			log_file  = NULL;
		}

		atexit(syslog_close);
		initflag = 1;
	}

	if (misc_strequ(name, log_name)) {
		/*
		** log destination hasn't changed
		** rotate, if a log file is used
		*/
		if(log_file) {
			syslog_rotate();
		}
		return;
	}

	if (NULL != log_name && NULL != name && '\0' != name[0]) {
		/*
		** this is a reopen - write a message with
		** the new log destination into the old one
		*/
		syslog_write(T_INF,
			     "reopening log - new destination is '%.*s'",
			     MAX_PATH_SIZE, name);
	}

	syslog_close();
	if (NULL == name || '\0' == name[0]) {
		/*
		** hmm... it was a close...
		*/
		return;
	}

	if(level && *level) {
		if( !strcasecmp("FLT", level)) {
			log_level = LOG_CRIT;
		} else
		if( !strcasecmp("ERR", level)) {
			log_level = LOG_ERR;
		} else
		if( !strcasecmp("WRN", level)) {
			log_level = LOG_WARNING;
		} else
		if( !strcasecmp("INF", level)) {
			log_level = LOG_INFO;
		} else
		if( !strcasecmp("DBG", level)) {
			log_level = LOG_DEBUG;
		} else {
			misc_die(FL, "invalid log level '%.3s'");
		}
	}

	/*
	** So we do have a destination now ...
	*/
	if (*name == '/') {
		char tmp_name[MAX_PATH_SIZE];
		/*
		** Logging to a regular file
		*/
		if(syslog_rename(tmp_name, name, sizeof(tmp_name))<0)
		{
			if (unlink(name) != 0 && errno != ENOENT) {
				misc_die(FL, "can't remove logfile '%.*s'",
						MAX_PATH_SIZE, name);
			}
		}
		if ((fd = open(name, O_RDWR | O_CREAT | O_EXCL,
							0640)) < 0) {
			misc_die(FL, "can't open logfile '%.*s'",
						MAX_PATH_SIZE, name);
		}
		if ((log_file = fdopen(fd, "w")) == NULL) {
			misc_die(FL, "can't open logfile '%.*s'",
						MAX_PATH_SIZE, name);
		}
	} else if (*name == '|') {
		/*
		** Logging to a command pipe
		*/
		for (++name; *name == ' ' || *name == '\t'; name++)
			;
		if ((log_pipe = popen(name, "w")) == NULL) {
			misc_die(FL, "can't open logpipe '%.*s'",
						MAX_PATH_SIZE, name);
		}
	} else {
		/*
		** Must be syslog, go and check the facility
		*/
		for (log_syslog = facilities;
				log_syslog->name; log_syslog++) {
			if (strcmp(name, log_syslog->name) == 0)
				break;
		}
		if (log_syslog->name == NULL) {
			log_syslog = NULL;
			misc_usage("invalid syslog facility '%.64s'",
								name);
		}
		openlog(misc_getprog(),
				LOG_PID | LOG_CONS | LOG_NDELAY,
				log_syslog->code);
		setlogmask(LOG_UPTO(log_level));
	}
	log_name = misc_strdup(FL, name);
}


/* ------------------------------------------------------------ **
**
**	Function......:	syslog_write
**
**	Parameters....:	level		Loglevel (similar to syslog)
**			fmt		Format string for output
**
**	Return........:	(none)
**
**	Purpose.......: Write a message to the current log.
**			Do not call misc_die() to avoid loops.
**
** ------------------------------------------------------------ */

void syslog_write(int level, char *fmt, ...)
{
	int tmperr = errno;		/* Save errno for later	*/
	va_list aptr;
	int loglvl, dbglvl;
	FILE *fp;
	time_t now;
	struct tm *t;
	char *logstr, buf[32], str[MAX_PATH_SIZE * 4];

	va_start(aptr, fmt);
#if defined(HAVE_VSNPRINTF)
	vsnprintf(str, sizeof(str), fmt, aptr);
#else
	vsprintf(str, fmt, aptr);
#endif
	va_end(aptr);

	switch (level) {
		case T_DBG:	loglvl = LOG_DEBUG;
				logstr = "TECH-DBG";
				dbglvl = 3;
				break;
		case T_INF:	loglvl = LOG_INFO;
				logstr = "TECH-INF";
				dbglvl = 2;
				break;
		case T_WRN:	loglvl = LOG_WARNING;
				logstr = "TECH-WRN";
				dbglvl = 1;
				break;
		case T_ERR:	loglvl = LOG_ERR;
				logstr = "TECH-ERR";
				dbglvl = 1;
				break;
		case T_FTL:	loglvl = LOG_CRIT;
				logstr = "TECH-FTL";
				dbglvl = 1;
				break;

		case U_DBG:	loglvl = LOG_DEBUG;
				logstr = "USER-DBG";
				dbglvl = 3;
				break;
		case U_INF:	loglvl = LOG_INFO;
				logstr = "USER-INF";
				dbglvl = 2;
				break;
		case U_WRN:	loglvl = LOG_WARNING;
				logstr = "USER-WRN";
				dbglvl = 1;
				break;
		case U_ERR:	loglvl = LOG_ERR;
				logstr = "USER-ERR";
				dbglvl = 1;
				break;
		case U_FTL:	loglvl = LOG_CRIT;
				logstr = "USER-FTL";
				dbglvl = 1;
				break;

		default:	loglvl = LOG_CRIT;
				logstr = "TECH-FLT";
				dbglvl = 1;
	}

#if defined(COMPILE_DEBUG)
	debug(dbglvl, "%s %s", logstr, str);
#endif

	if (log_level < loglvl) {
		errno = tmperr;		/* Restore errno	*/
		return;
	}

	if (log_syslog) {
		syslog(loglvl, "%s %s", logstr, str);
		errno = tmperr;		/* Restore errno	*/
		return;
	}

	if ((fp = (log_file ? log_file : log_pipe)) == NULL) {
		errno = tmperr;		/* Restore errno	*/
		return;
	}

	time(&now);
	t = localtime(&now);
#if defined(HAVE_SNPRINTF)
	snprintf(buf, sizeof(buf), "%02d/%02d-%02d:%02d:%02d",
			t->tm_mon + 1, t->tm_mday,
			t->tm_hour, t->tm_min, t->tm_sec);
#else
	sprintf(buf, "%02d/%02d-%02d:%02d:%02d",
			t->tm_mon + 1, t->tm_mday,
			t->tm_hour, t->tm_min, t->tm_sec);
#endif
	fprintf(fp, "%s [%d] <%s> %s %s\n", misc_getprog(),
				(int) getpid(), buf, logstr, str);
	fflush(fp);

	errno = tmperr;			/* Restore errno	*/
}


/* ------------------------------------------------------------ **
**
**	Function......:	syslog_error
**
**			fmt		Format string for output
**
**	Return........:	(none)
**
**	Purpose.......: Write a message to the current log.
**			Tag is ERR. Also write a debug info.
**
** ------------------------------------------------------------ */

void syslog_error(char *fmt, ...)
{
	int tmperr = errno;		/* Save errno for later	*/
	va_list aptr;
	FILE *fp;
	time_t now;
	struct tm *t;
	char buf[32], str[MAX_PATH_SIZE * 4];

	va_start(aptr, fmt);
#if defined(HAVE_VSNPRINTF)
	vsnprintf(str, sizeof(str), fmt, aptr);
#else
	vsprintf(str, fmt, aptr);
#endif
	va_end(aptr);

#if defined(COMPILE_DEBUG)
	if (tmperr == 0)
		debug(1, "TECH-ERR %s", str);
	else
		debug(1, "TECH-ERR %s (errno=%d [%.200s])",
				str, tmperr, strerror(tmperr));
#endif

	if (log_level < LOG_ERR) {
		errno = tmperr;		/* Restore errno	*/
		return;
	}

	if (log_syslog) {
		if (tmperr == 0)
			syslog(LOG_ERR, "TECH-ERR %s", str);
		else
			syslog(LOG_ERR, "TECH-ERR %s (errno=%d [%.256s])",
					str, tmperr, strerror(tmperr));
		errno = tmperr;		/* Restore errno	*/
		return;
	}

	if ((fp = (log_file ? log_file : log_pipe)) == NULL) {
		errno = tmperr;		/* Restore errno	*/
		return;
	}

	time(&now);
	t = localtime(&now);
#if defined(HAVE_SNPRINTF)
	snprintf(buf, sizeof(buf), "%02d/%02d-%02d:%02d:%02d",
			t->tm_mon + 1, t->tm_mday,
			t->tm_hour, t->tm_min, t->tm_sec);
#else
	sprintf(buf, "%02d/%02d-%02d:%02d:%02d",
			t->tm_mon + 1, t->tm_mday,
			t->tm_hour, t->tm_min, t->tm_sec);
#endif
	fprintf(fp, "%s [%d] <%s> TECH-ERR %s\n",
			misc_getprog(), (int) getpid(), buf, str);
	fflush(fp);

	errno = tmperr;			/* Restore errno	*/
}


/* ------------------------------------------------------------ **
**
**	Function......:	syslog_rename
**
**	Parameters....:	new_name, log_name, len
**
**	Return........:	-1 on error, 0 on success,
**			1 if log_name does not exists
**
**	Purpose.......: if file specified as log_name exists,
**                      rename it to new_name with a maximal
**                      length given in len.
**
** ------------------------------------------------------------ */

int  syslog_rename(char *new_name, char *log_name, size_t len)
{
	time_t now;
	struct tm *t;
	struct stat st;

	if( initflag == 0)
		return -1;

	if( !(new_name && log_name && len > (strlen(log_name) + 17)))
		return -1;

	time(&now);
	t = localtime(&now);

	memset(new_name, 0, len);
#if defined(HAVE_SNPRINTF)
	snprintf(new_name, len, "%.*s.%d%02d%02d-%02d%02d%02d",
		(int)len-17, log_name, t->tm_year + 1900,
		t->tm_mon + 1, t->tm_mday,
		t->tm_hour, t->tm_min, t->tm_sec);
#else
	sprintf(new_name, "%.*s.%d%02d%02d-%02d%02d%02d",
		(int)len-17, log_name, t->tm_year + 1900,
		t->tm_mon + 1, t->tm_mday,
		t->tm_hour, t->tm_min, t->tm_sec);
#endif

	if( lstat(log_name, &st))
		return 1;

	if( !lstat(new_name, &st)) {
		if( !(S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))) {
			return -1;
		}
		unlink(new_name);
	}

	if (rename(log_name, new_name)) {
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------ **
**
**	Function......:	syslog_rotate
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Rotate the log, if logging to a file.
**
** ------------------------------------------------------------ */

void syslog_rotate(void)
{
	char tmp_name[MAX_PATH_SIZE];
	int fd;

	if( initflag == 0)
		return;

	/* Only useful if logging to file */
	if (log_file == NULL)
		return;

#if defined(COMPILE_DEBUG)
	debug(2, "rotating log file '%.*s'",
	         MAX_PATH_SIZE, log_name);
#endif
	syslog_write(T_INF, "rotating log file '%.*s'",
	                    MAX_PATH_SIZE, log_name);

	fclose(log_file);
	log_file = NULL;

	if(syslog_rename(tmp_name, log_name, sizeof(tmp_name))<0) {
		misc_die(FL, "can't rotate logfile '%.*s'",
			MAX_PATH_SIZE, log_name);
	}
	if ((fd = open(log_name, O_RDWR | O_CREAT | O_EXCL,
						0640)) < 0) {
		misc_die(FL, "can't open logfile '%.*s'",
					MAX_PATH_SIZE, log_name);
	}
	if ((log_file = fdopen(fd, "w")) == NULL) {
		misc_die(FL, "can't open logfile '%.*s'",
					MAX_PATH_SIZE, log_name);
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	syslog_close
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Clean up at program exit.
**
** ------------------------------------------------------------ */

void syslog_close(void)
{
	if (log_syslog) {
		closelog();
		log_syslog = NULL;
	}

	if (log_file) {
		if(stderr != log_file)
			fclose(log_file);
		log_file = NULL;
	}

	if (log_pipe) {
		pclose(log_pipe);
		log_pipe = NULL;
	}

	if (log_name) {
		void *tmp = (void *) log_name;
		log_name = NULL;
		misc_free(FL, tmp);
	}

	log_level = DEFAULT_LOG_LEVEL;
}


/* ------------------------------------------------------------
 * $Log: com-syslog.c,v $
 * Revision 1.6.2.1  2003/05/07 11:14:34  mt
 * added check for empty name in log_open
 *
 * Revision 1.6  2002/05/02 13:01:58  mt
 * merged with v1.8.2.2
 *
 * Revision 1.5.2.2  2002/04/04 14:28:53  mt
 * replaced stat with lstat for rename check in log rotation
 *
 * Revision 1.5.2.1  2002/01/28 01:51:21  mt
 * replaced question marks sequences that may be misinterpreted as trigraphs
 *
 * Revision 1.5  2002/01/14 18:30:15  mt
 * implemented syslog_stderr function to redirect log to stderr
 * added LogLevel option handling allowing to set the maximal level
 * added snprintf usage, replaced strcpy/strncpy with misc_strncpy
 *
 * Revision 1.4  2001/11/06 23:04:43  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
 *
 * Revision 1.3  1999/09/26 13:25:05  wiegand
 * protection of debug/pid/log files against attacks
 *
 * Revision 1.2  1999/09/17 06:32:28  wiegand
 * buffer length and overflow protection review
 *
 * Revision 1.1  1999/09/15 14:05:38  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

