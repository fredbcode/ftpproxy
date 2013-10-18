/*
 * $Id: com-debug.c,v 1.5 2002/05/02 12:58:32 mt Exp $
 *
 * Common debugging functions
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
static char rcsid[] = "$Id: com-debug.c,v 1.5 2002/05/02 12:58:32 mt Exp $";
#endif

#include <config.h>

#if defined(STDC_HEADERS)
#  include <stdio.h>
#  include <string.h>
#  include <stdlib.h>
#  include <stdarg.h>
#  include <errno.h>
#endif

#include <sys/types.h>
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
#include <sys/stat.h>

#include "com-debug.h"
#include "com-misc.h"


#if defined(COMPILE_DEBUG)
/* ------------------------------------------------------------ */

#if !defined(O_NOFOLLOW)
#  define O_NOFOLLOW	0
#endif

#define OPEN_NEW	(O_RDWR | O_APPEND | O_CREAT | O_EXCL)
#define OPEN_OLD	(O_RDWR | O_APPEND | O_NOFOLLOW)


/* ------------------------------------------------------------ */

static void debug_cleanup(void);


/* ------------------------------------------------------------ */

static int   dbg_lvl     = 0;		/* Current debug level	*/
static char *dbg_out     = NULL;	/* Debug out file name	*/


/* ------------------------------------------------------------ **
**
**	Function......:	debug_init
**
**	Parameters....:	level		Debug level to set
**			file		Output file for debug
**
**	Return........:	Newly set debug level
**
**	Purpose.......: Initialize debugging. The output file
**			is chmod'ed to 0666 so that it can be
**			written also after setuid/setgid !!!
**
** ------------------------------------------------------------ */

int debug_init(int level, char *file)
{
	if (level >= 0 && level <= 4 && file && *file) {
		if (dbg_out == NULL)
			atexit(debug_cleanup);
		dbg_lvl = level;
		dbg_out = file;
		debug(1, "############# %s startup #############",
						misc_getprog());
	} else {
		misc_die(FL, "invalid debug settings %d / %.*s",
				level, MAX_PATH_SIZE, NIL(file));
	}

	return dbg_lvl;
}


/* ------------------------------------------------------------ **
**
**	Function......:	debug_level
**
**	Parameters....:	(none)
**
**	Return........:	Current debug level
**
**	Purpose.......: Retrieve the current debug level.
**
** ------------------------------------------------------------ */

int debug_level(void)
{
	return dbg_lvl;
}


/* ------------------------------------------------------------ **
**
**	Function......:	debug
**
**	Parameters....:	level		Debug level to use
**			fmt		Printf-string with message
**
**	Return........:	(none)
**
**	Purpose.......: Write debugging output.
**			CAVEAT: *DO NOT* call syslog or die.
**
** ------------------------------------------------------------ */

void debug(int level, char *fmt, ...)
{
	int tmperr = errno;		/* Save errno for later	*/
	va_list aptr;
	FILE *fp;
	int fd;
	struct stat st;
	time_t now;
	struct tm *t;
	mode_t omask;

	/*
	** Check if debug output is wanted
	*/
	if (level <= 0 || level > dbg_lvl)
		return;
	if (!dbg_out || !*dbg_out || !fmt || !*fmt)
		return;

	/*
	** Check that the debug file has not been tampered with
	*/
	memset(&st, 0, sizeof(st));
	if (lstat(dbg_out, &st) < 0) {

		/*
		** Note: we adjust the umask temporary to force
		** open to create a world-writeable debug file.
		** See also notes in ftp-proxy(8) manual page
		** and INSTALL file for compilation options.
		*/
		omask = umask(0);
		fd = open(dbg_out, OPEN_NEW, 0666);
		umask(omask);

		if (fd < 0)
			return;
	} else {
		if ((S_ISLNK(st.st_mode)) || (st.st_nlink > 1))
			return;
		if ((fd = open(dbg_out, OPEN_OLD)) < 0)
			return;
	}

	/*
	** All seems well, go and do your job
	*/
	if ((fp = fdopen(fd, "a")) != NULL) {
		time(&now);
		t = localtime(&now);
		fprintf(fp, "%02d:%02d:%02d <%5d> ", t->tm_hour,
				t->tm_min, t->tm_sec, (int) getpid());
		va_start(aptr, fmt);
		vfprintf(fp, fmt, aptr);
		va_end(aptr);
		fprintf(fp, "\n");
		fclose(fp);
	} else close(fd);

	errno = tmperr;			/* Restore errno	*/
}


/* ------------------------------------------------------------ **
**
**	Function......:	debug_forget
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Forget cleanup's (for forked children).
**
** ------------------------------------------------------------ */

void debug_forget(void)
{
	dbg_lvl = 0;
	dbg_out = NULL;
}


/* ------------------------------------------------------------ **
**
**	Function......:	debug_cleanup
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Finish the debugging tasks.
**
** ------------------------------------------------------------ */

static void debug_cleanup(void)
{
	debug(1, "------------- %s exiting -------------",
					misc_getprog());
}
#endif


/* ------------------------------------------------------------
 * $Log: com-debug.c,v $
 * Revision 1.5  2002/05/02 12:58:32  mt
 * merged with v1.8.2.2
 *
 * Revision 1.4.2.1  2002/04/04 14:27:29  mt
 * added umask(0) before opening new debug log file
 *
 * Revision 1.4  2002/01/14 18:14:03  mt
 * fixed minor format bug
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

