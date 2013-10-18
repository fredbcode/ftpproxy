/*
 * $Id: com-misc.c,v 1.9.2.1 2003/05/07 11:15:05 mt Exp $
 *
 * Common miscellaneous functions
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
static char rcsid[] = "$Id: com-misc.c,v 1.9.2.1 2003/05/07 11:15:05 mt Exp $";
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

#include "com-config.h"
#include "com-debug.h"
#include "com-misc.h"
#include "com-syslog.h"


/* ------------------------------------------------------------ */

static void misc_cleanup(void);


/* ------------------------------------------------------------ */

static int initflag = 0;	/* Have we been initialized?	*/

static char p_name[512] = "[unknown name]";
static char p_vers[512] = "[unknown version]";
static char p_date[512] = "[unknown date]";

static char **use_ptr = NULL;	/* Usage information array	*/
static char *pid_name = NULL;	/* Name of ProcID file		*/


/* ------------------------------------------------------------ **
**
**	Function......:	misc_cleanup
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Clean up at program exit.
**
** ------------------------------------------------------------ */

static void misc_cleanup(void)
{
	if (pid_name != NULL) {
		void *tmp = (void *) pid_name;
		unlink(pid_name);
		pid_name = NULL;
		misc_free(FL, tmp);
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_forget
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Forget cleanup's (for forked children).
**
** ------------------------------------------------------------ */

void misc_forget(void)
{
	if (pid_name != NULL) {
		void *tmp = (void *) pid_name;
		pid_name = NULL;
		misc_free(FL, tmp);
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_setprog / misc_getprog
**
**	Parameters....:	prog_str	Program name
**			usage_arr	Usage info string array
**
**	Return........:	Program basename
**
**	Purpose.......: Makes the prog-name known to logging,
**			provides a short name without path.
**
** ------------------------------------------------------------ */

char *misc_setprog(char *prog_str, char *usage_arr[])
{
	char *p;

	if (prog_str == NULL)
		p = "[unknown name]";
	else if ((p = strrchr(prog_str, '/')) != NULL)
		p++;
	else
		p = prog_str;
	misc_strncpy(p_name, p, sizeof(p_name));

	if (usage_arr != NULL)
		use_ptr = usage_arr;

	return p_name;
}


char *misc_getprog(void)
{
	return p_name;
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_setvers / misc_getvers
**			misc_setdate / misc_getdate
**			misc_getvsdt
**
**	Parameters....:	version		Program version
**
**	Return........:	Program version
**
**	Purpose.......: Sets and retrieves the program version
**			and program compilation date and time.
**			And a "standard version + date" thing.
**
** ------------------------------------------------------------ */

void misc_setvers(char *vers_str)
{
	if (vers_str == NULL)
		vers_str = "[unknown version]";
	misc_strncpy(p_vers, vers_str, sizeof(p_vers));
}


char *misc_getvers(void)
{
	return p_vers;
}


void misc_setdate(char *date_str)
{
	if (date_str == NULL)
		date_str = "[unknown date]";
	misc_strncpy(p_date, date_str, sizeof(p_date));
}


char *misc_getdate(void)
{
	return p_date;
}


char *misc_getvsdt(void)
{
	static char str[MAX_PATH_SIZE * 2];

#if defined(HAVE_SNPRINTF)
	snprintf(str, sizeof(str), "Version %s - %s", p_vers, p_date);
#else
	sprintf(str, "Version %s - %s", p_vers, p_date);
#endif
	return str;
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_alloc
**
**	Parameters....:	file		Filename of requestor
**			line		Line number of requestor
**			len		Number of bytes requested
**
**	Return........:	Pointer to memory
**
**	Purpose.......: Allocate memory with malloc. The program
**			dies if no memory is available.
**			The memory is automatically zero'ed.
**
** ------------------------------------------------------------ */

void *misc_alloc(char *file, int line, size_t len)
{
	void *ptr;

	if (file == NULL)		/* Sanity check		*/
		file = "[unknown file]";

	if (len == 0)			/* Another check ...	*/
		misc_die(file, line, "misc_alloc: ?len?");

	if ((ptr = malloc(len)) == NULL)
		misc_die(file, line, "out of memory");

#if defined(COMPILE_DEBUG)
	debug(4, "alloc %u (%.*s:%d): %p",
		(unsigned) len, MAX_PATH_SIZE, file, line, ptr);
#endif

	memset(ptr, 0, len);
	return ptr;
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_strdup
**
**	Parameters....:	file		Filename of requestor
**			line		Line number of requestor
**			str		Pointer to original string
**
**	Return........:	Pointer to allocated string
**
**	Purpose.......: Allocate memory for a copy of the given
**			string with misc_alloc and copy the
**			string in place.
**
** ------------------------------------------------------------ */

char *misc_strdup(char *file, int line, char *str)
{
	char *ptr;
	int   len;

	/* Basic sanity check	*/
	if (str == NULL)
		misc_die(file, line, "misc_strdup: ?str?");

	len = strlen(str);
	ptr = (char *) misc_alloc(file, line, len + 1);
	strncpy(ptr, str, len);

	return ptr;
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_free
**
**	Parameters....:	file		Filename of requestor
**			line		Line number of requestor
**			ptr		Memory area to be freed
**
**	Return........:	(none)
**
**	Purpose.......: Free memory allocated with misc_alloc.
**
** ------------------------------------------------------------ */

void misc_free(char *file, int line, void *ptr)
{
	if (file == NULL)		/* Sanity check		*/
		file = "[unknown file]";

#if defined(COMPILE_DEBUG)
	debug(4, "free %p (%.*s:%d)", ptr, MAX_PATH_SIZE, file, line);
#else
	line = line;		/* Calm down picky compilers...	*/
#endif

	if (ptr != NULL)
		free(ptr);
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_usage
**
**	Parameters....:	fmt		Printf-string with usage
**
**	Return........:	(none)
**
**	Purpose.......: Print a usage info and terminate.
**
** ------------------------------------------------------------ */

void misc_usage(char *fmt, ...)
{
	va_list aptr;
	int i;

	if (use_ptr != NULL) {
		for (i = 0; use_ptr[i] != NULL; i++)
			fprintf(stderr, "%s\n", use_ptr[i]);
	}

	if (fmt != NULL && *fmt != '\0') {
		fprintf(stderr, "%s Error: ", p_name);
		va_start(aptr, fmt);
		vfprintf(stderr, fmt, aptr);
		va_end(aptr);
		fprintf(stderr, "\n\n");
	}

	exit(EXIT_FAILURE);
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_die
**
**	Parameters....:	fmt		Printf-string with message
**
**	Return........:	(none)
**
**	Purpose.......: Print an error message and terminate.
**
** ------------------------------------------------------------ */

void misc_die(char *file, int line, char *fmt, ...)
{
	int tmperr = errno;		/* Save errno for later	*/
	char str[MAX_PATH_SIZE * 4];
	va_list aptr;
	size_t len;

	if (file == NULL)		/* Sanity check		*/
		file = "[unknown file]";

	memset(str, 0, sizeof(str));
#if defined(HAVE_SNPRINTF)
	snprintf(str, sizeof(str), "%s (%.*s:%d): ",
	         p_name, MAX_PATH_SIZE, file, line);
#else
	sprintf(str, "%s (%.*s:%d): ",
			p_name, MAX_PATH_SIZE, file, line);
#endif
	len = strlen(str);

	if (fmt != NULL && *fmt != '\0') {
		va_start(aptr, fmt);
#if defined(HAVE_VSNPRINTF)
		vsnprintf(str + len, sizeof(str)-len, fmt, aptr);
#else
		vsprintf(str + len, fmt, aptr);
#endif
		va_end(aptr);
		len = strlen(str);
	}
	if (tmperr) {
#if defined(HAVE_SNPRINTF)
		snprintf(str + len, sizeof(str)-len,
		         " (errno=%d [%.256s])",
		         tmperr, strerror(tmperr));
#else
		sprintf(str + len, " (errno=%d [%.256s])",
		        tmperr, strerror(tmperr));
#endif
	}

	fprintf(stderr, "%s\n", str);
	syslog_write(T_FTL, "%s", str);

	errno = tmperr;			/* Restore errno	*/
	exit(EXIT_FAILURE);
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_pidfile
**
**	Parameters....:	name		Desired PID-file name
**
**	Return........:	(none)
**
**	Purpose.......: Create a file with the Process-ID.
**
** ------------------------------------------------------------ */

void misc_pidfile(char *name)
{
	FILE *fp;
	int fd;

	if (initflag == 0) {
		atexit(misc_cleanup);
		initflag = 1;
	}

	/*
	** Do some housekeeping (maybe it's just a close)
	*/
	if (misc_strequ(name, pid_name))
		return;
	if (pid_name != NULL) {
		void *tmp = (void *) pid_name;
		unlink(pid_name);
		pid_name = NULL;
		misc_free(FL, tmp);
	}

	/*
	** Do we have a real filename now?
	*/
	if (name != NULL) {
		if (unlink(name) < 0 && errno != ENOENT) {
			syslog_error("can't remove pidfile '%.*s'",
			             MAX_PATH_SIZE, name);
			exit(EXIT_FAILURE);
		}
		if ((fd = open(name, O_RDWR | O_CREAT | O_EXCL, 0644)) < 0)
		{
			syslog_error("can't open pidfile '%.*s'",
			             MAX_PATH_SIZE, name);
			exit(EXIT_FAILURE);
		}
		if ((fp = fdopen(fd, "w")) == NULL) {
			syslog_error("can't open pidfile '%.*s'",
			             MAX_PATH_SIZE, name);
			exit(EXIT_FAILURE);
		}
		fprintf(fp, "%d\n", (int) getpid());
		fclose(fp);
		pid_name = misc_strdup(FL, name);
	}

#if defined(COMPILE_DEBUG)
	debug(2, "pid-file: '%s'", NIL(pid_name));
#endif
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_strtrim
**
**	Parameters....:	s		String to be trimmed
**
**	Return........:	String without leading or trailing space
**
**	Purpose.......: Trims white space at the beginning and end
**			of a given string (this is done in-place).
**
** ------------------------------------------------------------ */

char *misc_strtrim(char *s)
{
	char *p;

	if (s == NULL)
		return NULL;
	while (*s == ' ' || *s == '\t')
		s++;

	p = s + strlen(s);
	while (p > s && (p[-1] == ' '  || p[-1] == '\t' ||
	                 p[-1] == '\n' || p[-1] == '\r'))
		*--p = '\0';

	return s;
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_strequ / misc_strcaseequ
**
**	Parameters....:	s1		First string to compare
**			s2		Second string to compare
**
**	Return........:	1=strings are equal, 0=strings differ
**
**	Purpose.......: Check if two strings are equal. The
**			strings could well be NULL pointers.
**			And strcasecmp ignores upper/lower case.
**
** ------------------------------------------------------------ */

int misc_strequ(const char *s1, const char *s2)
{
	if (s1 == NULL && s2 == NULL)
		return 1;
	if (s1 == NULL && s2 != NULL)
		return 0;
	if (s1 != NULL && s2 == NULL)
		return 0;
	return (strcmp(s1, s2) == 0);
}


int misc_strcaseequ(const char *s1, const char *s2)
{
	if (s1 == NULL && s2 == NULL)
		return 1;
	if (s1 == NULL && s2 != NULL)
		return 0;
	if (s1 != NULL && s2 == NULL)
		return 0;
	return (strcasecmp(s1, s2) == 0);
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_strnequ / misc_strncaseequ
**
**	Parameters....:	s1		First string to compare
**			s2		Second string to compare
**			n		number of characters in
**					in s1 to compare
**
**	Return........:	1=strings are equal, 0=strings differ
**
**	Purpose.......: Check if two strings are equal. The
**			strings could well be NULL pointers.
**			strncasecmp ignores upper/lower case.
**
** ------------------------------------------------------------ */

int misc_strnequ(const char *s1, const char *s2, size_t n)
{
	if (s1 == NULL && s2 == NULL)
		return 1;
	if (s1 == NULL && s2 != NULL)
		return 0;
	if (s1 != NULL && s2 == NULL)
		return 0;
	return (strncmp(s1, s2, n) == 0);
}

int misc_strncaseequ(const char *s1, const char *s2, size_t n)
{
	if (s1 == NULL && s2 == NULL)
		return 1;
	if (s1 == NULL && s2 != NULL)
		return 0;
	if (s1 != NULL && s2 == NULL)
		return 0;
	return (strncasecmp(s1, s2, n) == 0);
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_strncpy
**
**	Parameters....:	s1		Destination pointer
**			s2		Source pointer
**			len		Size of Destination buffer
**
**	Return........:	Destination pointer
**
**	Purpose.......: Copies at most (len - 1) bytes from source
**			to destination and fills the residual space
**			of the destination buffer with null bytes.
**
** ------------------------------------------------------------ */

char *misc_strncpy(char *s1, const char *s2, size_t len)
{
	size_t cnt;

	/*
	** Prepare the destination buffer
	*/
	if (s1 == NULL)
		return NULL;
	memset(s1, 0, len);

	/*
	** Check the source and get its size
	*/
	if (s2 == NULL || (cnt = strlen(s2)) == 0)
		return s1;

	/*
	** Copy at most (len - 1) bytes
	*/
	if (cnt >= len)
		cnt = len - 1;
	memcpy(s1, s2, cnt);

	/*
	** Done -- return destination pointer
	*/
	return s1;
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_chroot
**
**	Parameters....:	dir	chroot directory
**
**	Return........:	0 on success, -1 if dir argument
**	               was emtpy; exits program on error
**
**	Purpose.......:	change root into specified directory
**
** ------------------------------------------------------------ */

int misc_chroot (char *dir)
{
	if(dir && *dir) {
		chdir("/");
		if (chroot(dir)) {
			syslog_error("can't chroot to '%.1024s'", dir);
			exit(EXIT_FAILURE);
		}
		chdir("/");
		return 0;
	}
	return -1;
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_uidgid
**
**	Parameters....:	uid		UID (-1 -> use config_uid)
**			gid		GID (-1 -> use config_gid)
**
**	Return........:	(none), exits program on error
**
**	Purpose.......: Set the UID and GID for the current process.
**			If the parameters are -1, use the config
**			file's "User" and "Group" variables.
**
** ------------------------------------------------------------ */

void misc_uidgid(uid_t uid, gid_t gid)
{
#if defined(COMPILE_DEBUG)
	debug(2, "uid-gid desired: uid=%d gid=%d",
					(int) uid, (int) gid);
#endif

	if (gid == CONFIG_GID) {
		if(config_str(NULL, "Group", NULL)) {
			/*
			** if config defines a group, use it
			** or complain (not found in system)
			*/
			gid = config_gid(NULL, "Group", CONFIG_GID);
		} else {
			gid = getgid();
		}
	}
	if (gid == CONFIG_GID) {
		syslog_error("can't determine Group-ID to use");
		exit(EXIT_FAILURE);
	}
	if (setgid(gid) < 0) {
		syslog_error("can't set Group-ID to %d", (int) gid);
		exit(EXIT_FAILURE);
	}
	if (getegid() != gid) {
		syslog_error("can't set Group-ID to %d", (int) gid);
		exit(EXIT_FAILURE);
	}

	if (uid == CONFIG_UID) {
		if(config_str(NULL, "User", NULL)) {
			/*
			** if config defines a user, use it
			** or complain (not found in system)
			*/
			uid = config_uid(NULL, "User", CONFIG_UID);
		} else {
			uid = getuid();
		}
	}
	if (uid == CONFIG_UID) {
		syslog_error("can't determine User-ID to use");
		exit(EXIT_FAILURE);
	}
	if (setuid(uid) < 0) {
		syslog_error("can't set User-ID to %d", (int) uid);
		exit(EXIT_FAILURE);
	}
	if (geteuid() != uid) {
		syslog_error("can't set User-ID to %d", (int) uid);
		exit(EXIT_FAILURE);
	}

#if defined(COMPILE_DEBUG)
	debug(2, "uid-gid adopted: uid=%d gid=%d",
				(int) getuid(), (int) getgid());
#endif
}


/* ------------------------------------------------------------ **
**
**	Function......:	misc_rand
**
**	Parameters....:	lower range mark
**			upper range mark
**
**	Return........:	random number between lower and upper mark
**
**	Purpose.......: generates a random number in specified range.
**
** ------------------------------------------------------------ */

int misc_rand (int lrng, int urng)
{
	struct timeval t; 

	if (lrng == urng) return lrng; 
	if (lrng > urng) {
		/* swap values */
		lrng ^= urng;
		urng ^= lrng;
		lrng ^= urng;
	}

	gettimeofday (&t, NULL); 
	srand (t.tv_usec);

	return (lrng + (rand () % (urng - lrng + 1)));
}

/* ------------------------------------------------------------
 * $Log: com-misc.c,v $
 * Revision 1.9.2.1  2003/05/07 11:15:05  mt
 * misc_strdup: changed to allow empty strings
 * misc_rand: removed sequence in lrng/urng swapping
 *
 * Revision 1.9  2002/05/02 12:59:00  mt
 * merged with v1.8.2.2
 *
 * Revision 1.8.2.1  2002/01/28 01:53:07  mt
 * implemented misc_strnequ misc_strncaseequ wrappers
 *
 * Revision 1.8  2002/01/14 18:18:50  mt
 * implemented misc_chroot wrapper function
 * added checks in misc_uidgid if User/Group are set in config
 * added snprintf usage if supported, replaced all strcpy with strncpy
 *
 * Revision 1.7  2001/11/06 23:04:43  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
 *
 * Revision 1.6  1999/09/30 09:49:45  wiegand
 * updated string trim function to trim also newlines
 *
 * Revision 1.5  1999/09/26 13:25:05  wiegand
 * protection of debug/pid/log files against attacks
 *
 * Revision 1.4  1999/09/21 05:42:28  wiegand
 * syslog / abort review
 *
 * Revision 1.3  1999/09/17 06:32:28  wiegand
 * buffer length and overflow protection review
 *
 * Revision 1.2  1999/09/16 14:26:33  wiegand
 * minor code review and cleanup
 *
 * Revision 1.1  1999/09/15 14:05:38  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

