/*
 * $Id: com-misc.h,v 1.5 2002/05/02 12:59:22 mt Exp $
 *
 * Header for common miscellaneous functions
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

#if !defined(_COM_MISC_H_)
#define _COM_MISC_H_

/* ------------------------------------------------------------ */

#define FL		__FILE__, __LINE__

#define NIL(p)		(p) ? (p) : "(nil)"

/*
** we are treating an -1 UID/GID as invalid
** _and_ as flag to read it from config file
*/
#define CONFIG_UID	((uid_t)(-1))	/* use cfg-file UID	*/
#define CONFIG_GID	((gid_t)(-1))	/* use cfg-file GID	*/


/* ------------------------------------------------------------ */

#if !defined(MAX_PATH_SIZE)
#  define MAX_PATH_SIZE		4096
#endif
#if defined(PATH_MAX) && (PATH_MAX > MAX_PATH_SIZE)
#  define MAX_PATH_SIZE		PATH_MAX
#endif
#if defined(MAXPATHLEN) && (MAXPATHLEN > MAX_PATH_SIZE)
#  define MAX_PATH_SIZE		MAXPATHLEN
#endif


/* ------------------------------------------------------------ */

void  misc_forget (void);

char *misc_setprog(char *prog_str, char *usage_arr[]);
char *misc_getprog(void);
void  misc_setvers(char *vers_str);
char *misc_getvers(void);
void  misc_setdate(char *date_str);
char *misc_getdate(void);
char *misc_getvsdt(void);

void *misc_alloc  (char *file, int line, size_t len);
char *misc_strdup (char *file, int line, char *str);
void  misc_free   (char *file, int line, void *ptr);

void  misc_usage  (char *fmt, ...);
void  misc_die    (char *file, int line, char *fmt, ...);

void  misc_pidfile(char *name);

char *misc_strtrim   (char *s);
int   misc_strequ    (const char *s1, const char *s2);
int   misc_strcaseequ(const char *s1, const char *s2);
int   misc_strnequ    (const char *s1, const char *s2, size_t n);
int   misc_strncaseequ(const char *s1, const char *s2, size_t n);
char *misc_strncpy   (char *s1, const char *s2, size_t len);

int   misc_chroot (char *dir);
void  misc_uidgid (uid_t uid, gid_t gid);
int   misc_rand (int lrng, int urng);

/* ------------------------------------------------------------ */

#endif /* defined(_COM_MISC_H_) */

/* ------------------------------------------------------------
 * $Log: com-misc.h,v $
 * Revision 1.5  2002/05/02 12:59:22  mt
 * merged with v1.8.2.2
 *
 * Revision 1.4.2.1  2002/01/28 01:53:07  mt
 * implemented misc_strnequ misc_strncaseequ wrappers
 *
 * Revision 1.4  2002/01/14 18:18:50  mt
 * implemented misc_chroot wrapper function
 * added checks in misc_uidgid if User/Group are set in config
 * added snprintf usage if supported, replaced all strcpy with strncpy
 *
 * Revision 1.3  2001/11/06 23:04:43  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
 *
 * Revision 1.2  1999/09/17 06:32:28  wiegand
 * buffer length and overflow protection review
 *
 * Revision 1.1  1999/09/15 14:05:38  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

