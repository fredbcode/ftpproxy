/*
 * $Id: com-syslog.h,v 1.3 2002/01/14 18:30:15 mt Exp $
 *
 * Header for common file/syslog logging functions
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

#if !defined(_COM_SYSLOG_H_)
#define _COM_SYSLOG_H_

/* ------------------------------------------------------------ */

#define T_DBG		1	/* Technical log level DEBUG	*/
#define T_INF		2	/* Technical log level INFO	*/
#define T_WRN		3	/* Technical log level WARNING	*/
#define T_ERR		4	/* Technical log level ERROR	*/
#define T_FTL		5	/* Technical log level FATAL	*/

#define U_DBG		11	/* User rel. log level DEBUG	*/
#define U_INF		12	/* User rel. log level INFO	*/
#define U_WRN		13	/* User rel. log level WARNING	*/
#define U_ERR		14	/* User rel. log level ERROR	*/
#define U_FTL		15	/* User rel. log level FATAL	*/


/* ------------------------------------------------------------ */

void syslog_stderr(void);
void syslog_open  (char *name, char *level);
void syslog_write (int level, char *fmt, ...);
void syslog_error (char *fmt, ...);
int  syslog_rename(char *new_name, char *log_name, size_t len);
void syslog_rotate(void);
void syslog_close (void);

/* ------------------------------------------------------------ */

#endif /* defined(_COM_SYSLOG_H_) */

/* ------------------------------------------------------------
 * $Log: com-syslog.h,v $
 * Revision 1.3  2002/01/14 18:30:15  mt
 * implemented syslog_stderr function to redirect log to stderr
 * added LogLevel option handling allowing to set the maximal level
 * added snprintf usage, replaced strcpy/strncpy with misc_strncpy
 *
 * Revision 1.2  2001/11/06 23:04:43  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
 *
 * Revision 1.1  1999/09/15 14:05:38  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

