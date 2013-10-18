/*
 * $Id: ftp-cmds.h,v 1.2 1999/09/24 06:38:52 wiegand Exp $
 *
 * Header for FTP Proxy command handling
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

#if !defined(_FTP_CMDS_H_)
#define _FTP_CMDS_H_

/* ------------------------------------------------------------ */

typedef struct {
	char *name;		/* Name of the FTP command...	*/
	void (*func)(CONTEXT *, char *);
				/* ..and corresponding function	*/

#if defined(HAVE_REGEX)
	void *regex;		/* Regular expr. for argument	*/
#endif

	int legal;		/* 1=command allowed, 0=nope	*/
	int len;		/* Length of name (for speed)	*/
} CMD;


/* ------------------------------------------------------------ */

CMD *cmds_get_list(void);

void cmds_set_allow(char *allow);

#if defined(HAVE_REGEX)
char *cmds_reg_comp(void **ppre, char *ptr);
char *cmds_reg_exec(void *regex, char *str);
#endif


/* ------------------------------------------------------------ */

#endif /* defined(_FTP_CMDS_H_) */

/* ------------------------------------------------------------
 * $Log: ftp-cmds.h,v $
 * Revision 1.2  1999/09/24 06:38:52  wiegand
 * added regular expressions for all commands
 * removed character map and length of paths
 * added flag to reset PASV on every PORT
 * added "magic" user with built-in destination
 * added some argument pointer fortification
 *
 * Revision 1.1  1999/09/15 14:06:22  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

