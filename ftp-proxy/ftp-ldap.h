/*
 * $Id: ftp-ldap.h,v 1.4.2.1 2003/05/07 11:09:27 mt Exp $
 *
 * Header for FTP Proxy LDAP interface handling
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

#if !defined(_FTP_LDAP_H_)
#define _FTP_LDAP_H_

/* ------------------------------------------------------------ */

/*
** default minimal password length used for user auth
*/
#if !defined(PASS_MIN_LEN)
#    define  PASS_MIN_LEN	5
#endif

int  ldap_setup_user(CONTEXT *ctx, char *who, char *pwd);


/* ------------------------------------------------------------ */

#endif /* defined(_FTP_LDAP_H_) */

/* ------------------------------------------------------------
 * $Log: ftp-ldap.h,v $
 * Revision 1.4.2.1  2003/05/07 11:09:27  mt
 * - moved user profile-config reading to ftp-client.c
 * - added LDAP_VERSION handling with LDAPv3 default
 * - improved user-auth to support auth via ldap-bind
 *
 * Revision 1.4  2002/05/02 13:17:12  mt
 * implemented simple (ldap based) user auth
 *
 * Revision 1.3  1999/09/24 06:38:52  wiegand
 * added regular expressions for all commands
 * removed character map and length of paths
 * added flag to reset PASV on every PORT
 * added "magic" user with built-in destination
 * added some argument pointer fortification
 *
 * Revision 1.2  1999/09/17 16:32:29  wiegand
 * changes from source code review
 * added POSIX regular expressions
 *
 * Revision 1.1  1999/09/15 14:06:22  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

