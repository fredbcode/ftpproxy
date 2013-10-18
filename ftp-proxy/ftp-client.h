/*
 * $Id: ftp-client.h,v 1.6.2.1 2003/05/07 11:12:03 mt Exp $
 *
 * Header for the FTP Proxy client handling
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

#if !defined(_FTP_CLIENT_H_)
#define _FTP_CLIENT_H_

#include "com-socket.h"		/* Make sure we know PEER_LEN	*/


/* ------------------------------------------------------------ */

/*
** Define the necessary Telnet support
*/

#if !defined(DM)
#  define DM		242	/* Data Mark			*/
#endif
#if !defined(IP)
#  define IP		244	/* Interrupt Process		*/
#endif
#if !defined(WILL)
#  define WILL		251	/* I will perform option	*/
#endif
#if !defined(WONT)
#  define WONT		252	/* I won't perform option	*/
#endif
#if !defined(DO)
#  define DO		253	/* Please do perform option	*/
#endif
#if !defined(DONT)
#  define DONT		254	/* Please don't perform option	*/
#endif
#if !defined(IAC)
#  define IAC		255	/* Interpret as Command		*/
#endif


/* ------------------------------------------------------------ */

#if !defined(IPPORT_FTP)
#  define IPPORT_FTP	21	/* Usually "well known"		*/
#endif

#define MOD_RESET	0	/* Reset mode to Active FTP	*/
#define MOD_ACT_FTP	1	/* Active FTP mode		*/
#define MOD_PAS_FTP	2	/* Passive FTP mode		*/
#define MOD_CLI_FTP	3	/* Same FTP mode as client	*/

#define EXP_IDLE	0	/* Idle: expect nothing		*/
#define EXP_CONN	1	/* Connect: expect 220 or 421	*/
#define EXP_USER	2	/* USER: expect 230, 331 or 5xx	*/
#define EXP_ABOR	3	/* ABOR: expect 226 *and* 230	*/
#define EXP_PASV	4	/* PASV: expect 227		*/
#define EXP_PORT	5	/* PORT: expect 200		*/
#define EXP_XFER	6	/* Transfer: expect 226		*/
#define EXP_PTHR	7	/* Pass-Through: just relay	*/

#define UAUTH_NONE	0	/* No user auth used		*/
#define UAUTH_FTP	1	/* Auth with ftp user + pass	*/
#define UAUTH_MAU	2	/* Magic auth mode auth%user	*/
#define UAUTH_MUA	3	/* Magic auth mode user%auth	*/

typedef struct {
	HLS *cli_ctrl;		/* Control path to the client	*/
	HLS *cli_data;		/* Data path to the client	*/
	HLS *srv_ctrl;		/* Control path to the server	*/
	HLS *srv_data;		/* Data path to the server	*/

	char *username;		/* Client's ftp-username	*/
	char *userpass;		/* Client's ftp-password	*/
	char *userauth;		/* Client's user auth name	*/

	int   auth_mode;	/* Client auth mode flag	*/
	char *magic_auth;	/* Magic-Auth mode string	*/

	u_int32_t magic_addr;	/* The "real" destination ...	*/
	u_int16_t magic_port;	/* ... and corresponding port	*/

	int cli_mode;		/* Transfer mode to client	*/
	u_int32_t cli_addr;	/* Address from client PORT	*/
	u_int16_t cli_port;	/* TCP port from client PORT	*/

	u_int16_t act_lrng;	/* Lower port range (active)	*/
	u_int16_t act_urng;	/* Upper port range (active)	*/
	u_int16_t pas_lrng;	/* Lower port range (passive)	*/
	u_int16_t pas_urng;	/* Upper port range (passive)	*/

	int same_adr;		/* 1=PORT to same address only	*/

	int srv_mode;		/* Transfer mode to server	*/
	u_int32_t srv_addr;	/* Destination server IP addr	*/
	u_int16_t srv_port;	/* Destination server port	*/
	u_int16_t srv_lrng;	/* Lower port range to server	*/
	u_int16_t srv_urng;	/* Upper port range to server	*/

	char *curr_cmd;		/* Current outstanding command	*/
	int expect;		/* Expected answer from server	*/

	int timeout;		/* Inactivity timeout in secs	*/

	time_t sess_beg;	/* Start time of session	*/

	char   xfer_cmd[16];	/* Outstanding transfer cmd	*/
	char   xfer_arg[1024];	/* Argument for xfer_cmd	*/
	char   xfer_rep[1024];	/* Outstanding server reply	*/
	time_t xfer_beg;	/* Start time of data transfer	*/
	size_t xfer_rcnt;	/* bytes, read transfers	*/
	size_t xfer_rsec;	/* secs, read transfers		*/
	size_t xfer_wcnt;	/* bytes, write transfers	*/
	size_t xfer_wsec;	/* secs, write transfers	*/
} CONTEXT;


/* ------------------------------------------------------------ */

void client_run    (void);
void client_reinit (void);
void client_respond(int code, char *file, char *fmt, ...);
void client_data_reset(int mode);

int  client_setup(char *pwd);
void client_srv_open(void);

/* ------------------------------------------------------------ */

#endif /* defined(_FTP_CLIENT_H_) */

/* ------------------------------------------------------------
 * $Log: ftp-client.h,v $
 * Revision 1.6.2.1  2003/05/07 11:12:03  mt
 * added ctx->auth_mode variale and UAUTH_ flags to remember auth mode
 *
 * Revision 1.6  2002/05/02 13:15:36  mt
 * implemented simple (ldap based) user auth
 *
 * Revision 1.5  2002/01/14 19:35:44  mt
 * implemented workarround for Netscape (4.x) directory symlink handling
 * implemented a MaxRecvBufSize option limiting max recv buffer size
 * extended log messages to provide basic transfer statistics data
 * added snprintf usage if supported, replaced strncpy with misc_strncpy
 *
 * Revision 1.4  1999/09/24 06:38:52  wiegand
 * added regular expressions for all commands
 * removed character map and length of paths
 * added flag to reset PASV on every PORT
 * added "magic" user with built-in destination
 * added some argument pointer fortification
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

