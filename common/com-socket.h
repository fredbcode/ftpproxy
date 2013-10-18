/*
 * $Id: com-socket.h,v 1.5.2.1 2003/05/07 11:13:34 mt Exp $
 *
 * Header for common functions for TCP/IP sockets
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

#if !defined(_COM_SOCKET_H_)
#define _COM_SOCKET_H_

/* ------------------------------------------------------------ */

#include <sys/types.h>
#include <sys/socket.h>

#if !defined(INADDR_NONE)
#  if defined(INADDR_BROADCAST)
#    define INADDR_NONE INADDR_BROADCAST
#  else
#    define INADDR_NONE ((uint32_t) 0xffffffffU)
#  endif
#endif

#if !defined(INPORT_ANY)
#  define   INPORT_ANY   0
#endif

#if !defined(MAXHOSTNAMELEN)
#  define MAXHOSTNAMELEN 256
#endif

/* ------------------------------------------------------------ */

#define SK_LISTEN	1	/* Kind: listening socket	*/
#define SK_CONTROL	2	/* Kind: control connection	*/
#define SK_DATA		3	/* Kind: data transfer		*/

#define LOC_END		1	/* Local end of connection	*/
#define REM_END		2	/* Remote end of connection	*/

#define PEER_LEN	32	/* Storage for dotted decimal	*/

#define MAX_RETRIES	6	/* bind retries on EADDRINUSE	*/

typedef void (*ACPT_CB)(int);	/* Accept callback function	*/


/* ------------------------------------------------------------ */

/*
** Definition of a "High Level Socket"
*/

typedef struct buf_t {
	struct buf_t *next;	/* Next one in the chain	*/
	size_t  len;		/* Number of bytes at ptr	*/
	size_t  cur;		/* Currently used offset	*/
	int     flg;		/* Flag for send() (e.g. OOB)	*/
	char    dat[8];		/* Beginning of data (Guard)	*/
} BUF;

typedef struct hls_t {
	struct hls_t *next;	/* Next one in the chain	*/
	int       sock;		/* The corresponding socket	*/
	int       kill;		/* 1=kill socket after send	*/
	int       ernr;		/* socket i/o error number	*/
	int       retr;		/* recv i/o retry counter	*/
	int       flag;		/* Flag for send() (e.g. OOB)	*/
	int       more;		/* 1=read more to complete line	*/
	u_int32_t addr;		/* Peer's address (host order)	*/
	u_int16_t port;		/* Peer's port (host order)	*/
	char      peer[PEER_LEN]; /* Peer's readable address	*/
	char     *ctyp;		/* Connection type identifier	*/
	BUF      *wbuf;		/* Write buffer chain		*/
	BUF      *rbuf;		/* Read buffer chain		*/
	size_t    wcnt;		/* write bytes counter		*/
	size_t    rcnt;		/* read bytes counter		*/
} HLS;


/* ------------------------------------------------------------ */

int  socket_listen (u_int32_t addr, u_int16_t port, ACPT_CB func);
void socket_lclose (int shut);

HLS  *socket_init  (int sock);
void  socket_opts  (int sock, int kind);
void  socket_kill  (HLS *hls);
char *socket_gets  (HLS *hls, char *ptr, int len);
void  socket_flag  (HLS *hls, int flag);
int   socket_write (HLS *hls, char *ptr, int len);
int   socket_printf(HLS *hls, char *fmt, ...);
int   socket_file  (HLS *hls, char *file, int crlf);

int   socket_exec  (int timeout, int *close_flag);

char *socket_msgline(char *fmt);

u_int16_t socket_d_bind   (int sock, u_int32_t addr,
			   u_int16_t lrng, u_int16_t urng,
			   int incr);

u_int16_t socket_d_listen (u_int32_t addr,
			   u_int16_t lrng, u_int16_t urng,
			   HLS **phls, char *ctyp,
			   int incr);

u_int16_t socket_d_connect(u_int32_t addr, u_int16_t port,
			   u_int32_t ladr,
			   u_int16_t lrng, u_int16_t urng,
			   HLS **phls, char *ctyp,
			   int incr);

u_int32_t  socket_str2addr(char *name, u_int32_t dflt);
u_int16_t  socket_str2port(char *name, u_int16_t dflt);
char      *socket_addr2str(u_int32_t addr);
u_int32_t  socket_sck2addr(int sock, int peer, u_int16_t *port);

int        socket_chkladdr(u_int32_t addr);
int        socket_orgdst(HLS *phls, u_int32_t *addr, u_int16_t *port);

int        getfqhostname(char *fqhost, size_t n);
int        getfqdomainname(char *fqdomain, size_t n);

/* ------------------------------------------------------------ */

#endif /* defined(_COM_SOCKET_H_) */

/* ------------------------------------------------------------
 * $Log: com-socket.h,v $
 * Revision 1.5.2.1  2003/05/07 11:13:34  mt
 * added hls->retr -- recv i/o retry counter
 *
 * Revision 1.5  2002/05/02 13:01:32  mt
 * merged with v1.8.2.2
 *
 * Revision 1.4.2.1  2002/04/04 14:33:17  mt
 * added ernr flag in hls needed to remember failures
 *
 * Revision 1.4  2002/01/14 18:26:55  mt
 * implemented socket_orgdst to read transparent proxying destinations
 * implemented a MaxRecvBufSize option limiting max recv buffer size
 * implemented workarround for Netscape (4.x) directory symlink handling
 * extended log messages to provide basic transfer statistics data
 * fixed socket_gets to wait for a complete line if no EOL found
 * added snprintf usage, replaced strcpy/strncpy with misc_strncpy
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

