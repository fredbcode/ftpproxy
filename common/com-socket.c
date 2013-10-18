/*
 * $Id: com-socket.c,v 1.7.2.2 2005/01/10 11:37:36 mt Exp $
 *
 * Common functions for TCP/IP sockets
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
static char rcsid[] = "$Id: com-socket.c,v 1.7.2.2 2005/01/10 11:37:36 mt Exp $";
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

#if defined(HAVE_SYS_SELECT_H)
#  include <sys/select.h>
#endif

#if defined(HAVE_FCNTL_H)
#  include <fcntl.h>
#elif defined(HAVE_SYS_FCNTL_H)
#  include <sys/fcntl.h>
#endif

#include <sys/ioctl.h>
#if defined(HAVE_SYS_FILIO_H)
#include <sys/filio.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#if defined(HAVE_NETINET_IN_SYSTM_H)
#   include <netinet/in_systm.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>

#if defined(HAVE_STROPTS_H)
#   include <stropts.h>
#endif
#if defined(HAVE_SYS_PARAM_H)
#   include <sys/param.h>
#endif
#if defined(HAVE_SYS_CONF_H)
#   include <sys/conf.h>
#endif
#if defined(HAVE_SYS_SOCKIO_H)
#  include <sys/sockio.h>
#endif
#if defined(I_NREAD) && (defined(__sun__) || !defined(FIONREAD))
#   define FIONREAD I_NREAD
#endif

#if defined(HAVE_NET_IF_H)
#  include <net/if.h>
#endif
#if defined(HAVE_NET_PFVAR_H)
#  include <net/pfvar.h>
#endif

#if defined(HAVE_NETINET_IP_H)
#   include <netinet/ip.h>
#endif

#if defined(HAVE_NETINET_IP_COMPAT_H)
#   include <netinet/ip_compat.h>
#endif
#if defined(HAVE_NETINET_IP_FIL_COMPAT_H)
#   include <netinet/ip_fil_compat.h>
#endif
#if defined(HAVE_NETINET_IP_FIL_H)
#   include <netinet/ip_fil.h>
#endif
#if defined(HAVE_NETINET_IP_NAT_H)
#   include <netinet/ip_nat.h>
#endif

#if defined(HAVE_LINUX_NETFILTER_IPV4_H)
#   include <linux/netfilter_ipv4.h>
#endif

#if defined(HAVE_LIBWRAP)
#   if defined(HAVE_SYSLOG_H)
#      include <syslog.h>
#   endif
#   if defined(NEED_SYS_SYSLOG_H)
#      include <sys/syslog.h>
#   endif
#   include <tcpd.h>
#endif

#include "com-config.h"
#include "com-debug.h"
#include "com-misc.h"
#include "com-socket.h"
#include "com-syslog.h"


/* ------------------------------------------------------------ */

#if !defined(SOMAXCONN)
#  define SOMAXCONN	5	/* Default accept queue size	*/
#endif

#if !defined(NETSIZ)
#  define NETSIZ	8192	/* Default network buffer size	*/
#endif


/* ------------------------------------------------------------ */

static void socket_cleanup (void);
static void socket_accept  (void);

static void socket_ll_read (HLS *hls);
static void socket_ll_write(HLS *hls);


/* ------------------------------------------------------------ */

static int initflag = 0;	/* Have we been initialized?	*/

static int lsock = -1;		/* Daemon: listening socket	*/
static ACPT_CB acpt_fp = NULL;	/* Call back function pointer	*/

static HLS *hlshead = NULL;	/* Chain of HighLevSock's	*/

#if defined(HAVE_LIBWRAP)
int allow_severity = LOG_INFO;	/* TCP Wrapper log levels	*/
int deny_severity  = LOG_WARNING;
#endif

static int maxrecv_bufsiz = -1;	/* max receive buffer size	*/

/* ------------------------------------------------------------ **
**
**	Function......:	socket_cleanup
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Clean up the socket related data.
**
** ------------------------------------------------------------ */

static void socket_cleanup(void)
{
	socket_lclose(1);

	while (hlshead != NULL)
		socket_kill(hlshead);
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_listen
**
**	Parameters....:	addr		IP address where to listen
**			port		TCP port where to listen
**
**	Return........:	0=success, -1=failure (EADDRINUSE)
**			Other errors make the program die.
**
**	Purpose.......: Opens a listening port.
**
** ------------------------------------------------------------ */

int socket_listen(u_int32_t addr, u_int16_t port, ACPT_CB func)
{
	struct sockaddr_in saddr;

	if (initflag == 0) {
		atexit(socket_cleanup);
		initflag = 1;

		/*
		** Check if we should limit the recv buffer size...
		** (because the link on the write side is much slower)
		*/
		if(maxrecv_bufsiz < 0) {
			maxrecv_bufsiz = config_int(NULL, "MaxRecvBufSize", 0);
			if(maxrecv_bufsiz < 0)
				maxrecv_bufsiz = 0;
		}
	}

	/*
	** Remember whom to call back for accept
	*/
	acpt_fp = func;

	/*
	** Prepare and open the listening socket
	*/
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_addr.s_addr = htonl(addr);
	saddr.sin_family      = AF_INET;
	saddr.sin_port        = htons(port);

#if defined(COMPILE_DEBUG)
	debug(2, "about to listen: %s:%d",
			inet_ntoa(saddr.sin_addr), (int) port);
#endif

	if ((lsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		syslog_error("can't create listener socket");
		exit(EXIT_FAILURE);
	}
	socket_opts(lsock, SK_LISTEN);

	if (bind(lsock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		if (errno == EADDRINUSE) {
			syslog_write(T_WRN,
				"port %d is in use...", (int) port);
			return -1;
		}
		syslog_error("can't bind to %s:%d",
				inet_ntoa(saddr.sin_addr), (int) port);
		exit(EXIT_FAILURE);
	}
	listen(lsock, SOMAXCONN);
	return 0;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_lclose
**
**	Parameters....:	shut		Call shutdown if non-zero
**
**	Return........:	(none)
**
**	Purpose.......: Close the listening socket.
**
** ------------------------------------------------------------ */

void socket_lclose(int shut)
{
	if (lsock != -1) {
		if (shut)
			shutdown(lsock, 2);
		close(lsock);
		lsock = -1;
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_accept
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Accept a new client connection.
**
** ------------------------------------------------------------ */

static void socket_accept(void)
{
	char peer[PEER_LEN] = {0};
	char dest[PEER_LEN] = {0};
	struct sockaddr_in saddr;
	int nsock, len;

	/*
	** Let the show begin ...
	*/
	memset(&saddr, 0, sizeof(saddr));
	len = sizeof(saddr);
	nsock = accept(lsock, (struct sockaddr *) &saddr, &len);
	if (nsock < 0) {
		syslog_error("can't accept client");
		return;
	}

	misc_strncpy(peer, inet_ntoa(saddr.sin_addr), sizeof(peer));
	memset(&saddr, 0, sizeof(saddr));
	if( !getsockname(nsock, (struct sockaddr *)&saddr, &len)) {
		misc_strncpy(dest, inet_ntoa(saddr.sin_addr), sizeof(dest));
	}

#if defined(COMPILE_DEBUG)
	debug(2, "accepted %d=%s on %s", nsock, NIL(peer), NIL(dest));
#endif

#if defined(HAVE_LIBWRAP)
	/*
	** Use the TCP Wrapper to control access
	*/
	if (config_bool(NULL, "TCPWrapper", 0)) {
		struct request_info req;
		char *wn;

		wn = config_str(NULL, "TCPWrapperName", misc_getprog());
		if( !(wn && *wn)) wn = "ftp-proxy"; /* fall back... */

		request_init(&req, RQ_DAEMON, wn,
					RQ_FILE, nsock, NULL);
		fromhost(&req);
		if (hosts_access(&req) == 0) {
			close(nsock);
			syslog_write(U_ERR,
				"%s reject: '%s' (Wrap)", wn, peer);
			return;
		}
	}
#endif

	/*
	** Setup some basic socket options
	*/
	socket_opts(nsock, SK_CONTROL);

	/*
	** Perform user level initialization
	*/
	if (acpt_fp)
		(*acpt_fp)(nsock);
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_init
**
**	Parameters....:	sock		Accepted new socket
**					Can be -1 (e.g. for
**					accepting sockets)
**
**	Return........:	Pointer to newly created Channel
**
**	Purpose.......: Allocate and initialize a new High
**			Level Socket (HLS).
**
** ------------------------------------------------------------ */

HLS *socket_init(int sock)
{
	HLS *hls;

	if (initflag == 0) {
		atexit(socket_cleanup);
		initflag = 1;

		/*
		** Check if we should limit the recv buffer size...
		** (because the link on the write side is much slower)
		*/
		if(maxrecv_bufsiz < 0) {
			maxrecv_bufsiz = config_int(NULL, "MaxRecvBufSize", 0);
			if(maxrecv_bufsiz < 0)
				maxrecv_bufsiz = 0;
		}
	}

	hls = (HLS *) misc_alloc(FL, sizeof(HLS));
	hls->next = hlshead;
	hlshead   = hls;

	if ((hls->sock = sock) != -1) {
		hls->addr = socket_sck2addr(sock, REM_END, &(hls->port));
		misc_strncpy(hls->peer, socket_addr2str(hls->addr),
		             sizeof(hls->peer));
	} else {
		hls->addr = 0;
		hls->port = 0;
		memset(hls->peer, 0, sizeof(hls->peer));
	}

	hls->kill = 0;
	hls->ernr = 0;
	hls->retr = 0;
	hls->flag = 0;
	hls->more = 0;
	hls->ctyp = "HLS-TYPE";

	hls->wbuf = NULL;
	hls->rbuf = NULL;

	hls->wcnt = 0;
	hls->rcnt = 0;

#if defined(COMPILE_DEBUG)
	debug(2, "created HLS for %d=%s:%d",
			hls->sock, hls->peer, (int) hls->port);
#endif
	return hls;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_opts
**
**	Parameters....:	sock		Socket to be worked upon
**			kind		SK_... value (a "Macro")
**
**	Return........:	(none)
**
**	Purpose.......: Setup socket options according to the
**			intended use (listen, control, data).
**
** ------------------------------------------------------------ */

void socket_opts(int sock, int kind)
{
#if defined(ENABLE_SO_LINGER)
	struct linger lin;
#endif
	int opt, len;

	opt = 1;
	len = sizeof(opt);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, len);

#if defined(ENABLE_SO_LINGER)
	if (kind == SK_LISTEN) {
		lin.l_onoff  = 0;
		lin.l_linger = 0;
	} else {
		lin.l_onoff  = 1;
		lin.l_linger = 60;
	}
	len = sizeof(lin);
	setsockopt(sock, SOL_SOCKET, SO_LINGER, &lin, len);
#endif

#if defined(SO_OOBINLINE)
	if (kind == SK_CONTROL) {
		opt = 1;
		len = sizeof(opt);
		setsockopt(sock, SOL_SOCKET, SO_OOBINLINE, &opt, len);
	}
#endif

	if (kind != SK_LISTEN) {
		opt = 1;
		len = sizeof(opt);
		setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, len);
	}

#if defined(IPTOS_THROUGHPUT) && defined(IPTOS_LOWDELAY)
	if (kind == SK_DATA)
		opt = IPTOS_THROUGHPUT;
	else
		opt = IPTOS_LOWDELAY;
	len = sizeof(opt);
	setsockopt(sock, IPPROTO_IP, IP_TOS, &opt, len);
#endif
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_kill
**
**	Parameters....:	hls		Pointer to HighLevSock
**
**	Return........:	(none)
**
**	Purpose.......: Destroy a High Level Socket.
**
** ------------------------------------------------------------ */

void socket_kill(HLS *hls)
{
	HLS *curr, *prev;
	BUF *buf;

	if (hls == NULL)		/* Basic sanity check	*/
		misc_die(FL, "socket_kill: ?hls?");

#if defined(COMPILE_DEBUG)
	debug(2, "deleting HLS %s %d=%s:%d", NIL(hls->ctyp),
			hls->sock, hls->peer, (int) hls->port);
#endif

	/*
	** Find and de-chain the socket
	*/
	for (curr = hlshead, prev = NULL; curr != NULL; ) {
		if (curr == hls) {
			if (prev == NULL)
				hlshead = curr->next;
			else
				prev->next = curr->next;
			break;
		}
		prev = curr;
		curr = curr->next;
	}

	/*
	** Now destroy the socket itself
	*/
	if (hls->sock != -1)
		close(hls->sock);
	for (buf = hls->wbuf; buf != NULL; ) {
		hls->wbuf = buf->next;
		misc_free(FL, buf);
		buf = hls->wbuf;
	}
	for (buf = hls->rbuf; buf != NULL; ) {
		hls->rbuf = buf->next;
		misc_free(FL, buf);
		buf = hls->rbuf;
	}
	misc_free(FL, hls);
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_gets
**
**	Parameters....:	hls		Pointer to HighLevSock
**			ptr		Pointer to read buffer
**			len		Size of buf to be filled
**					(includes trailing zero)
**
**	Return........:	Pointer to filled buf
**
**	Purpose.......: Read one line of input from a HighLevSock.
**			This function waits for complete lines with
**			(CR)LF at the end, which will be discarded.
**
** ------------------------------------------------------------ */

char *socket_gets(HLS *hls, char *ptr, int len)
{
	int cnt;
	BUF *buf;

	if (hls == NULL || ptr == NULL || len <= 0)
		misc_die(FL, "socket_gets: ?hls? ?ptr? ?len?");

	if (hls->rbuf == NULL) {
		errno = 0;
		return NULL;
	}
	len--;		/* Account for the trailing null byte */

	/*
	** Transfer at most one line of data
	*/
	hls->more = 0;
	for (buf = hls->rbuf, cnt = 0; buf != NULL && cnt < len; ) {
		if (buf->cur >= buf->len) {
			hls->rbuf = buf->next;
			misc_free(FL, buf);
			if(NULL == (buf = hls->rbuf)) {
				/*
				** last buffer in HLS and no EOL found;
				** restore the data into the HLS and
				** exit to wait to read more
				*/
				hls->more = 1;
				hls->rbuf = (BUF *)misc_alloc(FL, sizeof(BUF) + cnt);
				hls->rbuf->len = cnt;
				hls->rbuf->cur = 0;
				memcpy(hls->rbuf->dat, ptr, cnt);
#if defined(COMPILE_DEBUG)
				debug(4, "preread %d bytes while waiting "
					 "for end-of-line: '%.128s'%s",
					 cnt, hls->rbuf->dat,
					 (cnt > 128) ? "..." : "");
#endif
				return NULL;
			}
			continue;
		}
		if (buf->dat[buf->cur] == '\r')
			break;
		if (buf->dat[buf->cur] == '\n')
			break;
		ptr[cnt++] = buf->dat[buf->cur++];
	}
	ptr[cnt] = '\0';	/* Add the trailing null byte */

	/*
	** Remove possible newline and used up buffer
	*/
	if (buf != NULL) {
		while (buf->cur < buf->len &&
				buf->dat[buf->cur] == '\r')
			buf->cur++;
		while (buf->cur < buf->len &&
				buf->dat[buf->cur] == '\n')
			buf->cur++;
		if (buf->cur >= buf->len) {
			hls->rbuf = buf->next;
			misc_free(FL, buf);
			buf = hls->rbuf;
		}
	}

#if defined(COMPILE_DEBUG)
	debug(2, "gets %s %d=%s: %d bytes '%.128s'%s", hls->ctyp,
		hls->sock, hls->peer, cnt, ptr, (cnt > 128) ? "..." : "");
#endif
	return ptr;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_flag
**
**	Parameters....:	hls		Pointer to HighLevSock
**			flag		Flags to be applied
**
**	Return........:	(none)
**
**	Purpose.......: Set the send() flags for the next write.
**			They will be reset with the write/printf
**			function.
**
** ------------------------------------------------------------ */

void socket_flag(HLS *hls, int flag)
{
	if (hls == NULL)		/* Basic sanity check	*/
		misc_die(FL, "socket_flag: ?hls?");

	/*
	** Store for the next write / printf call
	*/
	hls->flag = flag;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_write
**
**	Parameters....:	hls		Pointer to HighLevSock
**			ptr		Pointer to write buffer
**			len		Number of bytes to write
**
**	Return........:	0=success, -1=failure
**
**	Purpose.......: Write to High Level Socket.
**
** ------------------------------------------------------------ */

int socket_write(HLS *hls, char *ptr, int len)
{
	BUF *buf, *tmp;

	if (hls == NULL || ptr == NULL)
		misc_die(FL, "socket_write: ?hls? ?ptr?");

	if (hls->kill != 0)	/* Socket already doomed?	*/
		return 0;

#if defined(COMPILE_DEBUG)
	debug(2, "write %s %d=%s: %d bytes",
			hls->ctyp, hls->sock, hls->peer, len);
#endif

	/*
	** Allocate a new buffer for the data
	*/
	buf = (BUF *) misc_alloc(FL, sizeof(BUF) + len);
	buf->len = len;
	buf->cur = 0;
	memcpy(buf->dat, ptr, len);

	buf->flg  = hls->flag;
	hls->flag = 0;

	/*
	** Chain the newly filled buffer
	*/
	if (hls->wbuf == NULL)
		hls->wbuf = buf;
	else {
		for (tmp = hls->wbuf; tmp->next; tmp = tmp->next)
			;
		tmp->next = buf;
	}
	buf->next = NULL;

	return 0;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_printf
**
**	Parameters....:	hls		Pointer to HighLevSock
**			fmt		Format string for output
**
**	Return........:	0=success, -1=failure
**
**	Purpose.......: Write to High Level Socket.
**
** ------------------------------------------------------------ */

int socket_printf(HLS *hls, char *fmt, ...)
{
	va_list aptr;
	char str[NETSIZ];
	int len;
	BUF *buf, *tmp;

	if (hls == NULL || fmt == NULL)
		misc_die(FL, "socket_printf: ?hls? ?fmt?");

	if (hls->kill != 0)	/* Socket already doomed?	*/
		return 0;

	/*
	** Prepare the new stuff to be written
	*/
	memset(str, 0, sizeof(str));
	va_start(aptr, fmt);
#if defined(HAVE_VSNPRINTF)
	vsnprintf(str, sizeof(str), fmt, aptr);
#else
	vsprintf(str, fmt, aptr);
#endif
	va_end(aptr);
	len = strlen(str);

#if defined(COMPILE_DEBUG)
	while (len > 0) {
		if (str[len-1] == '\r' || str[len-1] == '\n')
			len--;
		else
			break;
	}
	if (len > 128) {
		fmt = "...";
		len = 128;
	} else
		fmt = "";
	debug(2, "printf %s %d=%s: %d bytes '%.*s'%s", hls->ctyp,
		hls->sock, hls->peer, strlen(str), len, str, fmt);
	len = strlen(str);
#endif

	/*
	** Allocate a new buffer for the data
	*/
	buf = (BUF *) misc_alloc(FL, sizeof(BUF) + len);
	buf->len = len;
	buf->cur = 0;
	memcpy(buf->dat, str, len);

	buf->flg  = hls->flag;
	hls->flag = 0;

	/*
	** Chain the newly filled buffer
	*/
	if (hls->wbuf == NULL)
		hls->wbuf = buf;
	else {
		for (tmp = hls->wbuf; tmp->next; tmp = tmp->next)
			;
		tmp->next = buf;
	}
	buf->next = NULL;

	return 0;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_file
**
**	Parameters....:	hls		Pointer to HighLevSock
**			file		Name of file to print
**			crlf		0=send LF, 1=send CRLF
**
**	Return........:	0=success, -1=failure
**
**	Purpose.......: Output the contents of a file to the
**			High Level Socket. The line end can
**			either be LF or CRLF.
**
** ------------------------------------------------------------ */

int socket_file(HLS *hls, char *file, int crlf)
{
	char buf[1024], *p, *lend;
	FILE *fp;

	if (hls == NULL || file == NULL)
		misc_die(FL, "socket_file: ?hls? ?file?");

	lend = (crlf ? "\r\n" : "\n");

	if ((fp = fopen(file, "r")) == NULL)
		return -1;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if ((p = strchr(buf, '\n')) != NULL)
			*p = '\0';
		socket_printf(hls, "%s%s", buf, lend);
	}
	fclose(fp);

	return 0;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_exec
**
**	Parameters....:	timeout		Maximum seconds to wait
**			close_flag	Pointer to close_flag
**
**	Return........:	0=timeout, 1=activity, -1=error
**
**	Purpose.......: Prepare all relevant sockets, call the
**			select function (main waiting point),
**			and handle the outstanding actions.
**
** ------------------------------------------------------------ */

int socket_exec(int timeout, int *close_flag)
{
	HLS *hls;
	fd_set rfds, wfds;
	int fdcnt, i;
	struct timeval tv;

	/*
	** Prepare the select() input structures
	*/
	fdcnt = -1;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	/*
	** Allow the daemon listening socket to accept
	*/
	if (lsock != -1) {
		fdcnt = lsock;
		FD_SET(lsock, &rfds);
	}

	/*
	** Last but not least walk through the connections
	*/
	for (hls = hlshead; hls != NULL; hls = hls->next) {
		if (hls->sock == -1)
			continue;
		if (hls->kill != 0 && hls->wbuf == NULL) {
			close(hls->sock);
			hls->sock = -1;
#if defined(COMPILE_DEBUG)
			debug(4, "FD_CLR %s", hls->ctyp);
#endif
			/*
			** The following return ensures that
			** killed sockets will be detected.
			*/
			return 1;
		}
		if (hls->sock > fdcnt)
			fdcnt = hls->sock;
		if (hls->wbuf != NULL && hls->peer[0] != '\0') {
			FD_SET(hls->sock, &wfds);
#if defined(COMPILE_DEBUG)
			debug(4, "FD_SET %s for W", hls->ctyp);
#endif
		}
		if(hls->more >= 0) {
			FD_SET(hls->sock, &rfds);
#if defined(COMPILE_DEBUG)
			debug(4, "FD_SET %s for R", hls->ctyp);
#endif
		}
	}

	/*
	** If not a single descriptor remains, we are doomed
	*/
	if (fdcnt == -1) {
		if (close_flag)
			*close_flag = 1;
		return 1;	/* Return as non-defect situation */
	}

	/*
	** Wait for the next event
	*/
	tv.tv_sec  = timeout;
	tv.tv_usec = 0;
	i = select(fdcnt + 1, &rfds, &wfds, NULL, &tv);
	if (i == 0) {
#if defined(COMPILE_DEBUG)
		debug(2, "select: timeout (%d)", (int) time(NULL));
#endif
		return 0;
	}
	if (i < 0) {
		if (errno == EINTR)
			return 1;
		syslog_error("can't execute select");
		return -1;
	}

	/*
	** Check the various sources of events
	*/
	if (lsock != -1 && FD_ISSET(lsock, &rfds))
		socket_accept();
	for (hls = hlshead; hls != NULL; hls = hls->next) {

		if (hls->sock == -1)
			continue;

		if (FD_ISSET(hls->sock, &wfds))
			socket_ll_write(hls);
		if (hls->sock == -1)	/* May be dead by now */
			continue;

		if (FD_ISSET(hls->sock, &rfds))
			socket_ll_read(hls);
		if (hls->sock == -1)	/* May be dead by now */
			continue;

		if (hls->kill != 0 && hls->wbuf == NULL) {
			close(hls->sock);
			hls->sock = -1;
		}
	}
	return 1;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_ll_read
**
**	Parameters....:	hls		Pointer to HighLevSock
**
**	Return........:	(none)
**
**	Purpose.......: Socket low level read routine. If
**			peer is not set, we are listening.
**
** ------------------------------------------------------------ */

static void socket_ll_read(HLS *hls)
{
	int len, cnt, nsock;
	BUF *buf, *tmp;
	struct sockaddr_in saddr;

	if (hls == NULL)
		misc_die(FL, "socket_ll_read: ?hls?");

	/*
	** If the peer is not (yet) filled, this is a listening
	** socket. In this case we need to accept() the (data)
	** connection (e.g. FTP passive client or active server).
	*/
	if (hls->peer[0] == '\0') {
		memset(&saddr, 0, sizeof(saddr));
		len = sizeof(saddr);
		nsock = accept(hls->sock,
				(struct sockaddr *) &saddr, &len);
		if (nsock < 0) {
			hls->ernr = errno;
			syslog_error("can't accept %s", hls->ctyp);
			shutdown(hls->sock, 2);
			close(hls->sock);
			hls->sock = -1;
			return;
		}
		socket_opts(nsock, SK_DATA);

		/*
		** Update the High Level Socket
		*/
		shutdown(hls->sock, 2);		/* the "acceptor" */
		close(hls->sock);
		hls->sock = nsock;
		hls->addr = socket_sck2addr(nsock, REM_END, &(hls->port));
		misc_strncpy(hls->peer, socket_addr2str(hls->addr),
		             sizeof(hls->peer));
#if defined(COMPILE_DEBUG)
		debug(2, "accept %s (%d) from %s",
				hls->ctyp, hls->sock, hls->peer);
#endif
		return;
	}

	/*
	** Get the number of bytes waiting to be read
	*/
	len = 0;
	if( (cnt=ioctl(hls->sock, FIONREAD, &len)) < 0) {
		hls->ernr = errno;
		syslog_error("can't get num of bytes: %s %d=%s",
		             hls->ctyp, hls->sock, hls->peer);
		close(hls->sock);
		hls->sock = -1;
		return;
	}
#if defined(COMPILE_DEBUG)
	debug(4, "ll_read: FIONREAD reported %d bytes for %s %d=%s",
		len, hls->ctyp, hls->sock, hls->peer);
#endif

	/*
	** Check if the socket has been closed
	*/
	if (len == 0) {
#if defined(I_NREAD) && defined(__sun__)
		/*
		** solaris powers up select and returns "no data"
		** (both, len == cnt == 0) in the middle of a data
		** transfer; this was interpreted as EOF and has
		** caused transfer aborts on bigger files.
		** wait and retry before we assume this is a EOF.
		*/
		if((0 == cnt) && (++hls->retr < MAX_RETRIES)) {
			syslog_write(T_DBG,
			      "zero bytes to read reported: %s %d=%s",
			      hls->ctyp, hls->sock, hls->peer);
			usleep(10000);
			return;
		}
#endif

		/*
		** OK, EOF recived - should be cnt>0 and len == 0
		** on solaris / I_NREAD according to streamio(7I)
		*/
#if defined(COMPILE_DEBUG)
		debug(1, "closed: %s %d=%s, len=%d, cnt=%d",
			hls->ctyp, hls->sock, hls->peer, len, cnt);
#endif
		close(hls->sock);
		hls->sock = -1;
		return;
	}
	/*
	** else reset retry counter on success
	*/
	hls->retr = 0;

	/*
	** Limit the receive buffer sizes
	*/
	if(maxrecv_bufsiz > 0 && len > maxrecv_bufsiz)
		len = maxrecv_bufsiz;

	/*
	** Now read the data that is waiting
	*/
	buf = (BUF *) misc_alloc(FL, sizeof(BUF) + len);
	do {
		errno = 0;
		cnt = recv(hls->sock, buf->dat, len, 0);
	} while (cnt == -1 && EINTR == errno);

	if (cnt != len) {
		if(cnt > 0) {
			/*
			** hmm... seems to be solaris, isn't? :-)
			*/
			syslog_write(T_DBG,
			"recvd %d bytes while %d reported: %s %d=%s",
			cnt, len, hls->ctyp, hls->sock, hls->peer);
		} else {
			/*
			** report as error because we use FIONREAD
			** above and handle EOF's (len = 0) there...
			*/
			hls->ernr = errno;
			syslog_error("can't ll_read: %s %d=%s",
			             hls->ctyp, hls->sock, hls->peer);
			close(hls->sock);
			hls->sock = -1;
			misc_free(FL, buf);
			return;
		}
	}
	buf->len = cnt;
	buf->cur = 0;
	buf->flg = 0;

	/*
	** Update byte conter
	*/
	hls->rcnt += cnt;

	/*
	** Chain the newly filled buffer
	*/
	if (hls->rbuf == NULL)
		hls->rbuf = buf;
	else {
		for (tmp = hls->rbuf; tmp->next; tmp = tmp->next)
			;
		tmp->next = buf;
	}
	buf->next = NULL;

#if defined(COMPILE_DEBUG)
	debug(3, "ll_read %s %d=%s: %d/%d bytes",
			hls->ctyp, hls->sock, hls->peer,
			cnt, hls->rcnt);
#endif
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_ll_write
**
**	Parameters....:	hls		Pointer to HighLevSock
**
**	Return........:	(none)
**
**	Purpose.......: Socket low level write routine.
**
** ------------------------------------------------------------ */

static void socket_ll_write(HLS *hls)
{
	int cnt, tot;
	BUF *buf;

	if (hls == NULL)
		misc_die(FL, "socket_ll_write: ?hls?");

	/*
	** Try to send as much as possible
	*/
	for (buf = hls->wbuf, tot = 0; buf != NULL; ) {
		do
			cnt = send(hls->sock, buf->dat + buf->cur,
					buf->len - buf->cur, buf->flg);
		while (cnt == -1 && errno == EINTR);

		/*
		** Did we write anything?
		*/
		if (cnt < 0) {
			if (tot == 0) {
				hls->ernr = errno;
				syslog_error("can't ll_write: %s %d=%s",
				             hls->ctyp, hls->sock, hls->peer);
				close(hls->sock);
				hls->sock = -1;
				return;
			}
			break;	/* At least the first write was ok */
		}

#if defined(COMPILE_DEBUG)
		debug(4, "ll_write %s %d=%s: sent %d bytes",
			hls->ctyp, hls->sock, hls->peer, cnt);
#endif

		/*
		** Update byte conter
		*/
		tot += cnt;
		hls->wcnt += cnt;

		/*
		** Advance the write pointers
		*/
		if ((buf->cur += cnt) < buf->len)
			break;	/* Partly sent, try again later */

		/*
		** This buffer is done, try and send next one
		*/
		hls->wbuf = buf->next;
		misc_free(FL, buf);
		buf = hls->wbuf;
	}

#if defined(COMPILE_DEBUG)
	debug(3, "ll_write %s %d=%s: %d/%d bytes",
			hls->ctyp, hls->sock, hls->peer,
			tot, hls->wcnt);
#endif
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_msgline
**
**	Parameters....:	fmt		String to expand
**
**	Return........:	Pointer to expanded string
**			(Gets overwritten by subsequent calls)
**
**	Purpose.......: Compose a message line, by copying the
**			given string and expanding % escapes.
**
** ------------------------------------------------------------ */

char *socket_msgline(char *fmt)
{
	static char str[1024];
	char tmp[1024];
	size_t i, j;
	time_t now;
	struct tm *t;

	if (fmt == NULL)		/* Basic sanity check	*/
		misc_die(FL, "socket_msgline: ?fmt?");

	time(&now);
	t = localtime(&now);

	for (i = 0; (*fmt != '\0') && (i < (sizeof(str) - 64)); fmt++) {
		if (*fmt != '%') {
			str[i++] = *fmt;
			continue;
		}

		/*
		** Escape alert ...
		*/
		memset(tmp, 0, sizeof(tmp));
		switch (*++fmt) {
			case 'b':
			case 'B':
				strncpy(tmp, misc_getdate(), sizeof(tmp)-1);
				break;
			case 'd':
			case 'D':
#if defined(HAVE_SNPRINTF)
				snprintf(tmp, sizeof(tmp),
						"%04d/%02d/%02d",
						t->tm_year + 1900,
						t->tm_mon  + 1,
						t->tm_mday);
#else
				sprintf(tmp, "%04d/%02d/%02d",
						t->tm_year + 1900,
						t->tm_mon  + 1,
						t->tm_mday);
#endif
				break;
			case 'h':
			case 'H':
				if (gethostname(tmp, sizeof(tmp)) < 0)
					strncpy(tmp, "[unknown host]",
						sizeof(tmp)-1);
				break;
			case 'n':
			case 'N':
				if (getfqdomainname(tmp, sizeof(tmp)) < 0)
					strncpy(tmp, "[unknown network]",
						sizeof(tmp)-1);
				break;
			case 't':
			case 'T':
#if defined(HAVE_SNPRINTF)
				snprintf(tmp, sizeof(tmp),
						"%02d:%02d:%02d",
						t->tm_hour,
						t->tm_min,
						t->tm_sec);
#else
				sprintf(tmp, "%02d:%02d:%02d",
						t->tm_hour,
						t->tm_min,
						t->tm_sec);
#endif
				break;
			case 'v':
			case 'V':
				strncpy(tmp, misc_getvers(), sizeof(tmp)-1);
				break;
			case '%':
				tmp[0] = '%';
				break;
			default:
			break;
		}
		tmp[sizeof(tmp)-1] = '\0'; /* paranoia :-) */
		j = strlen(tmp);
		if ((i + j) < (sizeof(str) - 64)) {
			memcpy(str + i, tmp, j);
			i += j;
		}
	}

	return str;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_d_bind
**
**	Parameters....:	sock		socket descriptor
**			addr		IP address we want to bind
**			lrng		Lower TCP port range limit
**			urng		Upper TCP port range limit
**			incr		use rand or increment mode
**
**	Return........:	bound port, 0 (INPORT_ANY) on failure
**
**	Purpose.......: Binds a socket, taking care of a given
**                      port range using rand or incrementing
**                      the port number.
**                      Note: this function covers also dynamic
**                            ports assigning with a 0 range:
**                            lrng = urng = 0 ( = INPORT_ANY)
**
** ------------------------------------------------------------ */
u_int16_t socket_d_bind(int sock, u_int32_t addr,
			u_int16_t lrng, u_int16_t urng,
			int incr)
{
	struct sockaddr_in saddr;
	u_int16_t          port = INPORT_ANY;
	int                retry= MAX_RETRIES, err = -1;

	/* Sanity check */
	if(sock < 0)
		return INPORT_ANY;

	/* check port range */
	if( !(lrng<=urng)) {
#if defined(COMPILE_DEBUG)
		debug(2, "socket_d_bind: invalid port range %d-%d",
		         lrng, urng);
#endif
		return INPORT_ANY;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_addr.s_addr = htonl(addr);
	saddr.sin_family      = AF_INET;

#if defined(COMPILE_DEBUG)
	debug(4, "socket_d_bind using %s", incr ? "increment" : "random");
#endif

	if(incr) {
		for (port = lrng; err && (port <= urng); port++) {

			saddr.sin_port = htons(port);

			while(0 <= retry--) {
				errno = 0;
				err = bind(sock, (struct sockaddr *)&saddr,
				                 sizeof(saddr));
#if defined(COMPILE_DEBUG)
				debug(2, "bind %s:%d result: %d, status: %s",
				         socket_addr2str(addr),
				         port, err, strerror(errno));
#endif
				if(0 == err) {
					/* bind succeed */
#if defined(COMPILE_DEBUG)
					debug(2, "bind succeeded,"
						 "port: %d, result: %d",
						 port, err);
#endif
					retry = -1; break;
				} else {
					/* bind failed: fatal error? */
					if( !(EINTR == errno ||
					      EAGAIN == errno ||
					      EADDRINUSE == errno)) {
#if defined(COMPILE_DEBUG)
						debug(4, "bind failed,"
						      "result: %d, error %s",
						      err, strerror(errno));
#endif
						return INPORT_ANY;
					}
				}
			}
		}
	} else {
		int port_range = (urng - lrng) + 1;

		while(err && (0 < port_range--)) {

			port = misc_rand(lrng, urng);
			saddr.sin_port = htons(port);

			while(0 <= retry--) {
				err = bind(sock, (struct sockaddr *)&saddr,
				                 sizeof(saddr));
#if defined(COMPILE_DEBUG)
				debug(2, "bind %s:%d, result: %d, status: %s",
				         socket_addr2str(addr),
				         port, err, strerror(errno));
#endif
				if(0 == err) {
					/* bind succeed */
#if defined(COMPILE_DEBUG)
					debug(2, "bind succeeded, port: %d,"
						 "result: %d", port, err);
#endif
					retry = -1; break;
				} else {
					/* bind failed: fatal error? */
					if( !(EINTR == errno ||
					      EAGAIN == errno ||
					      EADDRINUSE == errno)) {
#if defined(COMPILE_DEBUG)
						debug(2, "bind failed, "
							"result: %d, error %s",
							err, strerror(errno));
#endif
						return INPORT_ANY;
					}
				}
			}
		}
	}

	if((0 == err) &&
	   (INADDR_NONE != socket_sck2addr(sock, LOC_END, &port)))
	{
#if defined(COMPILE_DEBUG)
		debug(2, "bound socket to port %d", port);
#endif
		return port;
	}
#if defined(COMPILE_DEBUG)
	debug(2, "bind error - port %d, IP %d",
		port, socket_sck2addr(sock, LOC_END, NULL));
#endif
	return INPORT_ANY;
}

/* ------------------------------------------------------------ **
**
**	Function......:	socket_d_listen
**
**	Parameters....:	addr		IP address we want to bind
**			lrng		Lower TCP port range limit
**			urng		Upper TCP port range limit
**			phls		Pointer where HLS will go
**			ctyp		Desired comms type identifier
**			incr		use rand or incremental bind
**
**	Return........:	Listening port (0=failure)
**
**	Purpose.......: Open a listening socket, suitable for
**			an additional data connection (e.g. FTP).
**
** ------------------------------------------------------------ */

u_int16_t socket_d_listen(u_int32_t addr,
			  u_int16_t lrng, u_int16_t urng,
			  HLS **phls, char *ctyp,
			  int incr)
{
	int       sock;
	u_int16_t port;

	if (phls == NULL || ctyp == NULL)	/* Sanity check	*/
		misc_die(FL, "socket_d_listen: ?phls? ?ctyp?");

	/*
	** Create the socket and prepare it for binding
	*/
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		syslog_error("can't create %s socket", ctyp);
		exit(EXIT_FAILURE);
	}
	socket_opts(sock, SK_LISTEN);

	port = socket_d_bind(sock, addr, lrng, urng, incr);
	if (INPORT_ANY == port) {
		/* nothing found? */
		close(sock);
		return 0;
	}
	listen(sock, 1);

	/*
	** Allocate the corresponding High Level Socket
	*/
	if ((*phls = socket_init(-1)) == NULL)
		misc_die(FL, "socket_d_listen: ?*phls?");
	(*phls)->sock = sock;
	(*phls)->ctyp = ctyp;

#if defined(COMPILE_DEBUG)
	debug(2, "listen: %s (fd=%d) %s:%d", (*phls)->ctyp,
		(*phls)->sock, socket_addr2str(addr), (int)port);
#endif
	return port;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_d_connect
**
**	Parameters....:	addr		Destination IP address
**			port		Destination TCP port
**			ladr		Local IP address
**			lrng		Lower TCP port range limit
**			urng		Upper TCP port range limit
**			phls		Pointer where HLS will go
**			ctyp		Desired comms type identifier
**			incr		use rand or incremental bind
**
**	Return........:	Local end of connected port (0=failure)
**
**	Purpose.......: Open a connecting socket, suitable for
**			an additional data connection (e.g. FTP).
**
** ------------------------------------------------------------ */

u_int16_t socket_d_connect(u_int32_t addr, u_int16_t port,
			   u_int32_t ladr,
			   u_int16_t lrng, u_int16_t urng,
			   HLS **phls, char *ctyp,
			   int incr)
{
	struct sockaddr_in saddr;
	int                sock  = -1; /* mark socket invalid */
	int                retry = MAX_RETRIES;
	u_int16_t          lprt  = lrng;

	if (phls == NULL || ctyp == NULL)	/* Sanity check	*/
		misc_die(FL, "socket_d_connect: ?phls? ?ctyp?");

	while(0 <= retry--)
	{
		/*
		** First of all, get a socket
		*/
		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			syslog_error("can't create %s socket", ctyp);
			exit(EXIT_FAILURE);
		}
		socket_opts(sock, SK_DATA);

		/*
		** check if we have to use a port range
		*/
		if( !(INPORT_ANY == lrng && INPORT_ANY == urng)) {
			/*
			** Bind the socket, taking care of a given port range
			*/
			if(incr) {
#if defined(COMPILE_DEBUG)
				debug(2, "%s: about to bind to %s:range(%d-%d)",
				         ctyp, socket_addr2str(ladr),
				         lprt, urng);
#endif
				lprt = socket_d_bind(sock, ladr,
				                     lprt, urng, incr);
			} else {
#if defined(COMPILE_DEBUG)
				debug(2, "%s: about to bind to %s:range(%d-%d)",
				         ctyp, socket_addr2str(ladr),
				         lrng, urng);
#endif
				lprt = socket_d_bind(sock, ladr,
				                     lrng, urng, incr);
			}
			if (INPORT_ANY == lprt) {
				/* nothing found? */
				close(sock);
				return 0;
			}
		} else lprt = INPORT_ANY;

		/*
		** Actually connect the socket
		*/
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_addr.s_addr = htonl(addr);
		saddr.sin_family      = AF_INET;
		saddr.sin_port        = htons(port);

		if (connect(sock, (struct sockaddr *) &saddr,
		                  sizeof(saddr)) < 0)
		{
#if defined(COMPILE_DEBUG)
			debug(2, "%s: connect failed with '%s'",
			         ctyp, strerror(errno));
#endif
			close(sock);
			sock = -1;
			/* check if is makes sense to retry?
			** perhaps we only need an other
			** local port (EADDRNOTAVAIL) for
			** this destination?
			*/
			if( !(EINTR == errno ||
			      EAGAIN == errno ||
			      EADDRINUSE == errno ||
			      EADDRNOTAVAIL == errno))
			{
				/*
				** an other (real) error ocurred
				*/
				return 0;
			} else
			if(incr && INPORT_ANY != lprt) {
				/*
				** increment lower range if we use
				** increment mode and have a range
				*/
				if(lprt < urng) {
					lprt++; /* incr lower range */
				} else {
				/*
				** no more ports in range we can try
				*/
					return 0;
				}
			}
		} else break;
	}

	/*
	** check if we have a valid, connected socket
	*/
	if(-1 == sock) {
		close(sock);
		return 0;
	}

	/*
	** Allocate the corresponding High Level Socket
	*/
	if ((*phls = socket_init(sock)) == NULL)
		misc_die(FL, "socket_d_connect: ?*phls?");
	(*phls)->ctyp = ctyp;

	(void) socket_sck2addr(sock, LOC_END, &port);
#if defined(COMPILE_DEBUG)
	debug(2, "connect: %s fd=%d", (*phls)->ctyp, (*phls)->sock);
#endif
	return port;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_str2addr
**
**	Parameters....:	name		Host name or address
**			dflt		Default value
**
**	Return........:	Resolved address or default
**
**	Purpose.......: Resolver for DNS names / IP addresses.
**
** ------------------------------------------------------------ */

u_int32_t socket_str2addr(char *name, u_int32_t dflt)
{
	struct hostent *hptr;
	struct in_addr iadr;

#if defined(COMPILE_DEBUG)
	debug(3, "str2addr: in='%.1024s'", NIL(name));
#endif

	if (name == NULL)		/* Basic sanity check	*/
		return dflt;
	memset(&iadr, 0, sizeof(iadr));

	/*
	** Try to interpret as dotted decimal
	*/
	if (*name >= '0' && *name <= '9') {
		if (inet_aton(name, &iadr) == 0)
			return dflt;	/* Can't be valid ...	*/
		return ntohl(iadr.s_addr);
	}

	/*
	** Try to resolve the host as a DNS name
	*/
	if ((hptr = gethostbyname(name)) != NULL) {
		memcpy(&iadr.s_addr, hptr->h_addr, sizeof(iadr.s_addr));
		return (u_int32_t) ntohl(iadr.s_addr);
	}

	/*
	** Well, then return the default
	*/
	return dflt;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_str2port
**
**	Parameters....:	name		Host name or address
**			dflt		Default value
**
**	Return........:	Resolved port or default
**
**	Purpose.......: Resolver for TCP ports.
**
** ------------------------------------------------------------ */

u_int16_t socket_str2port(char *name, u_int16_t dflt)
{
	struct servent *sptr;

	if (name == NULL)		/* Basic sanity check	*/
		return dflt;

	/*
	** Try to interpret as numeric port value
	*/
	if (*name >= '0' && *name <= '9')
		return (u_int16_t) atoi(name);

	/*
	** Try to resolve from /etc/services, NIS, etc.
	*/
	if ((sptr = getservbyname(name, "tcp")) != NULL)
		return (u_int16_t) ntohs(sptr->s_port);

	/*
	** Well, then return the default
	*/
	return dflt;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_addr2str
**
**	Parameters....:	addr		IP address in host order
**
**	Return........:	Dotted decimal string for addr
**
**	Purpose.......: Convert IP address (host byte order) into
**	                human readable form.
**			The buffer is reused in subsequent calls,
**			so the caller better move the result away.
**
** ------------------------------------------------------------ */

char *socket_addr2str(u_int32_t addr)
{
	struct in_addr iadr;
	static char str[PEER_LEN];

	memset(&iadr, 0, sizeof(iadr));
	iadr.s_addr = htonl(addr);
	misc_strncpy(str, inet_ntoa(iadr), sizeof(str));
	return str;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_sck2addr
**
**	Parameters....:	sock		Socket descriptor
**			peer		LOC_END or REM_END
**			port		Pointer to port
**
**	Return........:	IP address in host byte order
**			or INADDR_NONE on failure
**
**	Purpose.......: Retrieve the IP address of a socket,
**			for either the peer or the local end
**			in host byte order.
**
** ------------------------------------------------------------ */

u_int32_t socket_sck2addr(int sock, int peer, u_int16_t *port)
{
	struct sockaddr_in saddr;
	int len, r;
	char *s;

	/*
	** Retrieve the actual values
	*/
	memset(&saddr, 0, sizeof(saddr));
	len = sizeof(saddr);
	if (peer == LOC_END) {
		r = getsockname(sock, (struct sockaddr *) &saddr, &len);
		s = "sock";
	} else {
		r = getpeername(sock, (struct sockaddr *) &saddr, &len);
		s = "peer";
	}
	if (r < 0) {
		syslog_error("can't get %sname for socket %d", s, sock);
		return INADDR_NONE;
	}

	/*
	** Return the port if requested
	*/
	if (port != NULL)
		*port = (u_int16_t) ntohs(saddr.sin_port);

	/*
	** Return the address part
	*/
	return (u_int32_t) ntohl(saddr.sin_addr.s_addr);
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_chkladdr
**
**	Parameters....:	addr		ip address to check
**
**	Return........:	0 if not found, 1 if found, -1 on error
**
**	Purpose.......: Check if addr (in network byte order)
**			is used on an local network interface.
**
** ------------------------------------------------------------ */

int        socket_chkladdr(u_int32_t addr)
{
#define DEFAULT_IFNUM	512
	struct ifconf  ifc;
	int            ifn = DEFAULT_IFNUM;
	int            i, sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(-1 == sock) {
#if defined(COMPILE_DEBUG)
		debug(2, "can not create socket: %s", NIL(strerror(errno)));
#endif
		return -1;
	}

#if defined(SIOCGIFNUM)
	if( ioctl(sock, SIOCGIFNUM, (char *) &ifn) < 0) {
#if defined(COMPILE_DEBUG)
		debug(2, "ioctl SIOCGIFNUM failed: %s", NIL(strerror(errno)));
#endif
		ifn = DEFAULT_IFNUM;	/* ignore failure */
	}
#endif	/* SIOCGIFNUM */

	ifc.ifc_len = ifn * sizeof (struct ifreq);
	ifc.ifc_buf = malloc(ifc.ifc_len);
	if( !ifc.ifc_buf) {
#if defined(COMPILE_DEBUG)
		debug(2, "malloc(ifc.ifc_len=%d) failed: %s",
			 ifc.ifc_len, NIL(strerror(errno)));
#endif
		close(sock);
		return -1;
	}
        memset(ifc.ifc_buf, 0, ifc.ifc_len);

	if( ioctl(sock, SIOCGIFCONF, (char *)&ifc) < 0) {
#if defined(COMPILE_DEBUG)
		debug(2, "ioctl SIOCGIFCONF failed: %s", NIL(strerror(errno)));
#endif
		free(ifc.ifc_buf);
		close(sock);
		return -1;
	}
	close(sock);

	for( i=0; i<ifc.ifc_len; ) {
		struct ifreq       *ifr = (struct ifreq *) &ifc.ifc_buf[i];
		struct sockaddr_in *sa  = (struct sockaddr_in*) &ifr->ifr_addr;

		i += sizeof( *ifr);

		if(AF_INET     != ifr->ifr_addr.sa_family
		|| INADDR_ANY  == sa->sin_addr.s_addr
		|| INADDR_NONE == sa->sin_addr.s_addr)
			continue;

#if defined(COMPILE_DEBUG)
		debug(4, "interface %s has ip-address: %s",
			 ifr->ifr_name, inet_ntoa(sa->sin_addr));
#endif

		if( sa->sin_addr.s_addr == addr) {
#if defined(COMPILE_DEBUG)
			debug(2, "found local ip addr: %s",
				 inet_ntoa(sa->sin_addr));
#endif
			free(ifc.ifc_buf);
			return 1;
		}
	}
	free(ifc.ifc_buf);

#if defined(COMPILE_DEBUG)
	debug(2, "requested ip addr is not a local one");
#endif
	return 0;
}


/* ------------------------------------------------------------ **
**
**	Function......:	socket_orgdst
**
**	Parameters....:	phls	pointer to high-level socket
**			addr	pointer to in_addr_t
**			port	pointer to in_port_t
**
**	Return........:	0 on success, -1 on error
**
**	Purpose.......: get the original (transparent) destination
**	                addr and port the peer / client wanted to
**	                connect (network byte order!).
**
** ------------------------------------------------------------ */

int socket_orgdst(HLS *phls, u_int32_t *addr, u_int16_t *port)
{
	struct sockaddr_in   name;
#if defined(HAVE_LINUX_NETFILTER_IPV4_H) && defined(SO_ORIGINAL_DST)
	struct sockaddr_in   dest;
#endif
#if defined(HAVE_NETINET_IP_NAT_H) && defined(SIOCGNATL)
	natlookup_t          natlook, *nlptr = &natlook;
	int                  rc, nat_fd = -1;
#endif
#if defined(HAVE_NET_PFVAR_H)
	int                  rc, nat_fd = -1;
	struct protoent      *proto;
	struct sockaddr_in   peer;
	struct pfioc_natlook natlook;
#endif
	socklen_t            len;

	/*
	** sanity args checks
	*/
	if( !(phls && -1 != phls->sock && addr && port))
		return -1;

	len = sizeof(name);
	memset(&name, 0, len);
	if(getsockname(phls->sock, (struct sockaddr *)&name, &len) < 0) {
		syslog_error("can't get sockname for socket %d", phls->sock);
		return -1;
	}
	syslog_write(T_DBG, "socket name address is %s:%d",
		     socket_addr2str(ntohl(name.sin_addr.s_addr)),
		                     ntohs(name.sin_port));

#if defined(HAVE_LINUX_NETFILTER_IPV4_H) && defined(SO_ORIGINAL_DST)
	/*
	** IP-Tables uses SO_ORIGINAL_DST getsockopt call
	*/
	len = sizeof(dest);
	memset(&dest, 0, len);
	if(getsockopt(phls->sock, SOL_IP, SO_ORIGINAL_DST, &dest, &len) < 0) {
		switch(errno) {
		case ENOPROTOOPT:
			/*
			** no iptables support / 2.2 kernel
			** ==> use getsockname dst bellow
			*/
		break;
		case ENOENT:
			/*
			** 2.4 kernel without iptables support
			** ==> getsockname does not work here
			*/
			syslog_write(T_WRN,
			"iptables not supported or ipchains support active");
			return -1;
		break;
		default:
			syslog_error(
				"can't get iptables transparent destination");
			return -1;
		break;
		}
	} else {
		if((name.sin_port == dest.sin_port) &&
		   (name.sin_addr.s_addr == dest.sin_addr.s_addr)) {
			syslog_write(T_DBG,
			      "iptables transparent destination %s:%d is local",
			      socket_addr2str(ntohl(dest.sin_addr.s_addr)),
			      ntohs(dest.sin_port));
			return -1;
		}

		syslog_write(T_DBG, "iptables transparent destination: %s:%d",
			socket_addr2str(ntohl(dest.sin_addr.s_addr)),
			ntohs(dest.sin_port));

		*addr = dest.sin_addr.s_addr;
		*port = dest.sin_port;
		return 0;
	}
#endif

#if defined(HAVE_NET_PFVAR_H)

	/*
	** OpenBSD PF table lookup
	*/
	len = sizeof(peer);
	memset(&peer, 0, len);
	if(getpeername(phls->sock, (struct sockaddr *)&peer, &len) < 0) {
		syslog_error("can't get peername for socket %d", phls->sock);
		return -1;
	}
	syslog_write(T_DBG, "socket peer address is %s:%d",
		     socket_addr2str(ntohl(peer.sin_addr.s_addr)),
		                     ntohs(peer.sin_port));

	if(!(proto = getprotobyname("tcp"))) {
		syslog_error("can't get protocol number for tcp");
		return -1;
	}

	if((nat_fd = open("/dev/pf", O_RDWR, 0)) < 0) {
		endprotoent();
		syslog_error("can't open pf device '/dev/pf'");
		return -1;
	}

	memset(&natlook, 0, sizeof(natlook));
	natlook.af              = AF_INET;
	natlook.proto           = proto->p_proto;
	natlook.direction       = PF_OUT;
	natlook.saddr.v4.s_addr = peer.sin_addr.s_addr;		/* peer */
	natlook.sport           = peer.sin_port;
	natlook.daddr.v4.s_addr = name.sin_addr.s_addr;		/* sock */
	natlook.dport           = name.sin_port;

	endprotoent();

	rc = ioctl(nat_fd, DIOCNATLOOK, &natlook);
	close(nat_fd);

	if(rc < 0) {
		if(errno != ENOENT) {
			syslog_error("can't get pfnat transparent destination");
		}
		return -1;
	}

#if defined(COMPILE_DEBUG)
	debug(2, "pfnat transparent proxy destination: %s:%d",
			socket_addr2str(ntohl(natlook.rdaddr.v4.s_addr)),
			ntohs(natlook.rdport));
#endif

	if((natlook.rdport == name.sin_port) &&
	   (natlook.rdaddr.v4.s_addr == name.sin_addr.s_addr))
	{
		syslog_write(T_DBG, "pfnat proxy destination %s:%d is local",
		       socket_addr2str(ntohl(natlook.rdaddr.v4.s_addr)),
		       ntohs(natlook.rdport));
		return -1;
	}
	syslog_write(T_DBG, "pfnat transparent destination: %s:%d",
	             socket_addr2str(ntohl(natlook.rdaddr.v4.s_addr)),
	             ntohs(natlook.rdport));

	*addr = natlook.rdaddr.v4.s_addr;
	*port = natlook.rdport;
	return 0;
#endif

#if defined(HAVE_NETINET_IP_NAT_H) && defined(SIOCGNATL)
	/*
	** BSD ipnat table lookup
	*/
	if ((nat_fd = open(IPL_NAT, O_RDONLY, 0)) < 0) {
		syslog_error("can't open ipnat device '%.*s'",
		             MAX_PATH_SIZE, IPL_NAT);
		return -1;
	}

	memset(&natlook, 0, sizeof(natlook));
	natlook.nl_flags        = IPN_TCP;
	natlook.nl_inip.s_addr  = name.sin_addr.s_addr;
	natlook.nl_inport       = name.sin_port;
	natlook.nl_outip.s_addr = htonl(phls->addr);
	natlook.nl_outport      = htons(phls->port);

	/*
	** handle versions differences...
	*/
	rc = 0;
	if(63 == (SIOCGNATL & 0xff)) {
		rc = ioctl(nat_fd, SIOCGNATL, &nlptr);
#if defined(COMPILE_DEBUG)
		debug(2, "SIOCGNATL using &natlookptr: rc=%d", rc);
#endif
	} else {
		rc = ioctl(nat_fd, SIOCGNATL, &natlook);
#if defined(COMPILE_DEBUG)
		debug(2, "SIOCGNATL using &natlook: rc=%d", rc);
#endif
	}
	close(nat_fd);

	if(rc < 0) {
		if(errno != ESRCH) {
			syslog_error("can't get ipnat transparent destination");
		}
		return -1;
	}

	if((natlook.nl_realport == name.sin_port) &&
	   (natlook.nl_realip.s_addr == name.sin_addr.s_addr))
	{
		syslog_write(T_DBG,
		       "ipnat transparent destination %s:%d is local",
		       socket_addr2str(ntohl(natlook.nl_realip.s_addr)),
		       ntohs(natlook.nl_realport));
		return -1;
	}
	syslog_write(T_DBG, "ipnat transparent destination: %s:%d",
		socket_addr2str(ntohl(natlook.nl_realip.s_addr)),
		ntohs(natlook.nl_realport));

	*addr = natlook.nl_realip.s_addr;
	*port = natlook.nl_realport;
	return 0;

#else /* !BSD-IPNAT */

	/*
	** IP-Chains uses getsockname, as "transparent address"
	*/
	syslog_write(T_DBG,
			"ipchains transparent destination: %s:%d",
			socket_addr2str(ntohl(name.sin_addr.s_addr)),
			ntohs(name.sin_port));

	*addr = name.sin_addr.s_addr;
	*port = name.sin_port;
#endif
	return 0;
}


/* ------------------------------------------------------------ **
**
**	Function......:	getfqhostname
**
**	Parameters....:	fqhost	buffer to store the host name
**			n	size of the buffer
**
**	Return........:	0 on success, -1 on error
**
**	Purpose.......: get the full qualified (resolved)
**                      host name of the current/local host
**
** ------------------------------------------------------------ */

int getfqhostname(char *fqhost, size_t n)
{
	char           hname[MAXHOSTNAMELEN];
	struct hostent *hp;

	if( !(n > 0 && fqhost))
		return -1;

	memset(hname, 0, sizeof(hname));
	if( gethostname(hname, sizeof(hname)-1))
		return -1;

	if( !(hp = gethostbyname(hname)))
		return -1;

	misc_strncpy(fqhost, hp->h_name, n);

	return 0;
}

/* ------------------------------------------------------------ **
**
**	Function......:	getfqdomainname
**
**	Parameters....:	fqhost	buffer to store the domain name
**			n	size of the buffer
**
**	Return........:	0 on success, -1 on error
**
**	Purpose.......: get the full qualified (resolved)
**                      domain name of the current/local host
**
** ------------------------------------------------------------ */

int getfqdomainname(char *fqdomain, size_t n)
{
	char hname[MAXHOSTNAMELEN], *p;

	if( !(n > 0 && fqdomain))
		return -1;

	if(getfqhostname(hname, sizeof(hname)))
		return -1;

	p = strchr(hname, (int)'.');
	if(p && *(p+1)) {
		misc_strncpy(fqdomain, p+1, n);
		return 0;
	}

	return -1;
}

/* ------------------------------------------------------------
 * $Log: com-socket.c,v $
 * Revision 1.7.2.2  2005/01/10 11:37:36  mt
 * added sys/param.h inclusion
 *
 * Revision 1.7.2.1  2003/05/07 11:14:08  mt
 * added OpenBSD pf-nat transparent proxy support
 * fixed to use hls->retr instead of a static retry counter
 *
 * Revision 1.7  2002/05/02 13:01:08  mt
 * merged with v1.8.2.2
 *
 * Revision 1.6.2.2  2002/04/04 14:44:30  mt
 * added waiting and retrying on "no data" but no EOF in I_NREAD
 * added check for buffer len difference on ioctl and recv
 * added remembering of i/o failures in hls->ernr for loging
 * added and improved transparent proxy log messages
 *
 * Revision 1.6.2.1  2002/01/28 01:51:21  mt
 * replaced question marks sequences that may be misinterpreted as trigraphs
 *
 * Revision 1.6  2002/01/14 18:26:55  mt
 * implemented socket_orgdst to read transparent proxying destinations
 * implemented a MaxRecvBufSize option limiting max recv buffer size
 * implemented workarround for Netscape (4.x) directory symlink handling
 * extended log messages to provide basic transfer statistics data
 * fixed socket_gets to wait for a complete line if no EOL found
 * added snprintf usage, replaced strcpy/strncpy with misc_strncpy
 *
 * Revision 1.5  2001/11/06 23:04:43  mt
 * applied / merged with transparent proxy patches v8
 * see ftp-proxy/NEWS for more detailed release news
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

