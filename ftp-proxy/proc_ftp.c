/*
 * $Id: proc_ftp.c,v 1.2 2002/01/14 19:08:51 mt Exp $
 *
 * /proc/net/ftp_proxy interface
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
static char rcsid[] = "$Id: proc_ftp.c,v 1.2 2002/01/14 19:08:51 mt Exp $";
#endif

#include <config.h>

#if !defined(__KERNEL__)
#  define __KERNEL__
#endif

#define _LOOSE_KERNEL_NAMES

#include <linux/malloc.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/version.h>
#if !defined(VERSION_CODE)
#  define VERSION_CODE(v,r,s)   (((v) << 16) + ((r) << 8) + (s))
#endif

#if LINUX_VERSION_CODE >= VERSION_CODE(2,1,0)
#  include <asm/uaccess.h>
#else
#  define copy_from_user        memcpy_fromfs
#  define copy_to_user          memcpy_tofs
#  define proc_register         proc_register_dynamic
#  define access_ok             !verify_area
#endif

#define DIMOF(a)        (sizeof(a) / sizeof(a[0]))
#define C_STRLEN(s)     (DIMOF(s) - 1)  /* Subtract 1 for NULL byte */
#define PROC_NAME(s)    C_STRLEN(s), s

#if !defined(MODULE)
#  define MODULE
#endif

#include <linux/module.h>


/* ------------------------------------------------------------ */

#if LINUX_VERSION_CODE >= VERSION_CODE(2,1,0)
static ssize_t proc_ftp_read(struct file *file,
		char *buf, size_t count, loff_t *ppos);
static ssize_t proc_ftp_write(struct file *file,
		const char *buf, size_t count, loff_t *ppos);
#else
static int proc_ftp_read(struct inode *inode,
		struct file *file, char *buf, int count);
static int proc_ftp_write(struct inode *inode,
		struct file *file, const char *buf, int count);
#endif


/* ------------------------------------------------------------ */

#define MAX_LINE	4096	/* input line length		*/
#define MAX_ARGS	128	/* maximum number of arguments	*/

typedef struct {
	char *arg;		/* name of an argument		*/
	char *val;		/* value assigned to argument	*/
} AVPAIR;


#if 0
typedef struct {
	char	addr[20];	/* address in dotted decimal	*/
	char	user[10];	/* user name			*/
	time_t	when;		/* time when access started	*/
	pid_t	pid;		/* process id			*/
	long	cnt_get;	/* number of bytes received	*/
	long	cnt_put;	/* number of bytes written	*/
} CLIENT;

static CLIENT clients[1024];	/* give a reasonable limit	*/
#endif


/* ------------------------------------------------------------ */

static inline int mystrcmp(const char * s1, const char * s2)
{
	if (s1 == NULL || s2 == NULL)
		return 0;	/* Hmmm, what should it actually be? */

	while (*s1 != '\0' && *s1 == *s2) {
		s1++;
		s2++;
	}
	return (((int) *s1) - ((int) *s2));
}


/* ------------------------------------------------------------ */

static struct file_operations proc_ftp_operations = {
	NULL,			/* (l)lseek */
	proc_ftp_read,		/* read */
	proc_ftp_write,		/* write - update configuration */
	NULL,			/* readdir */
	NULL,			/* select/poll */
	NULL,			/* ioctl */
	NULL,			/* mmap */
	NULL,			/* open */
	NULL,			/* flush */
	NULL,			/* release */
	NULL,			/* fsync */
	NULL,			/* fasync */
	NULL,			/* check_media_change */
	NULL,			/* revalidate */
	NULL,			/* lock */
};

static struct inode_operations proc_ftp_inode_operations = {
	&proc_ftp_operations,	/* file-ops */
	NULL,			/* create */
	NULL,			/* lookup */
	NULL,			/* link */
	NULL,			/* unlink */
	NULL,			/* symlink */
	NULL,			/* mkdir */
	NULL,			/* rmdir */
	NULL,			/* mknod */
	NULL,			/* rename */
	NULL,			/* readlink */
	NULL,			/* follow_link */
	NULL,			/* readpage */
	NULL,			/* writepage */
	NULL,			/* bmap */
	NULL,			/* truncate */
	NULL,			/* permission */
	NULL,			/* smap */
	NULL,			/* updatepage */
	NULL,			/* revalidate */
};

static struct proc_dir_entry proc_ftp = {
	0, PROC_NAME("ftp_proxy"),		/* inode, name */
	S_IFREG | S_IRUSR | S_IWUSR, 1, 0, 0,	/* mode, nlink, uid, gid */
	0, &proc_ftp_inode_operations,		/* size, ops */
	NULL, NULL,				/* get_info, fill_inode */
	NULL,					/* next */
	NULL, NULL,				/* parent, subdir */
	NULL,					/* data */
	NULL, NULL,				/* read_proc, write_proc */
	NULL,					/* readlink_proc */
	0, 0,					/* count, deleted */
};


/* ------------------------------------------------------------ **
**
**	Function......:	proc_ftp_read
**
**	Parameters....:	...
**
**	Return........:	number of bytes successfully read
**
**	Purpose.......: Read ftp-proxy status file.
**
** ------------------------------------------------------------ */

#if LINUX_VERSION_CODE >= VERSION_CODE(2,1,0)
static ssize_t proc_ftp_read(struct file *file,
		char *buf, size_t count, loff_t *ppos)
#else
static int proc_ftp_read(struct inode *inode,
		struct file *file, char *buf, int count)
#endif
{
#if LINUX_VERSION_CODE >= VERSION_CODE(2,1,0)
	ppos = ppos;		/* calm down picky compilers	*/
#else
	inode = inode;		/* calm down picky compilers	*/
#endif
	file = file;		/* calm down picky compilers	*/

	/* TODO: auslesen der informationen aus dem array ... */
	buf = buf;
	count = count;

	return 0;
}


/* ------------------------------------------------------------ **
**
**	Function......:	proc_ftp_write
**
**	Parameters....:	...
**
**	Return........:	number of bytes successfully written
**
**	Purpose.......: Write (update) ftp-proxy status file
**
** ------------------------------------------------------------ */

#if LINUX_VERSION_CODE >= VERSION_CODE(2,1,0)
static ssize_t proc_ftp_write(struct file *file,
		const char *buf, size_t count, loff_t *ppos)
#else
static int proc_ftp_write(struct inode *inode,
		struct file *file, const char *buf, int count)
#endif
{
	char line[MAX_LINE], *p, *cmd, *typ;
	AVPAIR avlist[MAX_ARGS], *avptr;
	int argc, i;

	if (count >= sizeof(line))
		return -E2BIG;
	if (count <= 0)
		return count;

#if LINUX_VERSION_CODE >= VERSION_CODE(2,1,0)
	if (copy_from_user(line, buf, count))
		return -EFAULT;
	ppos = ppos;		/* calm down picky compilers	*/
#else
	memcpy_fromfs(line, buf, count);
#endif
	file = file;		/* calm down picky compilers	*/

	line[count] = '\0';
	cmd = typ = NULL;
	for (p = line, argc = 0, avptr = avlist; *p; ) {
		while (*p == ' ' ||
				*p == '\t' ||
				*p == '\n' ||
				*p == '\r')
			p++;		/* skip white space	*/
		if (*p == '\0')
			break;

		avptr->arg = p;		/* found an argument	*/
		while (*p != '\0' &&
				*p != '='  &&
				*p != ' '  &&
				*p != '\t' &&
				*p != '\n' &&
				*p != '\r')
			p++;
		if (*p == '=') {
			*p++ = '\0';	/* now get the value	*/
			avptr->val = p;	/* found arg's value	*/

			/* TODO: allow quoted strings */

			while (*p != '\0' &&
					*p != ' '  &&
					*p != '\t' &&
					*p != '\n' &&
					*p != '\r')
				p++;
		} else
			avptr->val = NULL;
		if (*p != '\0')
			*p++ = '\0';	/* terminate arg/val	*/

		/*
		** The following pair is most interesting
		*/
		if (mystrcmp(avptr->arg, "cmd") == 0)
			cmd = avptr->val;
		avptr++;

		if (++argc >= MAX_ARGS)
			break;		/* rude overflow check	*/
	}
	if (argc < 1)
		return 0;

	for (i = 0, avptr = avlist; i < argc; i++, avptr++) {
		printk("ftp-proxy: %2d: '%s'='%s'\n", i + 1,
			avptr->arg, avptr->val ? avptr->val : "(nil)");
	}

#if 0
	/*
	** TODO: Now for the real work ...
	*/
	if (mystrcmp(argv[0], "add") == 0) {
		i = proc_ftp_add(--argc, &argv[1], &valp[1]);
		return ((i < 0) ? i : count);
	}
	if (mystrcmp(argv[0], "del") == 0) {
		i = proc_ftp_del(--argc, &argv[1], &valp[1]);
		return ((i < 0) ? i : count);
	}
	if (mystrcmp(argv[0], "upd") == 0) {
		i = proc_ftp_upd(--argc, &argv[1], &valp[1]);
		return ((i < 0) ? i : count);
	}
	/* add more basic commands here if you like ... */
#endif

	printk("ftp-proxy: unknown cmd '%s'\n", cmd ? cmd : "(null)");
	return -EINVAL;
}


/* ------------------------------------------------------------ **
**
**	Function......:	init_module
**
**	Parameters....:	(none)
**
**	Return........:	0=success, else negative error code
**
**	Purpose.......: General Module initialization code.
**
** ------------------------------------------------------------ */

int init_module(void)
{
	struct proc_dir_entry *dir, *dp;
	int rc;

	printk("installing /proc/net/ftp-proxy interface\n");

	/*
	** First, verify that /proc/net is available
	*/
	for (dir = proc_root.subdir; dir; dir = dir->next) {
		if (mystrcmp(dir->name, "net") == 0)
			break;
	}
	if (dir == NULL)
		return -ENOENT;

	/*
	** Then, see if the file is already there
	*/
	for (dp = dir->subdir; dp; dp = dp->next) {
		if (mystrcmp(dp->name, "ftp_proxy") == 0)
			return 0;
	}

	/*
	** Let's go and install the file
	*/
	if ((rc = proc_register(dir, &proc_ftp)) == 0)
		return 0;

	printk(KERN_ALERT "unable to install /proc/net/ftp-proxy\n");
	return rc;
}


/* ------------------------------------------------------------ **
**
**	Function......:	cleanup_module
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: General Module termination code.
**
** ------------------------------------------------------------ */

void cleanup_module(void)
{
	printk("removing /proc/net/ftp-proxy interface\n");

	if (proc_ftp.parent) {
		proc_unregister(proc_ftp.parent, proc_ftp.low_ino);
		proc_ftp.parent = NULL;
	}
}


/* ------------------------------------------------------------
 * $Log: proc_ftp.c,v $
 * Revision 1.2  2002/01/14 19:08:51  mt
 * added _LOOSE_KERNEL_NAMES to avoid some warnings
 *
 * Revision 1.1  1999/09/15 14:06:22  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

