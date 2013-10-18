/*
 * $Id: com-config.c,v 1.7 2002/05/02 12:57:10 mt Exp $
 *
 * Common functions for configuration reading
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
static char rcsid[] = "$Id: com-config.c,v 1.7 2002/05/02 12:57:10 mt Exp $";
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

#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include "com-config.h"
#include "com-debug.h"
#include "com-misc.h"
#include "com-socket.h"
#include "com-syslog.h"


/* ------------------------------------------------------------ */

typedef struct config_t {
	struct config_t *next;	/* Next config option in chain	*/
	char *name;		/* Config option name		*/
	char *data;		/* Config value as string	*/
} CONFIG;

typedef struct section_t {
	struct section_t *next;	/* Next config section in chain	*/
	char   *name;		/* Section name (NULL=global)	*/
	CONFIG *conf;		/* Chained config option list	*/
} SECTION;


/*
** The next are used for configuration name display
*/

#define MAX_CONF_NAME		128	/* Max display size	*/
#define MIN_CONF_NAME		24	/* Display column size	*/


/* ------------------------------------------------------------ */

static void  config_cleanup(void);
static char *config_line   (FILE *fp);


/* ------------------------------------------------------------ */

static int initflag = 0;	/* Have we been initialized?	*/

static SECTION *sechead = NULL;	/* Chain of config sections	*/


/* ------------------------------------------------------------ **
**
**	Function......:	config_cleanup
**
**	Parameters....:	(none)
**
**	Return........:	(none)
**
**	Purpose.......: Clean up the config list.
**
** ------------------------------------------------------------ */

static void config_cleanup(void)
{
	SECTION *sect;
	CONFIG *conf;

#if defined(COMPILE_DEBUG)
	debug(3, "config_cleanup");
#endif

	for (sect = sechead; sect != NULL; ) {
		if (sect->name != NULL)
			misc_free(FL, sect->name);
		for (conf = sect->conf; conf != NULL; ) {
			sect->conf = conf->next;
			if (conf->name != NULL)
				misc_free(FL, conf->name);
			if (conf->data != NULL)
				misc_free(FL, conf->data);
			misc_free(FL, conf);
			conf = sect->conf;
		}
		sechead = sect->next;
		misc_free(FL, sect);
		sect = sechead;
	}
}


/* ------------------------------------------------------------ **
**
**	Function......:	config_line
**
**	Parameters....:	fp		Pointer to the FILE
**
**	Return........:	Pointer to next line from file
**
**	Purpose.......: Read the next complete line from a file.
**			Filter out empty or comment lines. The
**			comment character is defined as '#'.
**
** ------------------------------------------------------------ */

static char *config_line(FILE *fp)
{
	static char line[MAX_PATH_SIZE * 2];
	char *p;
	size_t len;

	if (fp == NULL)			/* Basic sanity check	*/
		misc_die(FL, "config_line: ?fp?");

	for (;;) {
		memset(line, 0, sizeof(line));

		for (len = 0; ; ) {
			/*
			** Read the first or next line
			*/
			if (fgets(line + len, sizeof(line) - len,
							fp) == NULL) {
				if (line[0] == '\0')
					return NULL;	/* End of file */
				break;
			}

			/*
			** Beautifier: cut leading blanks
			*/
			p = line + len;
			if (*p == ' ' || *p == '\t') {
				while (*p == ' ' || *p == '\t')
					p++;
				memmove(line + len, p, strlen(p) + 1);
			}

			/*
			** Cut off the newline
			*/
			if ((p = strchr(line, '\n')) != NULL)
				*p = '\0';

			/*
			** Skip empty lines
			*/
			if ((len = strlen(line)) == 0)
				continue;

			/*
			** Sanity check: truncate lines too long
			*/
			if (len > (sizeof(line) - 64))
				break;

			/*
			** If the line continues, read on
			*/
			if (line[--len] != '\\')
				break;
			line[len] = '\0';
		}

		/*
		** We have a line now, see if it contains data
		*/
		for (p = line; *p == ' ' || *p == '\t'; p++)
			;
		if (*p != '\0' && *p != '#')
			break;
	}

#if defined(COMPILE_DEBUG)
	debug(3, "config_line: '%.*s'", MAX_PATH_SIZE, p);
#endif
	return p;
}


/* ------------------------------------------------------------ **
**
**	Function......:	config_read
**
**	Parameters....:	name		Config file name
**			dflg		Flag to dump contents
**
**	Return........:	(none), exits program on error
**
**	Purpose.......: Read the configuration file and keep
**			the values for later usage. If dflg is
**			set, the contents of the config file
**			are displayed and the program exits.
**
** ------------------------------------------------------------ */

void config_read(char *file, int dflg)
{
	FILE *fp;
	char *name, *data;
	SECTION *sect, *tmps;
	CONFIG *conf, *tmpc;

	if (file == NULL)		/* Basic sanity check	*/
		misc_die(FL, "config_read: ?file?");

	if (initflag == 0) {
		atexit(config_cleanup);
		initflag = 1;
	}
	if (sechead != NULL)
		config_cleanup();

	if ((fp = fopen(file, "r")) == NULL) {
		syslog_error("can't open config file '%.*s'",
		             MAX_PATH_SIZE, file);
		exit(EXIT_FAILURE);
	}

	/*
	** Prepare the global section
	*/
	sect = (SECTION *) misc_alloc(FL, sizeof(SECTION));
	sect->next = NULL;
	sect->name = NULL;
	sect->conf = NULL;
	sechead = sect;

	/*
	** Now read the file and store sections and options
	*/
	while ((name = config_line(fp)) != NULL) {
		/*
		** Check if this is a section
		*/
		if (*name == '[') {
			if ((data = strchr(name, ']')) != NULL)
				*data = '\0';
			name = misc_strtrim(name + 1);

			/*
			** Do not accept empty sections or
			** sections begining with a wildcard...
			*/
			if('\0' == name[0] || '*' == name[0]) {
				misc_die(FL, "config_read: invalid section");
			}

			/*
			** The global section is outstanding
			*/
			if (strcasecmp(name, "-global-") == 0) {
				sect = sechead;
				continue;
			}

			/*
			** Check if the section is already allocated
			*/
			for (tmps = sechead->next;
					tmps; tmps = tmps->next) {
				if (strcasecmp(name, tmps->name) == 0)
					break;
			}
			if (tmps != NULL) {
				sect = tmps;	/* Make it current */
				continue;
			}

			/*
			** Create a new section
			*/
			sect = (SECTION *)
				misc_alloc(FL, sizeof(SECTION));
			sect->name = misc_strdup(FL, name);
			sect->conf = NULL;

			/*
			** Keep the sections sorted alphabetically
			*/
			for (tmps = sechead; tmps; tmps = tmps->next) {
				if (tmps->next == NULL)
					break;
				if (strcasecmp(name, tmps->next->name) < 0)
					break;
			}
			sect->next = tmps->next;
			tmps->next = sect;
			continue;
		}

		/*
		** Not a section, must be an ordinary line
		*/
		for (data = name; *data != ' ' && *data != '\t'; data++)
			;
		if (*data == '\0') {
			syslog_write(T_WRN,
				"no config value for '%.*s'",
				MAX_CONF_NAME, name);
			continue;	/* Ignore: missing value */
		}

		/*
		** The following is more or less a sanity check
		*/
		*data++ = '\0';
		if ((name = misc_strtrim(name)) == NULL)
			continue;
		if ((data = misc_strtrim(data)) == NULL)
			continue;
		if (*name == '\0' || *data == '\0')
			continue;

		/*
		** Check if the option is already allocated
		*/
		for (conf = sect->conf; conf; conf = conf->next) {
			if (strcasecmp(name, conf->name) == 0)
				break;
		}
		if (conf != NULL) {
			if (conf->data)
				misc_free(FL, conf->data);
			conf->data = misc_strdup(FL, data);
			continue;
		}

		/*
		** Create a new config option
		*/
		conf = (CONFIG *) misc_alloc(FL, sizeof(CONFIG));
		conf->name = misc_strdup(FL, name);
		conf->data = misc_strdup(FL, data);

		/*
		** Keep the config list sorted alphabetically
		*/
		if (sect->conf == NULL ||
				strcasecmp(name, sect->conf->name) < 0) {
			conf->next = sect->conf;
			sect->conf = conf;
		} else {
			for (tmpc = sect->conf; tmpc; tmpc = tmpc->next) {
				if (tmpc->next == NULL)
					break;
				if (strcasecmp(name, tmpc->next->name) < 0)
					break;
			}
			conf->next = tmpc->next;
			tmpc->next = conf;
		}
	}
	fclose(fp);

	/*
	** Do we just want to validate the interpretation?
	*/
	if (dflg != 0) {
		printf("Config-File: '%.*s'\n", MAX_PATH_SIZE, file);
		for (sect = sechead; sect; sect = sect->next) {
			printf("Config-Section ------ '%.*s'\n",
				MAX_CONF_NAME,
				sect->name ? sect->name : "(-global-)");
			for (conf = sect->conf; conf; conf = conf->next) {
				printf("Config:        %-*.*s = '%.*s'\n",
					MIN_CONF_NAME, MAX_CONF_NAME,
					conf->name,
					MAX_PATH_SIZE, conf->data);
			}
		}
		exit(EXIT_SUCCESS);
	}

	/*
	** Inform the possible auditor
	*/
	syslog_write(T_INF, "Config-File: '%.*s'",
			MAX_PATH_SIZE, file);
	for (sect = sechead; sect; sect = sect->next) {
		syslog_write(T_INF, "Config-Section ------ '%.*s'",
				MAX_CONF_NAME,
				sect->name ? sect->name : "(-global-)");
		for (conf = sect->conf; conf; conf = conf->next) {
			syslog_write(T_INF,
				"Config: %-*.*s = '%.*s'",
				MIN_CONF_NAME, MAX_CONF_NAME, conf->name,
				MAX_PATH_SIZE, conf->data);
		}
	}
}

void config_dump(FILE *fd)
{
	SECTION *sect;
	CONFIG *conf;

	if(NULL == fd)
		return;

	for (sect = sechead; sect; sect = sect->next) {
		fprintf(fd, "[%.*s]\n", MAX_CONF_NAME,
			sect->name ? sect->name : "-Global-");

		for (conf = sect->conf; conf; conf = conf->next) {
			fprintf(fd, "%-*.*s %.*s\n",
				MIN_CONF_NAME, MAX_CONF_NAME,
				conf->name,
				MAX_PATH_SIZE, conf->data);
		}
		fprintf(fd, "\n");
	}
}

/* ------------------------------------------------------------ **
**
**	Function......:	config_sect
**
**	Parameters....:	snam		Section (NULL=global)
**
**	Return........:	1=section exists, 0=no such section
**
**	Purpose.......: Check if a section exists.
**
** ------------------------------------------------------------ */

int config_sect(char *snam)
{
	SECTION *sect;

	/*
	** Find the relevant section
	*/
	for (sect = sechead; sect; sect = sect->next) {
		if (misc_strcaseequ(snam, sect->name))
			return 1;
	}
	return 0;
}


/* ------------------------------------------------------------ **
**
**	Function......:	config_sect_find
**
**	Parameters....:	snam		Section (NULL=global)
**
**	Return........:	pointer to the found the section or NULL
**
**	Purpose.......: find a config section by name; if snam
**			is NULL the global section matches!
**
** ------------------------------------------------------------ */
static SECTION* config_sect_find(char *snam)
{
	SECTION *sect;
	char    *wild;

	/*
	** Find the relevant section
	*/
	for(sect = sechead; sect; sect = sect->next) {
		if(sect->name && (wild = strchr(sect->name, '*'))) {
#if defined(COMPILE_DEBUG)
			debug(3, "config_sect_find: wildcard-sect='%.*s*'\n",
				  wild - sect->name, sect->name);
#endif
			if (misc_strncaseequ(sect->name, snam,
			                     wild - sect->name))
				break;
		} else {
			if (misc_strcaseequ(sect->name, snam))
				break;
		}
	}
	return sect;
}

/* ------------------------------------------------------------ **
**
**	Function......:	config_int
**
**	Parameters....:	snam		Section (NULL=global)
**			name		Config option name
**			dflt		Default value
**
**	Return........:	Integer value for config option
**
**	Purpose.......: Retrieve a numeric config value.
**
** ------------------------------------------------------------ */

int config_int(char *snam, char *name, int dflt)
{
	SECTION *sect;
	CONFIG *conf;
	char *p;
	int i;

	if (name == NULL)		/* Basic sanity check	*/
		misc_die(FL, "config_int: ?name?");

#if defined(COMPILE_DEBUG)
	debug(3, "config_int: s='%.*s' n='%.*s' d=%d",
				MAX_CONF_NAME, NIL(snam),
				MAX_CONF_NAME, name,
				dflt);
#endif

	/*
	** Find the relevant section
	*/
	sect = config_sect_find(snam);
	if (sect == NULL)
		return (snam ? config_int(NULL, name, dflt) : dflt);

	/*
	** Now look for the desired value
	*/
	for (conf = sect->conf, p = NULL; conf; conf = conf->next) {
		if (strcasecmp(conf->name, name) == 0) {
			p = conf->data;
			break;
		}
	}
	if (conf == NULL)
		return (snam ? config_int(NULL, name, dflt) : dflt);

	/*
	** Evaluate the found string
	*/
	i = atoi(p);

	/*
	** Return the value found
	*/
#if defined(COMPILE_DEBUG)
	debug(3, "config_int: result=%d", i);
#endif
	return i;
}


/* ------------------------------------------------------------ **
**
**	Function......:	config_bool
**
**	Parameters....:	snam		Section (NULL=global)
**			name		Config option name
**			dflt		Default value
**
**	Return........:	0/1 value for config option
**
**	Purpose.......: Retrieve a boolean config value.
**
** ------------------------------------------------------------ */

int config_bool(char *snam, char *name, int dflt)
{
	SECTION *sect;
	CONFIG *conf;
	char *p;
	int i;

	if (name == NULL)		/* Basic sanity check	*/
		misc_die(FL, "config_bool: ?name?");
	dflt = (dflt != 0);		/* Normalize value	*/

#if defined(COMPILE_DEBUG)
	debug(3, "config_bool: s='%.*s' n='%.*s' d=%d",
				MAX_CONF_NAME, NIL(snam),
				MAX_CONF_NAME, name,
				dflt);
#endif

	/*
	** Find the relevant section
	*/
	sect = config_sect_find(snam);
	if (sect == NULL)
		return (snam ? config_bool(NULL, name, dflt) : dflt);

	/*
	** Now look for the desired value
	*/
	for (conf = sect->conf, p = NULL; conf; conf = conf->next) {
		if (strcasecmp(conf->name, name) == 0) {
			p = conf->data;
			break;
		}
	}
	if (conf == NULL)
		return (snam ? config_bool(NULL, name, dflt) : dflt);

	/*
	** Evaluate the found string
	*/
	if (strcasecmp(p, "y") == 0)
		i = 1;
	else if (strcasecmp(p, "on") == 0)
		i = 1;
	else if (strcasecmp(p, "yes") == 0)
		i = 1;
	else if (strcasecmp(p, "true") == 0)
		i = 1;
	else if (*p >= '0' && *p <= '9')
		i = (atoi(p) != 0);
	else
		i = 0;

	/*
	** Return the value found
	*/
#if defined(COMPILE_DEBUG)
	debug(3, "config_bool: result=%d", i);
#endif
	return i;
}


/* ------------------------------------------------------------ **
**
**	Function......:	config_str
**
**	Parameters....:	snam		Section (NULL=global)
**			name		Config option name
**			dflt		Default value
**
**	Return........:	String value for config option
**
**	Purpose.......: Retrieve a textual config value.
**
** ------------------------------------------------------------ */

char *config_str(char *snam, char *name, char *dflt)
{
	SECTION *sect;
	CONFIG *conf;
	char *p;

	if (name == NULL)		/* Basic sanity check	*/
		misc_die(FL, "config_str: ?name?");

#if defined(COMPILE_DEBUG)
	debug(3, "config_str: s='%.*s' n='%.*s' d='%.*s'",
				MAX_CONF_NAME, NIL(snam),
				MAX_CONF_NAME, name,
				MAX_PATH_SIZE, NIL(dflt));
#endif

	/*
	** Find the relevant section
	*/
	sect = config_sect_find(snam);
	if (sect == NULL)
		return (snam ? config_str(NULL, name, dflt) : dflt);

	/*
	** Now look for the desired value
	*/
	for (conf = sect->conf, p = NULL; conf; conf = conf->next) {
		if (strcasecmp(conf->name, name) == 0) {
			p = conf->data;
			break;
		}
	}
	if (conf == NULL)
		return (snam ? config_str(NULL, name, dflt) : dflt);

	/*
	** Return the value found
	*/
#if defined(COMPILE_DEBUG)
	debug(3, "config_str: result='%.*s'", MAX_PATH_SIZE, NIL(p));
#endif
	return p;
}


/* ------------------------------------------------------------ **
**
**	Function......:	config_addr
**
**	Parameters....:	snam		Section (NULL=global)
**			name		Config option name
**			dflt		Default value
**
**	Return........:	IP Address value for config option
**			(returned in host byte order)
**
**	Purpose.......: Retrieve an IP Address config value.
**
** ------------------------------------------------------------ */

u_int32_t config_addr(char *snam, char *name, u_int32_t dflt)
{
	SECTION *sect;
	CONFIG *conf;
	char *p;
	u_int32_t addr;

	if (name == NULL)		/* Basic sanity check	*/
		misc_die(FL, "config_addr: ?name?");

#if defined(COMPILE_DEBUG)
	debug(3, "config_addr: s='%.*s' n='%.*s' d='%s'",
				MAX_CONF_NAME, NIL(snam),
				MAX_CONF_NAME, name,
				socket_addr2str(dflt));
#endif

	/*
	** Find the relevant section
	*/
	sect = config_sect_find(snam);
	if (sect == NULL)
		return (snam ? config_addr(NULL, name, dflt) : dflt);

	/*
	** Now look for the desired value
	*/
	for (conf = sect->conf, p = NULL; conf; conf = conf->next) {
		if (strcasecmp(conf->name, name) == 0) {
			p = conf->data;
			break;
		}
	}
	if (conf == NULL)
		return (snam ? config_addr(NULL, name, dflt) : dflt);

	/*
	** Evaluate the found string
	*/
	addr = socket_str2addr(p, dflt);

	/*
	** Return the value found
	*/
#if defined(COMPILE_DEBUG)
	debug(3, "config_addr: result='%s'", socket_addr2str(addr));
#endif
	return addr;
}


/* ------------------------------------------------------------ **
**
**	Function......:	config_port
**
**	Parameters....:	snam		Section (NULL=global)
**			name		Config option name
**			dflt		Default value
**
**	Return........:	TCP Port value for config option
**			(returned in host byte order)
**
**	Purpose.......: Retrieve a TCP Port config value.
**
** ------------------------------------------------------------ */

u_int16_t config_port(char *snam, char *name, u_int16_t dflt)
{
	SECTION *sect;
	CONFIG *conf;
	char *p;
	u_int16_t port;

	if (name == NULL)		/* Basic sanity check	*/
		misc_die(FL, "config_port: ?name?");

#if defined(COMPILE_DEBUG)
	debug(3, "config_port: s='%.*s' n='%.*s' d=%d",
				MAX_CONF_NAME, NIL(snam),
				MAX_CONF_NAME, name,
				(int) dflt);
#endif

	/*
	** Find the relevant section
	*/
	sect = config_sect_find(snam);
	if (sect == NULL)
		return (snam ? config_port(NULL, name, dflt) : dflt);

	/*
	** Now look for the desired value
	*/
	for (conf = sect->conf, p = NULL; conf; conf = conf->next) {
		if (strcasecmp(conf->name, name) == 0) {
			p = conf->data;
			break;
		}
	}
	if (conf == NULL)
		return (snam ? config_port(NULL, name, dflt) : dflt);

	/*
	** Evaluate the found string
	*/
	port = socket_str2port(p, dflt);

	/*
	** Return the value found
	*/
#if defined(COMPILE_DEBUG)
	debug(3, "config_port: result=%d", (int) port);
#endif
	return port;
}


/* ------------------------------------------------------------ **
**
**	Function......:	config_uid
**
**	Parameters....:	snam		Section (NULL=global)
**			name		Config option name
**			dflt		Default value
**
**	Return........:	User-ID value for config option
**
**	Purpose.......: Retrieve a User-ID config value.
**
** ------------------------------------------------------------ */

uid_t config_uid(char *snam, char *name, uid_t dflt)
{
	SECTION *sect;
	CONFIG *conf;
	char *p;
	struct passwd *pwd;
	uid_t uid;

	if (name == NULL)		/* Basic sanity check	*/
		misc_die(FL, "config_uid: ?name?");

#if defined(COMPILE_DEBUG)
	debug(3, "config_uid: s='%.*s' n='%.*s' d=%d",
				MAX_CONF_NAME, NIL(snam),
				MAX_CONF_NAME, name,
				(int) dflt);
#endif

	/*
	** Find the relevant section
	*/
	sect = config_sect_find(snam);
	if (sect == NULL)
		return (snam ? config_uid(NULL, name, dflt) : dflt);

	/*
	** Now look for the desired value
	*/
	for (conf = sect->conf, p = NULL; conf; conf = conf->next) {
		if (strcasecmp(conf->name, name) == 0) {
			p = conf->data;
			break;
		}
	}
	if (conf == NULL)
		return (snam ? config_uid(NULL, name, dflt) : dflt);

	/*
	** Evaluate the found string
	*/
	if (*p == '-' || (*p >= '0' && *p <= '9'))
		uid = (uid_t) atoi(p);
	else {
		uid = dflt;
		setpwent();
		while ((pwd = getpwent()) != NULL) {
			if (strcasecmp(pwd->pw_name, p) == 0) {
				uid = pwd->pw_uid;
				break;
			}
		}
		endpwent();
	}

	/*
	** Return the value found
	*/
#if defined(COMPILE_DEBUG)
	debug(3, "config_uid: result=%d", (int) uid);
#endif
	return uid;
}


/* ------------------------------------------------------------ **
**
**	Function......:	config_gid
**
**	Parameters....:	snam		Section (NULL=global)
**			name		Config option name
**			dflt		Default value
**
**	Return........:	Group-ID value for config option
**
**	Purpose.......: Retrieve a Group-ID config value.
**
** ------------------------------------------------------------ */

gid_t config_gid(char *snam, char *name, gid_t dflt)
{
	SECTION *sect;
	CONFIG *conf;
	char *p;
	struct group *grp;
	gid_t gid;

	if (name == NULL)		/* Basic sanity check	*/
		misc_die(FL, "config_gid: ?name?");

#if defined(COMPILE_DEBUG)
	debug(3, "config_gid: s='%.*s' n='%.*s' d=%d",
				MAX_CONF_NAME, NIL(snam),
				MAX_CONF_NAME, name,
				(int) dflt);
#endif

	/*
	** Find the relevant section
	*/
	sect = config_sect_find(snam);
	if (sect == NULL)
		return (snam ? config_gid(NULL, name, dflt) : dflt);

	/*
	** Now look for the desired value
	*/
	for (conf = sect->conf, p = NULL; conf; conf = conf->next) {
		if (strcasecmp(conf->name, name) == 0) {
			p = conf->data;
			break;
		}
	}
	if (conf == NULL)
		return (snam ? config_gid(NULL, name, dflt) : dflt);

	/*
	** Evaluate the found string
	*/
	if (*p == '-' || (*p >= '0' && *p <= '9'))
		gid = (gid_t) atoi(p);
	else {
		gid = dflt;
		setgrent();
		while ((grp = getgrent()) != NULL) {
			if (strcasecmp(grp->gr_name, p) == 0) {
				gid = grp->gr_gid;
				break;
			}
		}
		endgrent();
	}

	/*
	** Return the value found
	*/
#if defined(COMPILE_DEBUG)
	debug(3, "config_gid: result=%d", (int) gid);
#endif
	return gid;
}


/* ------------------------------------------------------------
 * $Log: com-config.c,v $
 * Revision 1.7  2002/05/02 12:57:10  mt
 * merged with v1.8.2.2
 *
 * Revision 1.6.2.2  2002/04/04 10:00:07  mt
 * fixed bug done while last changes
 *
 * Revision 1.6.2.1  2002/01/28 01:55:58  mt
 * implemented wildcard-section support
 *
 * Revision 1.6  2002/01/14 18:12:20  mt
 * implemented config_dump function to dump in-memory config to a FILE stream
 *
 * Revision 1.5  1999/09/23 18:34:44  wiegand
 * remove white space at line start (incl. continuation lines)
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

