/*
 * $Id: com-config.h,v 1.2 2002/01/14 18:12:20 mt Exp $
 *
 * Header for common functions for configuration reading
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

#if !defined(_COM_CONFIG_H_)
#define _COM_CONFIG_H_

#include <config.h>

#if defined(STDC_HEADERS)
#  include <stdio.h>
#endif

/* ------------------------------------------------------------ */

void      config_read(char *file, int dflg);
void      config_dump(FILE *fd);
int       config_sect(char *snam);

int       config_int (char *snam, char *name, int       dflt);
int       config_bool(char *snam, char *name, int       dflt);
char     *config_str (char *snam, char *name, char     *dflt);

u_int32_t config_addr(char *snam, char *name, u_int32_t dflt);
u_int16_t config_port(char *snam, char *name, u_int16_t dflt);

uid_t     config_uid (char *snam, char *name, uid_t     dflt);
gid_t     config_gid (char *snam, char *name, gid_t     dflt);


/* ------------------------------------------------------------ */

#endif /* defined(_COM_CONFIG_H_) */

/* ------------------------------------------------------------
 * $Log: com-config.h,v $
 * Revision 1.2  2002/01/14 18:12:20  mt
 * implemented config_dump function to dump in-memory config to a FILE stream
 *
 * Revision 1.1  1999/09/15 14:05:38  wiegand
 * initial checkin
 *
 * ------------------------------------------------------------ */

