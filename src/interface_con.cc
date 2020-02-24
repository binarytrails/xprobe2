/* $Id: interface_con.cc,v 1.3 2003/08/20 05:30:16 mederchik Exp $ */
/*
** Copyright (C) 2001 Fyodor Yarochkin <fygrave@tigerteam.net>,
**                    Ofir Arkin       <ofir@sys-security.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


#include "xprobe.h"
#include "interface_con.h"
#include "cmd_opts.h"

extern Cmd_Opts *copts;

Interface_Con::Interface_Con(void) {
	logopened = false;
    return;
}

Interface_Con::~Interface_Con(void) {
	if (logopened && fclose(logfile) != 0)
		msg("Interface_Con::Interface_Con(): fclose() failed: %s\n", strerror(errno));
    return;
}

void Interface_Con::error(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

}

void Interface_Con::perror(const char *errmsg) {

    fprintf(stderr,"%s: %s",errmsg, strerror(errno));
}

void Interface_Con::msg(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

void Interface_Con::log(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
	if (copts->get_logfile()) {
		if (!logopened) {
			//open the log file
			if ((logfile = fopen(copts->get_logfile(), "w")) == NULL) {
				msg("Interface_Con::log(): fopen() failed: %s\n", strerror(errno));
				return;
			}
			// it seems to have worked
			logopened = true;
		}
		vfprintf(logfile, fmt, ap);
	}
    va_end(ap);
}

void Interface_Con::verbose(int lvl, const char *fmt, ...) {
    va_list ap;

    if (copts->is_verbose() < lvl) return;

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);

}

void Interface_Con::debug(unsigned long lvl, const char *file, int line, const char *fmt, ...) {
    va_list ap;

    if (!(copts->debug() & lvl)) return;

    va_start(ap, fmt);
    fprintf(stderr,"DEBUG: %s %i:\t", file, line);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

}

