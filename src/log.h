/*
** Copyright (C) 2003 Meder Kydyraliev <meder@areopag.net>
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

#ifndef LOGH
#define LOGH

#include "xprobe.h"
#include "interface.h"

extern Interface *ui;

class Log {
		string logfile;
		bool logopened;
		FILE *ofile;
		int open();
	protected:
		int write(const char *, ...);
	public:
		Log() { logopened = false; }
		virtual ~Log() { if (logopened) fclose(ofile); }
		Log(const char *lfile) { set_logfile(lfile); logopened = false; }
		int set_logfile(const char *lfile) {
			if (lfile != NULL && logopened != true) {
				logfile = lfile;
				return open();
			}
			return OK;
		}
		virtual int log(unsigned int type, const char *, ...)=0;
		void flush() { if (logopened) fflush(ofile); }
		bool is_opened() { return logopened; }
};

class XML_Log: public Log {
		int tags_opened;
		int log_mod(const char *, va_list);
		int log_start(const char *fmt, va_list varg);
		int log_run(const char *fmt, va_list varg);
		int log_module(const char *fmt, va_list varg);
		int log_target(const char *fmt, va_list varg);
		int log_state(const char *fmt, va_list varg);
		int log_rtt(const char *fmt, va_list varg);
		int log_pscan(const char *fmt, va_list varg);
		int log_port_stats(char, const char *fmt, va_list varg);
		int log_port(const char *fmt, va_list varg);
		int log_guess(int, const char *, va_list);
		int log_other_ports(char, const char *, va_list);
		void write_tabs() { int k; for (k=0; k < tags_opened; k++) write("\t"); }
	public:
		XML_Log() { tags_opened=0; }
		XML_Log(const char *lfile): Log(lfile) { tags_opened=0; }
		~XML_Log() { return; }
		int log(unsigned int type, const char *, ...);
};

#endif
