/* $Id: interface_con.h,v 1.3 2003/08/20 05:30:16 mederchik Exp $ */
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

#ifndef INTERFACE_CON_H
#define INTERFACE_CON_H

#include "xprobe.h"
#include "interface.h"

class Interface_Con: public Interface {
    private:
		FILE *logfile;
		bool logopened;
    public:
        Interface_Con(void);
        ~Interface_Con(void);
        void error(const char *, ...);
        void perror(const char *);
        void msg(const char *, ...);
        void log(const char *, ...);
        void verbose(int, const char *, ...);
        void debug(unsigned long, const char *, int, const char *, ...);
};

#endif /* INTERFACE_H */
            
