/* $Id: interface.h,v 1.2 2003/04/22 20:00:01 fygrave Exp $ */
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

#ifndef INTERFACE_H
#define INTERFACE_H

#include "xprobe.h"

/* Generic interface class, use it if develop UI of your own.
 * functions usage agreement:
 * {p,}error()  - display errors.
 * msg()        - display messages.
 * log()        - display and log stuff.
 * verbose()    - verbose messages.
 * debug()      - debug messages.
 */


class Interface {
    private:
    public:
        Interface(void);
        virtual ~Interface(void);
        virtual    void error(const char *, ...) = 0;
        virtual    void perror(const char *) = 0;
        virtual    void msg(const char *, ...) = 0;
        virtual    void log(const char *, ...) = 0;
        virtual    void verbose(int, const char *, ...) = 0;
        virtual    void debug(unsigned long , const char *,
                             int, const char *, ...) = 0;
};

#endif /* INTERFACE_H */
            
