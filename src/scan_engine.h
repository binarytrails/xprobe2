/* $Id: scan_engine.h,v 1.2 2003/04/22 20:00:01 fygrave Exp $ */
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

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

#include "xprobe.h"

class Scan_Engine {
    private:
        int check_alive(struct in_addr);
        int os_probe(struct in_addr);
    public:
        int init(void);
        int run(void);
        int fini(void);
};

#endif /* SCAN_ENGINE_H */
