/* $Id: test_mod.h,v 1.2 2003/04/22 20:00:54 fygrave Exp $ */
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

#ifndef TEST_MOD_H
#define TEST_MOD_H

#include "xprobe.h"
#include "xprobe_module.h"


class Test_Mod: public Xprobe_Module {
    private:
    public:
        Test_Mod(void) : Xprobe_Module(XPROBE_MODULE_ALIVETEST, "ICMP ECHO") { return; }
        ~Test_Mod(void) { return; }
        int init(void);
        int parse_keyword(int, char *, char *);
        int exec(Target *, OS_Matrix *);
        int fini(void);
};

#endif /* TEST_MOD_H */
