/* $Id: test_mod.cc,v 1.2 2003/04/22 20:00:51 fygrave Exp $ */
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
#define _XPROBE_MODULE
#include "xplib.h"
#include "xprobe_module.h"
#include "xprobe_module_hdlr.h"
#include "target.h"
#include "interface.h"
#include "test_mod.h"

extern Interface *ui;



int Test_Mod::init(void) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
    return OK;
}


int Test_Mod::exec(Target *tg, OS_Matrix *os) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "--%s module has been executed against: %s\n", get_name(),
            inet_ntoa(tg->get_addr()));
    os->add_result(get_id(), 1, XPROBE_MATCH_YES);
    return OK;
}

int Test_Mod::fini(void) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
    return OK;
}

int Test_Mod::parse_keyword(int os_id, char *kwd, char *val)  {
    
    xprobe_debug(XPROBE_DEBUG_MODULES, "Parsing for %i : %s  = %s\n",
                                                        os_id,  kwd, val);
    return OK;
};

/* initialization function */

int test_mod_init(Xprobe_Module_Hdlr *pt) {

    Test_Mod *test_mod = new Test_Mod;

    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the test module\n");
    pt->register_module(test_mod);

return OK;
}


