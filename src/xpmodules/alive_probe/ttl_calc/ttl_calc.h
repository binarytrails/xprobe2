/* $Id: ttl_calc.h,v 1.3 2003/08/05 03:35:12 mederchik Exp $ */
/*
** Copyright (C) 2001, 2002 Meder Kydyraliev
**
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
#ifndef TTL_MOD_H
#define TTL_MOD_H

#include "xprobe.h"
#include "usi++/usi++.h"
#include <pcap.h>
#include "xprobe_module.h"
#include "xprobe_module_hdlr.h"
#include "interface.h"
#define _XPROBE_MODULE
#include "xplib.h"

#ifndef __USE_BSD
#define __USE_BSD
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

class TTL_Mod: public Xprobe_Module {
    private:
    int sock;
	int get_ttl_distance (Target *);
    void build_DNS_reply (u_char *);
	int getrandom(int limit);
    public:
		/* constructor */
        TTL_Mod(void) : Xprobe_Module(XPROBE_MODULE_ALIVETEST, "infogather:ttl_calc", "TCP and UDP based TTL distance calculation") { return; }
		/* destructor */
        ~TTL_Mod(void) { return; }
        int init(void);
        int parse_keyword(int, const char *, const char *);
        int exec(Target *, OS_Matrix *);
        int fini(void);
};

#endif
