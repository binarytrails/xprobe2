/* $Id: icmp_ping.cc,v 1.7 2004/10/12 11:30:04 mederchik Exp $ */
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
#include "usi++/usi++.h"
#include <signal.h>
#include <setjmp.h>
#define _XPROBE_MODULE
#include "xplib.h"
#include "xprobe_module.h"
#include "xprobe_module_hdlr.h"
#include "interface.h"
#include "cmd_opts.h"
#include "target.h"
#include "icmp_ping.h"

extern Interface *ui;
extern Cmd_Opts *copts;

/* initialization function */

int icmp_ping_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {

    ICMP_Ping_Mod *module = new ICMP_Ping_Mod;

    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the ICMP PING module\n");
    module->set_name(nm);
    pt->register_module(module);

return OK;
}



int ICMP_Ping_Mod::init(void) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
    return OK;
}


int ICMP_Ping_Mod::exec(Target *tg, OS_Matrix *os) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "--%s module has been executed against: %s\n", get_name(),
            inet_ntoa(tg->get_addr()));
    if (do_icmp_ping(tg)) {
        os->add_result(get_id(), 1, XPROBE_MATCH_YES);
    } else {
        os->add_result(get_id(), 1, XPROBE_MATCH_NO);
    }
    return OK;
}

int ICMP_Ping_Mod::fini(void) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
    return OK;
}

int ICMP_Ping_Mod::parse_keyword(int os_id, const char *kwd, const char *val)  {
    
    xprobe_debug(XPROBE_DEBUG_MODULES, "Parsing for %i : %s  = %s\n",
                                                        os_id,  kwd, val);
    return OK;
};



int ICMP_Ping_Mod::do_icmp_ping(Target *tg) {

    char buf[1024];
    Xprobe::Timeval tv;
    int ret;
    int done;
    unsigned short int icmpp_id;
    struct in_addr local, remote;
    Xprobe::Timeval t1, t2, tt; // to calc rtt

/* our lamyer randomizer ;-p */
    srand(time(NULL));
    icmpp_id = rand();
    local = tg->get_interface_addr();
	remote = tg->get_addr();

    ICMP icmpp(remote.s_addr);
    ICMP sn(local.s_addr);
    sn.init_device(tg->get_interface(), 0, 1500);
	/* sn.setfilter("icmp[0] = 0");*/
    tv = copts->get_timeout();
    icmpp.set_src(local.s_addr);
    icmpp.set_icmpId(icmpp_id);
    icmpp.set_type(ICMP_ECHO);
    fflush(stderr);
    ret = -1;
    
    icmpp.timeout(tv);
    sn.timeout(tv);
    t1 = Xprobe::Timeval::gettimeofday();
	ret = icmpp.send_ping_payload();
    done = 0;
    while (!done) {
        ret = sn.sniffpack(buf, sizeof(buf));
        /* packet response */
        if (! sn.timeout() && sn.get_src() == remote.s_addr && 
			sn.get_type() == ICMP_ECHOREPLY && sn.get_icmpId() == icmpp_id) done = 1;
        if (sn.timeout()) done = 1; /* timeout */    
    }
    t2 = Xprobe::Timeval::gettimeofday();
    
    if (! sn.timeout()) {
	    tt = t2 - t1;
        if (tg->get_rtt() < tt) 
            tg->set_rtt(tt);
	//if ((double)tg->get_rtt() <= 0.0)
	//	tg->set_rtt(1.0);
        return 1;
    }
    return 0;
    
}
