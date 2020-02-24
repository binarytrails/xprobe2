/* $Id: udp_ping.cc,v 1.1 2003/08/05 03:35:11 mederchik Exp $ */
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
#define _XPROBE_MODULE
#include "xplib.h"
#include "xprobe_module.h"
#include "xprobe_module_hdlr.h"
#include "interface.h"
#include "cmd_opts.h"
#include "target.h"
#include "udp_ping.h"

extern Interface *ui;
extern Cmd_Opts *copts;



int UDP_Ping_Mod::init(void) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
    return OK;
}


int UDP_Ping_Mod::exec(Target *tg, OS_Matrix *os) {

    char buf[1024];
    Xprobe::Timeval tv, t1, t2, tt;
	struct in_addr local=tg->get_interface_addr(), remote=tg->get_addr();
	UDP udpp(inet_ntoa(remote));
    int port, ret, done;
    /* FIXME */
	ICMP sn(inet_ntoa(local));



    xprobe_debug(XPROBE_DEBUG_MODULES, "--%s module has been executed against: %s\n", get_name(),
            inet_ntoa(remote));
    
    tv = copts->get_timeout();

    if (tg->get_port(IPPROTO_UDP, XPROBE_TARGETP_OPEN) == -1 &&
        tg->get_port(IPPROTO_UDP, XPROBE_TARGETP_CLOSED) == -1) {
        ui->msg("[-] %s module: no closed/open UDP ports known on %s. Module test failed\n", get_name(),
                inet_ntoa(remote));
        return FAIL;
    }
    if ((port = tg->get_port(IPPROTO_UDP, XPROBE_TARGETP_OPEN)) == -1 ) {

        port = tg->get_port(IPPROTO_UDP, XPROBE_TARGETP_CLOSED);
    } else {
   //     UDP sn(inet_ntoa(local));
    }

	sn.init_device(tg->get_interface(), 0, 1500);
	sn.timeout(tv);

	srand(time(NULL));
	udpp.set_src(inet_ntoa(local));
	udpp.set_srcport(5555);
	udpp.set_dstport(port);
	udpp.set_ttl(64);
	udpp.set_id(rand());


    t1 = Xprobe::Timeval::gettimeofday();

   	udpp.sendpack("");

    done = 0;
	while(!done) {
		ret = sn.sniffpack(buf, sizeof(buf));
		if (!sn.timeout()) {
			/* FIXME: lame check */
            
		        //printf("got responce: %x %i\n", sn.get_src(), sn.get_id());
			if (sn.get_src() == remote.s_addr && 
                sn.get_proto() == IPPROTO_ICMP && 
                sn.get_type() == ICMP_DEST_UNREACH && 
                sn.get_code() == ICMP_PORT_UNREACH) {

				done = 1;
				xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Got reply.\n", get_name());
			}
		} else {
			ret = -1;
			done = 1; // timeout
		}
	}

    t2 = Xprobe::Timeval::gettimeofday();

    if (ret > -1) {
        tt = t2 - t1;
        xprobe_debug(XPROBE_DEBUG_MODULES, "UDP PING response: %.7f\n", (double)tt);
        if (tg->get_rtt() < tt) 
            tg->set_rtt(tt);
        os->add_result(get_id(), 1, XPROBE_MATCH_YES);
    } else {
        os->add_result(get_id(), 1, XPROBE_MATCH_NO);
    }

    return OK;
}

int UDP_Ping_Mod::fini(void) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
    return OK;
}

int UDP_Ping_Mod::parse_keyword(int os_id, const char *kwd, const char *val)  {
    
    xprobe_debug(XPROBE_DEBUG_MODULES, "Parsing for %i : %s  = %s\n",
                                                        os_id,  kwd, val);
    return OK;
};

/* initialization function */

int udp_ping_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {

    UDP_Ping_Mod *module = new UDP_Ping_Mod;

    module->set_name(nm);
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the UDP PING module\n");
    pt->register_module(module);

return OK;
}


