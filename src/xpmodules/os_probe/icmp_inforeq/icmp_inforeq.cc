/* $Id: icmp_inforeq.cc,v 1.14 2005/06/26 11:26:13 mederchik Exp $ */
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
#include "target.h"
#include "icmp_inforeq.h"

extern Interface *ui;

/* initialization function */

int icmp_inforeq_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {

    ICMP_Inforeq_Mod *module = new ICMP_Inforeq_Mod;

    module->set_name(nm);
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the ICMP Inforeq module\n");
    pt->register_module(module);
    pt->add_keyword(module->get_id(),"icmp_info_reply");
    pt->add_keyword(module->get_id(),"icmp_info_reply_ttl");
	pt->add_keyword(module->get_id(), "icmp_info_reply_ip_id");

return OK;
}

ICMP_Inforeq_Mod::ICMP_Inforeq_Mod(void):Xprobe_Module(XPROBE_MODULE_OSTEST, "fingerprint:icmp_info","ICMP Information request fingerprinting module") {

	ICMP_Inforeq_Reply_Check *inforep = new ICMP_Inforeq_Reply_Check;
	ICMP_Inforeq_Ip_Id_Check *infoid = new ICMP_Inforeq_Ip_Id_Check;
	ICMP_Inforeq_Ttl_Check *infottl = new ICMP_Inforeq_Ttl_Check;

	kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_info_reply",inforep));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_info_reply_ttl",infottl));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_info_reply_ip_id",infoid));
}

ICMP_Inforeq_Mod::~ICMP_Inforeq_Mod(void) {

	// free allocated classes 
	for (s_i=kwd_chk.begin(); s_i != kwd_chk.end(); s_i++)
		delete s_i->second;
}


int ICMP_Inforeq_Mod::init(void) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
    return OK;
}


int ICMP_Inforeq_Mod::exec(Target *tg, OS_Matrix *os) {
    
    xprobe_debug(XPROBE_DEBUG_MODULES, "--%s module has been executed against: %s\n", get_name(),
            inet_ntoa(tg->get_addr()));

    current_os = os;
    do_icmp_query(tg);
    
    return OK;
}

int ICMP_Inforeq_Mod::fini(void) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
    return OK;
}

int ICMP_Inforeq_Mod::parse_keyword(int os_id, const char *kwd, const char *val) {

    xprobe_debug(XPROBE_DEBUG_SIGNATURES, "Parsing for %i : %s  = %s\n",
                                                        os_id,  kwd, val);
	if ((s_i=kwd_chk.find(kwd)) != kwd_chk.end()) {
		return s_i->second->parse_param(os_id, val);
	}
	return OK;
}

int ICMP_Inforeq_Mod::do_icmp_query(Target *tg) {

    char buf[1024];
    struct timeval tv;
    int ret;
    int done;
    unsigned short int icmpp_id;
    struct in_addr local, remote;

/* our lamyer randomizer ;-p */
    srand(time(NULL));
    icmpp_id = rand();
    local = tg->get_interface_addr();
	remote = tg->get_addr();

    ICMP icmpp(inet_ntoa(remote));
    ICMP sn(inet_ntoa(local));
    sn.init_device(tg->get_interface(), 0, 1500);

    tv = tg->get_rtt();

    icmpp.set_src(inet_ntoa(tg->get_interface_addr()));
    icmpp.set_icmpId(icmpp_id);
    icmpp.set_type(ICMP_INFO_REQUEST);
    fflush(stderr);
    ret = -1;
    
    icmpp.timeout(tv);
    sn.timeout(tv);
    ret = icmpp.sendpack("");
    done = 0;
    while (!done) {
        ret = sn.sniffpack(buf, sizeof(buf));
        /* packet response */
//        if (ret > 0 && sn.get_src() != local.s_addr 
        if (!sn.timeout() && sn.get_src() == remote.s_addr 
            && sn.get_type() == ICMP_INFO_REPLY && sn.get_icmpId() == icmpp_id) {
			done = 1;
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Received reply.\n", get_name());
		}
//        if (ret < 1) done = 1; /* timeout */    
		if (sn.timeout()) {
			done = 1;
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Timed out, no reply received.\n", get_name());
		}
    }
	for (s_i = kwd_chk.begin(); s_i != kwd_chk.end(); s_i++)
		s_i->second->check_param(&sn, &icmpp, current_os);

	if (tg->generate_sig())
		generate_signature(tg, &sn, &icmpp);
    return OK;

}

void ICMP_Inforeq_Mod::generate_signature(Target *tg, ICMP *pack, ICMP *orig) {
	string keyword, value;
	unsigned int ttl;
/*
#       icmp_info_reply = [ y, n]
#       icmp_info_reply_ttl = [>< decimal num] 
#       icmp_info_reply_ip_id = [0, !0, SENT]
*/
	if (!pack->timeout()) {
		tg->signature("icmp_info_reply", "y");
		keyword = "icmp_info_reply_ttl";
		ttl = pack->get_ttl() + tg->get_distance();
		value = "<";
		if (ttl <= 32)
			value.append("32");
		else if (ttl <= 60)
			value.append("60");
		else if (ttl <= 64)
			value.append("64");
		else if (ttl <= 128)
			value.append("128");
		else if (ttl <= 255)
			value.append("255");
		tg->signature(keyword, value);
		keyword = "icmp_info_reply_ip_id";
		if (pack->get_id() == 0)
			value = "0";
		else if (pack->get_id() == orig->get_id())
			value = "SENT";
		else
			value = "!0";
		tg->signature(keyword, value);
	} else {
		tg->signature("icmp_info_reply", "n");
		tg->signature("icmp_info_reply_ttl", "<255");
		tg->signature("icmp_info_reply_ip_id", "!0");
	}

}

int ICMP_Inforeq_Reply_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

	int gotp=ip_pkt->timeout() ? 0 : 1;
	orig_pkt->timeout();	//suspend the warning
	add_param(gotp, 0, os);
	if (!gotp) {
		/* 2 keywords depend on this on
		 * so to be able to get 100% we
		 * generate 2 matches here if no
		 * reply was received
		 */
		gen_match(2, os);
	}
	return OK;
}

int ICMP_Inforeq_Ip_Id_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

	if (!ip_pkt->timeout())
		return add_param(ip_pkt->get_id(), orig_pkt->get_id(), os);
	return OK;
}

int ICMP_Inforeq_Ttl_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

	if (!ip_pkt->timeout())
		return add_param(ip_pkt->get_ttl(), orig_pkt->get_ttl(), os);
	return OK;
}
