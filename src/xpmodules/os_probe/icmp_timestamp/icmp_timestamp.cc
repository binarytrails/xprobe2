/* $Id: icmp_timestamp.cc,v 1.13 2005/06/26 11:26:13 mederchik Exp $ */
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
#include "icmp_timestamp.h"

extern Interface *ui;

/* initialization function */

int icmp_timestamp_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {

    ICMP_Timestamp_Mod *module = new ICMP_Timestamp_Mod;

    module->set_name(nm);
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the ICMP Timestamp module\n");
    pt->register_module(module);
    pt->add_keyword(module->get_id(),"icmp_timestamp_reply");
    pt->add_keyword(module->get_id(),"icmp_timestamp_reply_ttl");
    pt->add_keyword(module->get_id(),"icmp_timestamp_reply_ip_id");

return OK;
}

ICMP_Timestamp_Mod::ICMP_Timestamp_Mod(void):Xprobe_Module(XPROBE_MODULE_OSTEST, 
		"fingerprint:icmp_tstamp", "ICMP Timestamp request fingerprinting module") {
	ICMP_Timestamp_Reply_Check *timrep = new ICMP_Timestamp_Reply_Check;
	ICMP_Timestamp_Ip_Id_Check *timid = new ICMP_Timestamp_Ip_Id_Check;
	ICMP_Timestamp_Ttl_Check *timttl = new ICMP_Timestamp_Ttl_Check;

	kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_timestamp_reply", timrep));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_timestamp_reply_ttl", timttl));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_timestamp_reply_ip_id", timid));
}

ICMP_Timestamp_Mod::~ICMP_Timestamp_Mod(void) {

	for (s_i=kwd_chk.begin(); s_i != kwd_chk.end(); s_i++)
		delete s_i->second;
}

int ICMP_Timestamp_Mod::init(void) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
    return OK;
}


int ICMP_Timestamp_Mod::exec(Target *tg, OS_Matrix *os) {
    
    xprobe_debug(XPROBE_DEBUG_MODULES, "--%s module has been executed against: %s\n", get_name(),
            inet_ntoa(tg->get_addr()));

    current_os = os;
    do_icmp_query(tg);
    
    return OK;
}

int ICMP_Timestamp_Mod::fini(void) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
    return OK;
}

int ICMP_Timestamp_Mod::parse_keyword(int os_id, const char *kwd, const char *val) {

	if ((s_i=kwd_chk.find(kwd)) != kwd_chk.end()) {
		return s_i->second->parse_param(os_id, val);
	}
	ui->msg("Ooops..none matched %s %s\n", kwd, val);
	return FAIL;
}



int ICMP_Timestamp_Mod::do_icmp_query(Target *tg) {

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
    icmpp.set_type(ICMP_TIMESTAMP);
    fflush(stderr);
    ret = -1;
    
    icmpp.timeout(tv);
    sn.timeout(tv);
	ret = icmpp.send_timestamp_payload();
    done = 0;
    while (!done) {
        ret = sn.sniffpack(buf, sizeof(buf));
        /* packet response */
//        if (ret > 0 && sn.get_src() != local.s_addr 
        if (!sn.timeout() && sn.get_src() == remote.s_addr 
            && sn.get_type() == ICMP_TIMESTAMPREPLY && sn.get_icmpId() == icmpp_id) {
			done = 1;
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Received reply.\n", get_name());
		}
     //   if (ret < 1) done = 1; /* timeout */    
		if (sn.timeout()) {
			done = 1;
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Timed out, no reply received.\n", get_name());
		}
    }
    
    /* do_response_check(ret);
    if (ret > 0) 
        do_ttl_check(sn.get_ttl());
	*/
	for (s_i = kwd_chk.begin(); s_i != kwd_chk.end(); s_i++) 
		s_i->second->check_param(&sn, &icmpp, current_os);
	if (tg->generate_sig())
		generate_signature(tg, &sn, &icmpp);
    return OK;

}

void ICMP_Timestamp_Mod::generate_signature(Target *tg, ICMP *pack, ICMP *orig) {
	string keyword, value;
	unsigned int ttl;

/* 
#       icmp_timestamp_reply = [ y, n]
#       icmp_timestamp_reply_ttl = [>< decimal num]
#       icmp_timestamp_reply_ip_id = [0, !0, SENT]
*/
	if (!pack->timeout()) {
		tg->signature("icmp_timestamp_reply", "y");
		keyword = "icmp_timestamp_reply_ttl";
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
		keyword="icmp_timestamp_reply_ip_id";
		if (pack->get_id() == 0)
			value="0";
		else if (pack->get_id() == orig->get_id())
			value = "SENT";
		else 
			value = "!0";
		tg->signature(keyword, value);
	} else {
		tg->signature("icmp_timestamp_reply", "n");
		tg->signature("icmp_timestamp_reply_ttl", "<64");
		tg->signature("icmp_timestamp_reply_ip_id", "!0");
	}



}

int ICMP_Timestamp_Reply_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {
	int gotp=ip_pkt->timeout() ? 0 : 1;

	orig_pkt->timeout();    //suspend the warning
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

int ICMP_Timestamp_Ip_Id_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

	if (!ip_pkt->timeout())
		return add_param(ip_pkt->get_id(), orig_pkt->get_id(), os);
	return OK;
}

int ICMP_Timestamp_Ttl_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

	if(!ip_pkt->timeout())
		return add_param(ip_pkt->get_ttl(), orig_pkt->get_ttl(), os);
	return OK;
}
