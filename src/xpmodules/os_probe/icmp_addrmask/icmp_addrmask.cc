/* $Id: icmp_addrmask.cc,v 1.14 2005/06/26 11:26:12 mederchik Exp $ */
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
#include "icmp_addrmask.h"

extern Interface *ui;

/* initialization function */

int icmp_addrmask_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {

    ICMP_Addrmask_Mod *module = new ICMP_Addrmask_Mod;

    module->set_name(nm);
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the ICMP Addrmask module\n");
    pt->register_module(module);
    pt->add_keyword(module->get_id(),"icmp_addrmask_reply");
    pt->add_keyword(module->get_id(),"icmp_addrmask_reply_ttl");
	pt->add_keyword(module->get_id(), "icmp_addrmask_reply_ip_id");

return OK;
}


ICMP_Addrmask_Mod::ICMP_Addrmask_Mod(void): Xprobe_Module(XPROBE_MODULE_OSTEST, "fingerprint:icmp_amask","ICMP Address mask request fingerprinting module") { 

	ICMP_Addrmask_Reply_Check *repchk = new ICMP_Addrmask_Reply_Check;
	ICMP_Addrmask_Ip_Id_Check *ipidchk = new ICMP_Addrmask_Ip_Id_Check;
	ICMP_Addrmask_Ttl_Check	*ttlchk = new ICMP_Addrmask_Ttl_Check;

	kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_addrmask_reply", repchk));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_addrmask_reply_ttl", ttlchk));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_addrmask_reply_ip_id", ipidchk));
}

ICMP_Addrmask_Mod::~ICMP_Addrmask_Mod(void) {
	
	for (s_i = kwd_chk.begin(); s_i != kwd_chk.end(); s_i++) 
		delete s_i->second;
}

int ICMP_Addrmask_Mod::init(void) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
    return OK;
}


int ICMP_Addrmask_Mod::exec(Target *tg, OS_Matrix *os) {
    
    xprobe_debug(XPROBE_DEBUG_MODULES, "--%s module has been executed against: %s\n", get_name(),
            inet_ntoa(tg->get_addr()));

    current_os = os;
    do_icmp_query(tg);
    
    return OK;
}

int ICMP_Addrmask_Mod::fini(void) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
    return OK;
}

int ICMP_Addrmask_Mod::parse_keyword(int os_id, const char *kwd, const char *val) {

	if ((s_i = kwd_chk.find(kwd)) != kwd_chk.end()) {
			return s_i->second->parse_param(os_id, val);
	}
	ui->msg ("No keywords matched(%s=%s)!", kwd, val);
	return FAIL;
}



int ICMP_Addrmask_Mod::do_icmp_query(Target *tg) {

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
    icmpp.set_type(ICMP_ADDRESS);
    fflush(stderr);
    ret = -1;
    
    icmpp.timeout(tv);
    sn.timeout(tv);
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Sending ICMP message\n");
	ret = icmpp.send_addrmask_payload();
    done = 0;
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Receiving ICMP response\n");
    while (!done) {
        ret = sn.sniffpack(buf, sizeof(buf));
        xprobe_debug(XPROBE_DEBUG_MODULES, "Received %i bytes\n", ret);
        /* packet response */
//        if (ret > 0 && sn.get_src() != local.s_addr 
        if (!sn.timeout() && sn.get_src() == remote.s_addr 
            && sn.get_type() == ICMP_ADDRESSREPLY && sn.get_icmpId() == icmpp_id) {
			done = 1;
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Received reply.\n", get_name());
		}
//        if (ret < 1) done = 1; /* timeout */    
		if (sn.timeout()) {
			done = 1; 
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Timed out, no reply received.\n", get_name());
		}
    }
    
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Got good ICMP response\n");
	for (s_i = kwd_chk.begin(); s_i != kwd_chk.end(); s_i++)
		s_i->second->check_param(&sn, &icmpp, current_os);

	if (tg->generate_sig())
		generate_signature(tg, &sn, &icmpp);
    return OK;

}

void ICMP_Addrmask_Mod::generate_signature(Target *tg, ICMP *pack, ICMP *orig) {
	string keyword, value;
	unsigned int ttl;
	/*
#       icmp_addrmask_reply = [ y, n]
#       icmp_addrmask_reply_ttl = [>< decimal num] 
#       icmp_addrmask_reply_ip_id = [0, !0, SENT]
	*/
	if (!pack->timeout()) {
		keyword = "icmp_addrmask_reply";
		value = "y";
		tg->signature(keyword, value);
		keyword="icmp_addrmask_reply_ttl";
		ttl = pack->get_ttl() + tg->get_distance();
		/* following checkpoint values are used for ICMP:
		 * 32, 64, 128, 255
		 */
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

		keyword = "icmp_addrmask_reply_ip_id";
		if (pack->get_id() == 0)
			value = "0";
		else if (pack->get_id() == orig->get_id())
			value = "SENT";
		else
			value = "!0";
		tg->signature(keyword, value);
	} else {
		tg->signature("icmp_addrmask_reply", "n");
		tg->signature("icmp_addrmask_reply_ttl", "<255");
		tg->signature("icmp_addrmask_reply_ip_id", "!0");
	}
}

int ICMP_Addrmask_Reply_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {
	int gotp=ip_pkt->timeout() ? 0 : 1;

	// suspend warning
	orig_pkt->timeout();
	add_param(gotp, 0, os);
	if (!gotp) {
		/* no reply recieved so
		 * now we need to generate 2 matches (2 keywords
		 * that depend on reply)
		 * so that we are able to get 100% even
		 * if no reply was received
		 * NOTE: need to make module count
		 * depending keywords automatically
		 */
		gen_match(2, os);
	}
	return OK;
}

int ICMP_Addrmask_Ip_Id_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

	if(!ip_pkt->timeout())
		// we have received reply
		return add_param(ip_pkt->get_id(), orig_pkt->get_id(), os);
	return OK;
}

int ICMP_Addrmask_Ttl_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

	if (!ip_pkt->timeout())
		// we have received reply
		return add_param(ip_pkt->get_ttl(), orig_pkt->get_ttl(), os);
	return OK;
}
