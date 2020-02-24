/* $Id: icmp_echo_id.cc,v 1.16 2005/06/26 11:26:12 mederchik Exp $ */
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
#include "xprobe_module_param.h"
#include "xprobe_module_hdlr.h"
#include "interface.h"
#include "target.h"
#include "icmp_echo_id.h"

extern Interface *ui;

/* initialization function */

int icmp_echo_id_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {

    ICMP_Echo_Id_Mod *module = new ICMP_Echo_Id_Mod;

    module->set_name(nm);
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the ICMP ECHO ID module\n");
    pt->register_module(module);
    pt->add_keyword(module->get_id(),"icmp_echo_reply");
    pt->add_keyword(module->get_id(),"icmp_echo_code");
    pt->add_keyword(module->get_id(),"icmp_echo_ip_id");
    pt->add_keyword(module->get_id(),"icmp_echo_tos_bits");
    pt->add_keyword(module->get_id(),"icmp_echo_df_bit");
    pt->add_keyword(module->get_id(),"icmp_echo_reply_ttl");

return OK;
}

ICMP_Echo_Id_Mod::ICMP_Echo_Id_Mod(void): Xprobe_Module(XPROBE_MODULE_OSTEST, "fingerprint:icmp_echo","ICMP Echo request fingerprinting module") { 
    
    ICMP_Echo_Code_Chk *iecc = new ICMP_Echo_Code_Chk;
    ICMP_Echo_Id_Chk   *ieic = new ICMP_Echo_Id_Chk;
    ICMP_Echo_Tos_Chk  *ietc = new ICMP_Echo_Tos_Chk;
    ICMP_Echo_Df_Bit_Chk *iedbc = new ICMP_Echo_Df_Bit_Chk;
    ICMP_Echo_Reply_Ttl_Chk *iertc = new ICMP_Echo_Reply_Ttl_Chk;
    ICMP_Echo_Reply_Check *ierc= new ICMP_Echo_Reply_Check;

    kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_echo_reply", ierc));
    kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_echo_code", iecc));
    kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_echo_ip_id", ieic));
    kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_echo_tos_bits", ietc));
    kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_echo_df_bit", iedbc));
    kwd_chk.insert(pair<string, Xprobe_Module_Param_ICMP *>("icmp_echo_reply_ttl", iertc));
    
    return;
}

ICMP_Echo_Id_Mod::~ICMP_Echo_Id_Mod(void) {
    map <string, Xprobe_Module_Param_ICMP *>::iterator s_i;

/* free check objects */
    for (s_i = kwd_chk.begin(); s_i != kwd_chk.end(); s_i++) 
        delete (*s_i).second;
    
}

int ICMP_Echo_Id_Mod::init(void) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
    return OK;
}


int ICMP_Echo_Id_Mod::exec(Target *tg, OS_Matrix *os) {
    int ret;
    
    xprobe_debug(XPROBE_DEBUG_MODULES, "--%s module has been executed against: %s\n", get_name(),
            inet_ntoa(tg->get_addr()));

    current_os = os;
    ret = do_icmp_ping(tg);
    
    if (!ret) return FAIL;
    return OK;
}

int ICMP_Echo_Id_Mod::fini(void) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
    return OK;
}

void ICMP_Echo_Id_Mod::sig_insert(int os_id, int val) {

    if (sig.find(os_id) != sig.end()) {
        ui->msg("OS %i - duplicate signature\n", os_id);
        return;
    }
    sig.insert(pair <int, int>(os_id, val));

}

void ICMP_Echo_Id_Mod::sig_ttl_insert(int os_id, int val) {

    if (sig_ttl.find(os_id) != sig_ttl.end()) {
        ui->msg("OS %i - dublicate signature\n", os_id);
        return;
    }

    sig_ttl.insert(pair <int, int>(os_id, val));

}




int ICMP_Echo_Id_Mod::parse_keyword(int os_id, const char *kwd, const char *val)  {
	map <string, Xprobe_Module_Param_ICMP *>::iterator s_i;

    xprobe_debug(XPROBE_DEBUG_SIGNATURES, "Parsing for %i : %s  = %s\n",
                                                        os_id,  kwd, val);
	if ((s_i=kwd_chk.find(kwd)) != kwd_chk.end()) {
            return((*s_i).second->parse_param(os_id, val));
	}
    ui->msg("Ooops..none matched %s %s\n", kwd, val);   
    return FAIL;

};

int ICMP_Echo_Id_Mod::do_icmp_ping(Target *tg) {

    char buf[1024];
    struct timeval tv;
    int ret;
    int done;
    unsigned short int icmpp_id;
    struct in_addr local, remote;
    map <string, Xprobe_Module_Param_ICMP *>::iterator s_i;

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
	// set ip id now, instead of letting os do that
	// since we need get_id() to return sent ip id
	icmpp.set_id(rand());
	icmpp.set_seq(256);
    icmpp.set_icmpId(icmpp_id);
    icmpp.set_type(ICMP_ECHO);
    icmpp.set_code(123); /* our test with non-0 icmp code */
    icmpp.set_tos(6);
    icmpp.set_fragoff(IP_DF);
    fflush(stderr);
    ret = -1;
    
    icmpp.timeout(tv);
    sn.timeout(tv);
	ret = icmpp.send_ping_payload();
    done = 0;
    while (!done) {
        ret = sn.sniffpack(buf, sizeof(buf));
        /* packet response */
//        if (ret > 0 && sn.get_src() != local.s_addr 
        if (!sn.timeout() && sn.get_src() == remote.s_addr && 
			sn.get_type() == ICMP_ECHOREPLY && sn.get_icmpId() == icmpp_id) {
			done = 1;
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Received reply.\n", get_name());
		}
//        if (ret < 1) done = 1; /* timeout */    
        if (sn.timeout()) {
			done = 1; /* timeout */    
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Timed out, no reply received.\n", get_name());
		}
    }
    
    if (! sn.timeout()) {
        for (s_i = kwd_chk.begin(); s_i != kwd_chk.end(); s_i++) 
            ((*s_i).second->check_param(&sn, &icmpp, current_os));
        
		if (tg->generate_sig())
			generate_signature(tg, &sn, &icmpp);
        return OK;
    }
    return FAIL;

}

void ICMP_Echo_Id_Mod::generate_signature(Target *tg, ICMP *pack, ICMP *orig) {
	string keyword, value;
	unsigned int ttl;
/*
#       icmp_echo_code = [0, !0]
#       icmp_echo_ip_id = [0, !0, SENT]
#       icmp_echo_tos_bits = [0, !0]
#       icmp_echo_df_bit = [0, 1]
#       icmp_echo_reply_ttl = [>< decimal num]
*/
	if (!pack->timeout()) {
		tg->signature("icmp_echo_reply", "y");
		keyword = "icmp_echo_code";
		if (pack->get_code() == 0)
			value="0";
		else 
			value="!0";
		tg->signature(keyword, value);
		keyword= "icmp_echo_ip_id";
		if (pack->get_id() == 0)
			value = "0";
		else if (pack->get_id() == orig->get_id())
			value = "SENT";
		else
			value = "!0";
		tg->signature(keyword, value);
		keyword= "icmp_echo_tos_bits";
		if (pack->get_tos() == 0)
			value="0";
		else 
			value="!0";
		tg->signature(keyword, value);
		keyword = "icmp_echo_df_bit";
		if (pack->get_fragoff() & IP_DF)
			value = "1";
		else 
			value ="0";	
		tg->signature(keyword, value);
		keyword = "icmp_echo_reply_ttl";
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
	} else {
		tg->signature("# No ICMP Echo reply received", "");
		tg->signature("icmp_echo_reply", "n");
		tg->signature("icmp_echo_code", "");
		tg->signature("icmp_echo_ip_id", "");
		tg->signature("icmp_echo_tos_bits","");
		tg->signature("icmp_echo_df_bit", "");
		tg->signature("icmp_echo_reply_ttl", "");
	}
	

}


int ICMP_Echo_Code_Chk::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

   xprobe_debug(XPROBE_DEBUG_MODULES, "ICMP ECHO code %i\n", ip_pkt->get_code());
   return (add_param(ip_pkt->get_code(),orig_pkt->get_code(), os));
}

int ICMP_Echo_Id_Chk::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

   xprobe_debug(XPROBE_DEBUG_MODULES, "ICMP ip id %i\n", ip_pkt->get_id());
   return (add_param(ip_pkt->get_id(), orig_pkt->get_id(), os));
}

int ICMP_Echo_Tos_Chk::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

   xprobe_debug(XPROBE_DEBUG_MODULES, "ICMP ip tos 0x%x\n", ip_pkt->get_tos());
   return (add_param(ip_pkt->get_tos(), orig_pkt->get_tos(), os));
}


int ICMP_Echo_Df_Bit_Chk::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

   xprobe_debug(XPROBE_DEBUG_MODULES, "ICMP ip df %i\n",
                        (ip_pkt->get_fragoff() & IP_DF) !=0?1:0);
   return (add_param(((ip_pkt->get_fragoff() & IP_DF) != 0), ((orig_pkt->get_fragoff() & IP_DF) != 0), os));
}

int ICMP_Echo_Reply_Ttl_Chk::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {

   xprobe_debug(XPROBE_DEBUG_MODULES, "ICMP ip ttl %i",  ip_pkt->get_ttl());
   return (add_param(ip_pkt->get_ttl(), orig_pkt->get_ttl(), os));
}

int ICMP_Echo_Reply_Check::check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) {
	int gotp=ip_pkt->timeout() ? 0 : 1;
	// suspend warning
	orig_pkt->timeout();
	add_param(gotp, 0, os);
	if (!gotp) {
		gen_match(5, os);
	}
	return OK;
}
