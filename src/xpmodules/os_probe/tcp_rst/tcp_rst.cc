/*
 * **
 * ** Copyright (C) 2001-2005  Fyodor Yarochkin <fygrave@tigerteam.net>,
 * **						Ofir Arkin       <ofir@sys-security.com>
 * **						Meder Kydyraliev <meder@o0o.nu>
 * **
 * ** This program is free software; you can redistribute it and/or modify
 * ** it under the terms of the GNU General Public License as published by
 * ** the Free Software Foundation; either version 2 of the License, or
 * ** (at your option) any later version.
 * **
 * **
 * ** This program is distributed in the hope that it will be useful,
 * ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 * ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * ** GNU General Public License for more details.
 * **
 * ** You should have received a copy of the GNU General Public License
 * ** along with this program; if not, write to the Free Software
 * ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * */

#include "xprobe.h"
#define _XPROBE_MODULE
#include "xplib.h"
#include "xprobe_module.h"
#include "xprobe_module_hdlr.h"
#include "target.h"
#include "interface.h"
#include "cmd_opts.h"
#include "tcp_rst.h"

extern Interface *ui;
extern Cmd_Opts *copts;

int tcp_rst_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {
	TCP_Rst_Mod *rst = new TCP_Rst_Mod;
	rst->set_name(nm);
	xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the TCP RST module\n");
	pt->register_module(rst);
	pt->add_keyword(rst->get_id(), "tcp_rst_df");
	pt->add_keyword(rst->get_id(), "tcp_rst_ip_id_1");
	pt->add_keyword(rst->get_id(), "tcp_rst_ip_id_2");
	pt->add_keyword(rst->get_id(), "tcp_rst_ip_id_strategy");
	pt->add_keyword(rst->get_id(), "tcp_rst_ttl");
	pt->add_keyword(rst->get_id(), "tcp_rst_reply");
	return OK;
}

TCP_Rst_Mod::TCP_Rst_Mod(void): Xprobe_Module(XPROBE_MODULE_OSTEST, "fingerprint:tcp_rst", "TCP RST fingerprinting module") {
	TCP_Rst_Df_Bit_Check *df_check = new TCP_Rst_Df_Bit_Check;
	TCP_Rst_Ip_Id_Check *id_check_one = new TCP_Rst_Ip_Id_Check;
	TCP_Rst_Ip_Id_Check *id_check_two = new TCP_Rst_Ip_Id_Check;
	TCP_Rst_Ttl_Check	*ttl_check = new TCP_Rst_Ttl_Check;
	TCP_Rst_Ip_Id_Strategy *strat_check = new TCP_Rst_Ip_Id_Strategy;
	TCP_Rst_Reply_Check *reply_check = new TCP_Rst_Reply_Check;

	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_rst_df", df_check));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_rst_ip_id_1", id_check_one));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_rst_ip_id_2", id_check_two));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_rst_ip_id_strategy", strat_check));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_rst_ttl", ttl_check));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_rst_reply", reply_check));
}

TCP_Rst_Mod::~TCP_Rst_Mod(void) {
	map<string, Xprobe_Module_Param_TCP *>::iterator m_i;

	for (m_i = kwd_chk.begin(); m_i != kwd_chk.end(); m_i++) {
		delete m_i->second;
	}
}


int TCP_Rst_Mod::parse_keyword(int os_id, const char *kwd, const char *val) {
	map<string, Xprobe_Module_Param_TCP *>::iterator m_i;
	
	if ((m_i = kwd_chk.find(kwd)) == kwd_chk.end()) {
		ui->error("%s: unknown keyword %s", get_name(), kwd);
		return FAIL;
	}
	return m_i->second->parse_param(os_id, val);
}

int TCP_Rst_Mod::init(void) {
	xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
	return OK;
}

int TCP_Rst_Mod::exec(Target *tg, OS_Matrix *os) {
	int done=0, ret;
	bool second_packet = false;
	char buf[1024];
	struct in_addr local = tg->get_interface_addr(), remote = tg->get_addr();
	struct timeval tv;
	map<string, Xprobe_Module_Param_TCP *>::iterator m_i;
	
	TCP request(inet_ntoa(remote));
	TCP sn(inet_ntoa(local)), sample1(inet_ntoa(local));

	if (tg->get_port(IPPROTO_TCP, XPROBE_TARGETP_CLOSED) == -1) {
		// ui->msg("[-] %s Module execution aborted (no closed TCP port known)\n", get_name());
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Sending probe to port 65535\n", get_name());
		//return FAIL;
	}
	srand(time(NULL));
	request.set_src(local.s_addr);
	request.set_dst(remote.s_addr);
	request.set_srcport(rand());
	request.set_dstport(tg->get_port(IPPROTO_TCP, XPROBE_TARGETP_CLOSED));
	request.set_ttl(64);
	request.set_win(6840);
	request.set_flags(TH_SYN);
	request.set_tos(0x10);
	request.set_fragoff(IP_DF);
	request.set_seq(rand());
	request.set_ack(0);
	request.set_id(rand());

	tv = tg->get_rtt();
	sn.init_device(tg->get_interface(), 0, 1500);
	sn.timeout(tv);

	request.sendpack("");
	while (!done) {
		ret = sn.sniffpack(buf, sizeof(buf));	
		if (!sn.timeout()) {
			if (sn.get_src() == remote.s_addr && request.get_dstport() == sn.get_srcport() &&
					request.get_srcport() == sn.get_dstport()) {
						done = 1;
			}
		} else {
			done = 1; //timeout
		}
		if (done && !sn.timeout() && (sn.get_flags() & TH_RST) == TH_RST) {
			if (!second_packet) {
				xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Got first RST packet. Sending second\n", get_name());
				sample1 = sn;
				request.set_srcport(rand());
				request.set_id(rand());
				request.set_seq(rand());
				request.set_tcpsum(0);
				done = 0;	
				sn.timeout(tv);
				request.sendpack("");
				second_packet=true;
			} else {
				xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Got second RST packet.\n", get_name());
				done = 1;
			}
		}
	} // while (!done)
	if (sn.timeout())
		return FAIL;

	// we got two packets
	for (m_i = kwd_chk.begin(); m_i != kwd_chk.end(); m_i++) {
		if (m_i->first == "tcp_rst_ip_id_strategy") {
			m_i->second->check_param(&sn, &sample1, os);
		} else {
			m_i->second->check_param(&sn, &request, os);
		}
	}
	if (tg->generate_sig())
		generate_signature(tg, &sample1, &request, &sn);
	return OK;
}

void TCP_Rst_Mod::generate_signature(Target *tg, TCP *pack, TCP *orig, TCP *second) {
	string keyword, value;
	unsigned int ttl;
	long id_diff;
	/*
	 * tcp_rst_reply = [y,n]
	 * tcp_rst_df=[0,1]
	 * tcp_rst_ip_id_1=[0, !0, SENT]
	 * tcp_rst_ip_id_2=[0, !0, SENT]
	 * tcp_rst_ip_id_strategy=[R, I, 0]
	 * tcp_rst_ttl = [<> decimal num]
	*/

	if (pack->timeout() || second->timeout()) {
		tg->signature("tcp_rst_reply", "n");
		tg->signature("tcp_rst_df", "0");
		tg->signature("tcp_rst_ip_id_1", "!0");
		tg->signature("tcp_rst_ip_id_2", "!0");
		tg->signature("tcp_rst_ip_id_strategy", "I");
		tg->signature("tcp_rst_ttl", "<255");
		return;
	}
	tg->signature("tcp_rst_reply", "y");
	keyword = "tcp_rst_df";
	if (pack->get_fragoff() & IP_DF) {
		value="1";
	} else {
		value="0";
	}
	tg->signature(keyword.c_str(), value.c_str());
	keyword= "tcp_rst_ip_id_1";	
	if (pack->get_id() == 0) {
		value="0";
	} else if (pack->get_id() == orig->get_id()) {
		value = "SENT";
	} else {
		value = "!0";
	}
	tg->signature(keyword.c_str(), value.c_str());
	keyword= "tcp_rst_ip_id_2";	
	tg->signature(keyword.c_str(), value.c_str());
	keyword="tcp_rst_ttl";
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
	tg->signature(keyword.c_str(), value.c_str());
	keyword="tcp_rst_ip_id_strategy";
	id_diff = second->get_id() - pack->get_id();
	if (id_diff > 256 || id_diff < 0) {
		value ="R";
	} else if (id_diff > 0 && id_diff <= 256) {
		value = "I";
	} else if (id_diff == 0) {
		value = "0";
	}
	tg->signature(keyword.c_str(), value.c_str());
	
}

int TCP_Rst_Mod::fini(void) {
	xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
	return OK;
}

int TCP_Rst_Df_Bit_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval = OK;
	o=o; //suspend compiler warning
	if (!p->timeout())
		retval = add_param(((p->get_fragoff() & IP_DF) != 0), 0,  os);
	return retval;
}

int TCP_Rst_Ip_Id_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval = OK;
	if (!p->timeout())
		retval = add_param(p->get_id(), o->get_id(), os);
	return retval;
}

int TCP_Rst_Ttl_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval=OK;
	if (!p->timeout())
		retval = add_param(p->get_ttl(), o->get_ttl(), os);
	return retval;
}

int TCP_Rst_Ip_Id_Strategy::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval = OK;
	if (!p->timeout())
		retval = add_param(p->get_id(), o->get_id(), os);
	return retval;
}

int TCP_Rst_Reply_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int gotp=p->timeout() ? 0 : 1;
	// suspend warning
	o->timeout();
	add_param(gotp, 0, os);
	if (!gotp) {
		gen_match(5, os);
	}
return OK;
}
