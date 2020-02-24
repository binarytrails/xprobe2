/*
**
** Copyright (C) 2001, 2002, 2003 Meder Kydyraliev
**
** Copyright (C) 2001, 2002, 2003  Fyodor Yarochkin <fygrave@tigerteam.net>,
**                                  Ofir Arkin       <ofir@sys-security.com>
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
#include "cmd_opts.h"
#include "tcp_handshake.h"

extern Interface *ui;
extern Cmd_Opts *copts;


TCP_Handshake_Mod::TCP_Handshake_Mod(void): Xprobe_Module(XPROBE_MODULE_OSTEST, 
		"fingerprint:tcp_hshake","TCP Handshake fingerprinting module") { 

	TCP_Handshake_Ttl_Check *ttlc = new TCP_Handshake_Ttl_Check;
	TCP_Handshake_Ip_Id_Check *ipidc = new TCP_Handshake_Ip_Id_Check;
	TCP_Handshake_Tos_Check *tosc = new TCP_Handshake_Tos_Check;
	TCP_Handshake_Df_Bit_Check *dfbc = new TCP_Handshake_Df_Bit_Check;
	TCP_Handhake_Ack_Check *ackc = new TCP_Handhake_Ack_Check;
	TCP_Handshake_Window_Check *winc = new TCP_Handshake_Window_Check;

	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_syn_ack_ttl", ttlc));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_syn_ack_ip_id", ipidc));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_syn_ack_tos", tosc));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_syn_ack_df", dfbc));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_syn_ack_ack", ackc));
	kwd_chk.insert(pair<string, Xprobe_Module_Param_TCP *>("tcp_syn_ack_window_size", winc));
	memset(opt_order, 0, sizeof(opt_order));
	wscale = -1;
	got_timestamp = false;
	tse_first = tsv_first = tse_second = tsv_second = used_port = 0;

}

TCP_Handshake_Mod::~TCP_Handshake_Mod(void) {
	map <string, Xprobe_Module_Param_TCP *>::iterator m_i;

	for (m_i = kwd_chk.begin(); m_i != kwd_chk.end(); m_i++)
		delete m_i->second;
}

int TCP_Handshake_Mod::init(void) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
    return OK;
}


int TCP_Handshake_Mod::exec(Target *tg, OS_Matrix *os) {

//	if (run_probe(tg, os) != FAIL) {
		return run_probe(tg, os);
//	}	
//	return FAIL;
}

int TCP_Handshake_Mod::run_probe(Target *tg, OS_Matrix *os) {
	map<string, Xprobe_Module_Param_TCP *>::iterator m_i;
	TCP *request = new TCP(inet_ntoa(tg->get_addr()));
	char buf[1024];
	int done=0, ret, have_more_ports=1;
	bool no_open_port;
	unsigned int ix=0;
	unsigned short tcp_brute_ports[] = {80, 443, 23, 21, 25, 22, 445, 139, 6000};
	Xprobe::Timeval tv;
	struct in_addr local=tg->get_interface_addr(), remote=tg->get_addr();
	TCP sn(inet_ntoa(local));

	tv = (double)tg->get_rtt()*50;
	tv.tv_sec = 2;

	if (used_port != 0 && (tse_first == 0 || tsv_first == 0)) {
		// timestamp option was not received in previous request
		xprobe_debug(XPROBE_DEBUG_MODULES, "--%s No timestamp recevied in previous TCP reply\n", get_name());
		return OK;
	}
	if (used_port != 0)
		usleep(10000);
	/*
	 * logic is as follows: 
	 * - if user supplied the port with -p switch we'll go ahead and do a run
	 *   using the port specified(or if got ports from portscan);
	 * - if user didnot supply the port w/ -p, but supplied -B (tcp bruteforce),
	 *   we will loop throught the tcp_brute_ports[] array sending one packet
	 *   at a time to each port in array
	 * - if neither -B nor -p (for tcp) were specified, the module will not be run
	 * - if both options are specified, the port supplied w/ -p will be use and no
	 *   TCP brute forcing will be done
	 */
	no_open_port = (tg->get_port(IPPROTO_TCP, XPROBE_TARGETP_OPEN) == -1);
	if (!copts->tcp_port_brute() && no_open_port) {
		ui->msg("[-] %s Module execution aborted (no open TCP ports known)\n", get_name());
		return FAIL;
	}

	sn.init_device(tg->get_interface(), 0, 1500);
	sn.timeout(tv);
    xprobe_debug(XPROBE_DEBUG_MODULES, "--%s module has been executed against: %s\n", get_name(),
            inet_ntoa(tg->get_addr()));
	if (get_tcpopts_pack(tg, request)) {
		ui->msg("[%s] send_tcpopts() failed\n", get_name());
		return FAIL;
	}
	srand(time(NULL));
	while (have_more_ports) {
		request->set_tcpsum(0);
		if (no_open_port) { // we bruteforce 
			if (ix < sizeof(tcp_brute_ports)/sizeof(unsigned short)) {
				request->set_dstport(tcp_brute_ports[ix++]);
				request->set_srcport(rand());
			} else { // bruteforcing finished
				break;
			}
		} else { // no bruteforcing, we have tcp port supplied by user or from portscan
			have_more_ports = false;
		}
		request->sendpack("");
		while(!done) {
			memset(buf, 0, sizeof(buf));
			ret = sn.sniffpack(buf, sizeof(buf));
			if (!sn.timeout()) {
				if (sn.get_src() == remote.s_addr &&
					request->get_dstport() == sn.get_srcport() &&
					request->get_srcport() == sn.get_dstport()) {
					done = 1;
					xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Got reply.\n", get_name());
				}
			} else
				done = 1; // timeout
		} /* sniffpack loop */
		done = 0;
		if (!sn.timeout() && sn.get_flags() == (TH_SYN|TH_ACK)){
				/*
				 * add port to the list of the open ports on target
				 */
				tg->add_port(IPPROTO_TCP, request->get_dstport(), XPROBE_TARGETP_OPEN);
				have_more_ports=false; // we got reply, no further packets required
				xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Got SYN ACK packet.\n", get_name());
				//memset(tcp_options, 0, sizeof(tcp_options));
				//len = sn.get_tcpopt(tcp_options)-20;
				//parse_options(tcp_options, len);
				memset(opt_order, 0, sizeof(opt_order));
				sn.get_parsed_tcpopt(opt_order, sizeof(opt_order)-1);
				xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] GOT OPTIONS: %s\n", get_name(), opt_order);
				if (strchr(opt_order, 'T')) {
					got_timestamp=true;
					timestamps[0] = sn.get_tcpopt_tsv();
					timestamps[1] = sn.get_tcpopt_tse();
				}
				if (strchr(opt_order, 'W')) {
					wscale = sn.get_wscale();
				}
				if (used_port != 0) { //second execution
					xprobe_debug(XPROBE_DEBUG_MODULES, "TSV difference: %u\n", timestamps[0] - tsv_first);
					xprobe_debug(XPROBE_DEBUG_MODULES, "TSE difference: %u\n", timestamps[1] - tse_first);
				} else {
					used_port = request->get_dstport();
					for (m_i = kwd_chk.begin(); m_i != kwd_chk.end(); m_i++)
						m_i->second->check_param(&sn, request, os);
					for (w_i = wscale_map.begin(); w_i != wscale_map.end(); w_i++)
						if (w_i->second == wscale) {
							os->add_result(get_id(), w_i->first, XPROBE_MATCH_YES);
						} else {
							os->add_result(get_id(), w_i->first, XPROBE_MATCH_NO);
						}
					for (o_i = options_map.begin(); o_i != options_map.end(); o_i++)
						if (o_i->second == opt_order) {
							os->add_result(get_id(), o_i->first, XPROBE_MATCH_YES);
						} else {
							os->add_result(get_id(), o_i->first, XPROBE_MATCH_NO);
						}
					if (got_timestamp) {
						if (timestamps[0] == 0)
							tsv_first = 0;
						else
							tsv_first = 1;

						if (timestamps[1] == 0)
							tse_first = 0;
						else 
							tse_first = 1;
						for (ts_i = tsval.begin(); ts_i != tsval.end(); ts_i++)
							if (ts_i->second == tsv_first)
								os->add_result(get_id(), ts_i->first, XPROBE_MATCH_YES);
							else
								os->add_result(get_id(), ts_i->first, XPROBE_MATCH_NO);
						for (ts_i = tsecr.begin(); ts_i != tsecr.end(); ts_i++)
							if (ts_i->second == tse_first)
								os->add_result(get_id(), ts_i->first, XPROBE_MATCH_YES);
							else
								os->add_result(get_id(), ts_i->first, XPROBE_MATCH_NO);
						tsv_first = timestamps[0];
						tse_first = timestamps[1];
					} else {
						for (ts_i = tsval.begin(); ts_i != tsval.end(); ts_i++)  
							if (ts_i->second == 2) /* NONE */
								os->add_result(get_id(), ts_i->first, XPROBE_MATCH_YES);
							else
								os->add_result(get_id(), ts_i->first, XPROBE_MATCH_NO);
						for (ts_i = tsecr.begin(); ts_i != tsecr.end(); ts_i++)
							if (ts_i->second == 2) /* NONE */
								os->add_result(get_id(), ts_i->first, XPROBE_MATCH_YES);
							else 
								os->add_result(get_id(), ts_i->first, XPROBE_MATCH_NO);
					}
					if (tg->generate_sig())
						generate_signature(tg, &sn, request);
				}
		} else {
			if (!sn.timeout() && sn.get_flags() == (TH_ACK|TH_RST)) {
				/*
				 * add port to the list of the open ports on target
				 */
				tg->add_port(IPPROTO_TCP, request->get_dstport(), XPROBE_TARGETP_CLOSED);
			}
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Did not receive SYN ACK packet. %d\n", get_name(), sn.get_dstport());
		}
	}
	return OK;
}

int TCP_Handshake_Mod::parse_options(char *tcp_options, int len) {
	int lenparsed, optlen= 0;
	unsigned int k=0;

	xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Length of options: %d. Options are:\n",get_name(), len);
	// Parse TCP options, like OpenBSD does in /sys/netinet/tcp_input.c
	memset(opt_order, 0, sizeof(opt_order));
	for (lenparsed = 0; lenparsed < len; lenparsed += optlen) {
		if (tcp_options[lenparsed] == TCPOPT_NOP) {
			optlen=1;
			xprobe_mdebug(XPROBE_DEBUG_MODULES, "NOP\n");
			if (k < sizeof(opt_order))
				opt_order[k++]='N';
			continue;
		} else if (tcp_options[lenparsed] == TCPOPT_EOL) {
			xprobe_mdebug(XPROBE_DEBUG_MODULES, "EOL\n");
			if (len - lenparsed > 1)
				// something fucked up, we have end of list
				// but we are not done yet
				xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Got TCPOPT_EOL not at the end of options", get_name());
				break;
		} else  {
			// avoid evil packets that only have
			// option w/o lenght
			if (lenparsed + 1 < len)
				optlen = tcp_options[lenparsed+1];
			else
				// something is really fucked
				// we have option but do not have
				// its length
				return FAIL;
		}
		// alrighty, check for a fucked up packs
		// make sure that len reported in the pack
		// fits into our buffer
		if (optlen > len - lenparsed) {
			ui->msg("Option length reported in packet is greater than total options length\n");
			return FAIL;
		}

		// at this point have optlen bytes in tcp_options;
		// if optlen for some particular option is fucked up
		// we assign it correct value and try to parse further,
		// however neither data is parsed, nor we add option to
		// opt_order
		switch(tcp_options[lenparsed]) {
			case TCPOPT_WINDOW:	
				xprobe_mdebug(XPROBE_DEBUG_MODULES, "WSCALE ");
				if (optlen != TCPOLEN_WINDOW) {
					xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Bad TCPOPT_WINDOW len %d", get_name(), optlen);
					optlen = TCPOLEN_WINDOW;
					continue;
				} else {
					wscale = tcp_options[lenparsed+2];
					xprobe_debug(XPROBE_DEBUG_MODULES, "%d \n", wscale);
					if (k < sizeof(opt_order))
						opt_order[k++]='W';
				}
				break;
			case TCPOPT_TIMESTAMP:
				xprobe_mdebug(XPROBE_DEBUG_MODULES, "TIMESTAMP\n");
				if (optlen != TCPOLEN_TIMESTAMP) {
					xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Bad TCPOPT_TIMESTAMP len %d", get_name(), optlen);
					optlen = TCPOLEN_TIMESTAMP;
					continue;
				} 
				// we are guaranteed to have 8 bytes of option data at tcp_options+lenparsed
				memcpy(&timestamps[0], tcp_options+lenparsed+2, 4);
				memcpy(&timestamps[1], tcp_options+lenparsed+6, 4);
				timestamps[0] = ntohl(timestamps[0]);
				timestamps[1] = ntohl(timestamps[1]);

				xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Timestamps: %d %d\n", get_name(), timestamps[0],timestamps[1]);
				if (k < sizeof(opt_order))
					opt_order[k++]='T';
				got_timestamp = true;
				break;
			case TCPOPT_MAXSEG:
				xprobe_mdebug(XPROBE_DEBUG_MODULES, "MSS\n");
				if (optlen != TCPOLEN_MAXSEG) {
					xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Bad TCPOPT_MAXSEG len %d", get_name(), optlen);
					optlen = TCPOLEN_MAXSEG;
					continue;
				}
				if (k < sizeof(opt_order))
					opt_order[k++] = 'M';
				break;
			case TCPOPT_SACK_PERMITTED:
				xprobe_mdebug(XPROBE_DEBUG_MODULES, "SACK\n");
				if (optlen != TCPOLEN_SACK_PERMITTED) {
					xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Bad TCPOPT_SACK_PERMITTED len %d", get_name(), optlen);
					optlen = TCPOLEN_SACK_PERMITTED;
					continue;
				}
				if (k < sizeof(opt_order))
					opt_order[k++] = 'S';
				break;
			default:
				ui->msg("[%s] Remote hosts proposed TCP option in SYNACK packet please report\n");
		}

	}
	
    return OK;
}

int TCP_Handshake_Mod::fini(void) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
    return OK;
}

int TCP_Handshake_Mod::parse_keyword(int os_id, const char *kwd, const char *val)  {
	unsigned int vl=0;
	map<string, Xprobe_Module_Param_TCP *>::iterator m_i;
	
	xprobe_debug(XPROBE_DEBUG_SIGNATURES, "Parsing for %i : %s  = %s\n", os_id,  kwd, val);
    
	if ((m_i=kwd_chk.find(kwd)) != kwd_chk.end()) {
		return (m_i->second->parse_param(os_id, val));
	}
	/* parse "tcp_syn_ack_options_order" keyword
	 * following values are accepted:
	 * NOP MSS WSCALE SACK TIMESTAMP
	 */
	if (!strncasecmp(kwd, "tcp_syn_ack_options_order", strlen("tcp_syn_ack_options_order"))) {
		string options(val), fin_opt;
		string::size_type begin, end;
		unsigned int k=0;

		memset(opt_order, 0, sizeof(opt_order));
		//for the loop to work and parse last param
		// last char should be  `"' anyway
		options[options.size()-1] = ' '; 
		begin = options.find_first_not_of('"');
		end = options.find_first_of(' ');
		while (begin != string::npos && end != string::npos) {
			if (k < sizeof(opt_order))
				opt_order[k++] = options.substr(begin, end)[0];	
			else 
				ui->msg("[%s] Too many options specified\n", get_name());
			begin=options.find_first_not_of(' ', end);
			end = options.find_first_of(' ', begin);
		}
		// sanity check to make sure no UNKNOWN 
		// options were specified in the fingerprint
		while (k-- > 0) {
			if (opt_order[k] != 'N' && opt_order[k] != 'M' &&
				opt_order[k] != 'W' && opt_order[k] != 'S' &&
				opt_order[k] != 'T') {
				ui->msg("[%s] Unknown TCP option %c in fingerprint (%s=%s)\n", 
							get_name(), opt_order[k], kwd, val);
				return FAIL;
			}
		}
		fin_opt = opt_order;
		options_map.insert(pair<int, string>(os_id, fin_opt));

	} else  if (!strncasecmp(kwd, "tcp_syn_ack_wscale", strlen("tcp_syn_ack_wscale"))) {
		if (val[0] == 'N' || val[0] == 'n'){
			wscale_map.insert(pair<int, int>(os_id, -1));
		} else if (val[0] >= '0' && val[0] <= '9') {
			errno = 0;
			int j = strtol(val, NULL, 0);
			if (errno == ERANGE) {
				ui->msg("tcp_handshake::parse_keyword() bad value for keyword(%s=%s)", kwd, val);
				return FAIL;
			}	
			wscale_map.insert(pair<int, int>(os_id, j));
		} else
			ui->msg("[%s] Unknown value (%s=%s)\n", kwd, val);
	} else if (!strncasecmp(kwd, "tcp_syn_ack_tsval", strlen("tcp_syn_ack_tsval"))) {
		if (val[0] == 'N' || val[0] == 'n')
			vl = 2;
		else if (val[0] == '!')
			vl = 1;
		else if (val[0] == '0')
			vl = 0;
		tsval.insert(pair<int, unsigned int>(os_id, vl));
	} else if (!strncasecmp(kwd, "tcp_syn_ack_tsecr", strlen("tcp_syn_ack_tsecr"))) {
		if (val[0] == 'N' || val[0] == 'n')
			vl = 2;
		else if (val[0] == '!')
			vl = 1;
		else if (val[0] == '0')
			vl = 0;
		tsecr.insert(pair<int, unsigned int>(os_id, vl));
	} else
		ui->msg("[%s] Unknown keyword %s\n", get_name());
    return OK;
};

int TCP_Handshake_Mod::get_tcpopts_pack(Target *tg, TCP *tcp) {
	union tcp_options to;
	struct timeval tv;

	if ((gettimeofday(&tv, NULL)) < 0) {
		ui->msg("[%s] gettimeofday failed: %s\n", get_name(), strerror(errno));
		return FAIL;
	}
	srand(time(NULL));
	tcp->set_src(inet_ntoa(tg->get_interface_addr()));
	//CHANGE PORT
	tcp->set_srcport(rand());
	tcp->set_dstport(tg->get_port(IPPROTO_TCP, XPROBE_TARGETP_OPEN));
	tcp->set_ttl(64);
	tcp->set_win(5840);
	tcp->set_flags(TH_SYN);
	tcp->set_tos(0x10);
	tcp->set_fragoff(IP_DF);
	tcp->set_seq(rand());
	tcp->set_ack(0);
	to.one_word = 1460;
	tcp->set_tcpopt(TCPOPT_MAXSEG, TCPOLEN_MAXSEG, to);
	memset(&to, 0, sizeof(to.unknown));
	tcp->set_tcpopt(TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED, to);
	to.two_dwords[0] = tv.tv_usec; //usi++ will do htonl()
	tcp->set_tcpopt(TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, to);
	memset(&to, 0, sizeof(to.unknown));
	tcp->set_tcpopt(TCPOPT_NOP, 1, to);
	to.one_byte = 0;
	tcp->set_tcpopt(TCPOPT_WINDOW, TCPOLEN_WINDOW, to);
	return OK;
}

void TCP_Handshake_Mod::generate_signature(Target *tg, TCP *pack, TCP *orig) {
	string keyword, value;
	unsigned int ttl;
	char buf[100];
/*
#       #IP header of the TCP SYN ACK
#       tcp_syn_ack_tos = [0, <value>]
#       tcp_syn_ack_df = [0 , 1 ]
#       tcp_syn_ack_ip_id = [0 , !0, SENT ]
#       tcp_syn_ack_ttl = [>< decimal num]
#
#       #Information from the TCP header
#       tcp_syn_ack_ack = [<value>]
#       tcp_syn_ack_window_size = [<value>]
#       tcp_syn_ack_options_order = ["order"]
#       tcp_syn_ack_wscale = [<value>, NONE]
		tcp_syn_ack_tsval = [0, !0, NONE]
		tcp_syn_ack_tsecr = [0, !0, NONE]
*/
	if (!pack->timeout()) {
		keyword="tcp_syn_ack_tos";
		memset(buf, 0, sizeof(buf));
		if (pack->get_tos() == 0)
			value="0";
		else {
			snprintf(buf, sizeof(buf), "0x%x", pack->get_tos());
			value = buf;
		}
		tg->signature(keyword, value);
		/* following checkpoing values for TCP ttl:
		 * 32, 60, 64, 128, 255
		 */
		keyword="tcp_syn_ack_ttl";
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
		keyword="tcp_syn_ack_df";
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "%d", pack->get_fragoff() & IP_DF ? 1 : 0);
		tg->signature(keyword.c_str(), buf);
		keyword = "tcp_syn_ack_ip_id";
		if (pack->get_id() == 0)
			value = "0";
		else if (pack->get_id() == orig->get_id())
			value = "SENT";
		else
			value = "!0";
		tg->signature(keyword, value);
		keyword = "tcp_syn_ack_ack";	
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "%d", pack->get_ack() - orig->get_seq());
		tg->signature(keyword.c_str(), buf);	
		keyword = "tcp_syn_ack_window_size";
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "%d", pack->get_win());
		tg->signature(keyword.c_str(), buf);
		keyword="tcp_syn_ack_options_order";
		value="";
		for (ttl=0; ttl < sizeof(opt_order); ttl++) {
			switch(opt_order[ttl]) {
				case 'N':
					value.append("NOP ");
					break;
				case 'M':
					value.append("MSS ");
					break;
				case 'W':
					value.append("WSCALE ");
					break;
				case 'S':
					value.append("SACK ");
					break;
				case 'T':
					value.append("TIMESTAMP ");
					break;
			}
		}
		tg->signature(keyword, value);
		keyword="tcp_syn_ack_wscale";
		if (wscale == -1)
			value = "NONE";
		else {
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), "%d", wscale);
			value = buf;
		}
		tg->signature(keyword, value);
		if (got_timestamp) {
			keyword = "tcp_syn_ack_tsval";
			if (timestamps[0] == 0)
				value = "0";
			else
				value = "!0";
			tg->signature(keyword, value);	
			keyword= "tcp_syn_ack_tsecr";
			if (timestamps[1] == 0)
				value = "0";
			else
				value = "!0";
			tg->signature(keyword, value);
		} else {
			tg->signature("tcp_syn_ack_tsval", "NONE");
			tg->signature("tcp_syn_ack_tsecr", "NONE");
		}
	} else {
		tg->signature("# No TCP SYN ACK reply received", "");
		tg->signature("tcp_syn_ack_tos", "");
		tg->signature("tcp_syn_ack_df", "");
		tg->signature("tcp_syn_ack_ip_id", "");
		tg->signature("tcp_syn_ack_ttl", "");
		tg->signature("tcp_syn_ack_ack", "");
		tg->signature("tcp_syn_ack_window_size", "");
		tg->signature("tcp_syn_ack_options_order", "");
		tg->signature("tcp_syn_ack_wscale", "");
		tg->signature("tcp_syn_ack_tsval", "");
		tg->signature("tcp_syn_ack_tsecr", "");
	}

}

/* initialization function */

int tcp_handshake_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {

    TCP_Handshake_Mod *tcp_handshake = new TCP_Handshake_Mod;

    tcp_handshake->set_name(nm);
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the TCP handshake module\n");
    pt->register_module(tcp_handshake);
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_ttl"); 
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_ip_id");
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_tos");
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_df");
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_ack");
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_window_size");
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_options_order");
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_wscale");
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_tsval");
	pt->add_keyword(tcp_handshake->get_id(), "tcp_syn_ack_tsecr");
return OK;
}

int TCP_Handshake_Ttl_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval=OK;
	if (!p->timeout())
		retval = add_param(p->get_ttl(), o->get_ttl(), os);
	return retval;
}

int TCP_Handshake_Ip_Id_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval = OK;	
	if (!p->timeout())
		retval = add_param(p->get_id(), o->get_id(), os);
	return retval;
}

int TCP_Handshake_Tos_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval = OK;
	if (!p->timeout())
		retval = add_param(p->get_tos(), o->get_tos(), os);
	return retval;
}

int TCP_Handshake_Df_Bit_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval = OK;	
	if (!p->timeout())
		retval = add_param(((p->get_fragoff() & IP_DF) != 0), ((o->get_fragoff() & IP_DF) != 0), os);
	return retval;
}

int TCP_Handhake_Ack_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval = OK;
	if (!p->timeout())
		retval = add_param(p->get_ack() - o->get_seq(), 0, os);
	return retval;
}

int TCP_Handshake_Window_Check::check_param(TCP *p, TCP *o, OS_Matrix *os) {
	int retval = OK;
	if (!p->timeout())
		retval = add_param(p->get_win(), o->get_win(), os);
	return retval;
}
