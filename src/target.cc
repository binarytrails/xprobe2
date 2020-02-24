/* $Id: target.cc,v 1.17 2005/07/26 12:33:42 mederchik Exp $ */
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
#include "target.h"
#include "interface.h"
#include "xprobe_module_hdlr.h"
#include "cmd_opts.h"
#include "os_matrix.h"
#include "xplib/xplib.h"
#include "log.h"

extern Interface *ui;
extern Xprobe_Module_Hdlr   *xmh;
extern OS_Name *oses;
extern Cmd_Opts *copts;
extern XML_Log *xml;

/*
 *************************
 * Target_Net:: object methods
 *************************
 */
int Target_Net::parse_mask(char *mask_ascii) {

    if (!mask_ascii) return FAIL;
    if (!atoi(mask_ascii) || atoi(mask_ascii) > 32) {
        ui->error("Incorrect netmask specification: %s "
                "(1-32 allowed)\n", mask_ascii);
        return FAIL;
    }
    mask = htonl((0xffffffff<<(32-atoi(mask_ascii))));
    return OK;
}

int Target_Net::parse_host(char *target) {
    char *host_ascii;
    char *mask_ascii;

    host_ascii = strdup(target);
    if((mask_ascii = strchr(host_ascii,'/')) != NULL) {
		*mask_ascii='\0';
		mask_ascii++;
        if (parse_mask(mask_ascii) != OK) {
            free(host_ascii);
            return FAIL;
        }
    } else {
        mask = 0xffffffff;
    }

    if (resolve_host(host_ascii) == FAIL) {
        ui->error("Can not resolve %s: %s\n", host_ascii,
                     hstrerror(h_errno));
        free(host_ascii);
        return FAIL;
    }
    addr &= mask; 
    free(host_ascii);
    return OK;
}

int Target_Net::resolve_host(char *host) {

    struct hostent *host_serv;

    if ((addr = inet_addr(host)) == INADDR_NONE)
    {
        host_serv = gethostbyname(host);
        if (host_serv == NULL)
            return FAIL;
	memcpy((void *)&addr, (void *)host_serv->h_addr, host_serv->h_length);
    }
    return OK;
}

Target_Net::Target_Net(char *target) {
    init(target);
}

Target_Net::Target_Net(void) {

    ascii_name = NULL;
    addr = mask = counter = 0;
}

int Target_Net::init(char *target) {

    ascii_name = strdup(target);
    if (parse_host(ascii_name) == FAIL) return FAIL;
    counter = ntohl(addr);
    return OK;
}
    
unsigned long Target_Net::getnext(void) {

    if (counter > ntohl(addr|mask^0xffffffff))
        return 0;
	if (counter == htonl(addr)) { // network number
		if (mask != 0xffffffff) { // special case of /32
			counter++;
		}
		return (htonl(counter++));
	}
	if (ntohl(mask^0xffffffff) == (counter & ntohl(mask^0xffffffff))){ // broadcast address
		return 0;
	}
	return (htonl(counter++));
}



/*
 ******************************
 * Target:: object methods
 ******************************
 */

//void Target::add_p(map <int, char> &ic_map, int p, char s) {
void Target::add_p(map <int, char> *ic_map, int p, char s) {
            ic_map->insert(pair<int, char>(p, s));
}

//int Target::find_stat_p(map <int, char> &ic_map, char s) {
int Target::find_stat_p(map <int, char> *ic_map, char s) {
    map <int, char>::iterator ic_map_i;
        for (ic_map_i = ic_map->begin(); ic_map_i != ic_map->end(); ic_map_i++) {
            if ((*ic_map_i).second == s) return (*ic_map_i).first;
        }
        return -1;
}

void Target::add_port(int proto, int port, char s) {

    switch(proto) {
        case IPPROTO_TCP:
            add_p(&tcp_ports, port, s);
            break;
        case IPPROTO_UDP:    
            add_p(&udp_ports, port, s);
            break;
        default:
            xprobe_debug(XPROBE_DEBUG_TARGET, "Unknown protocol: %i for port %i",
                            proto, port);
    }
}

int Target::get_port(int proto, int s) {

    switch(proto) {
        case IPPROTO_TCP:
            return (find_stat_p(&tcp_ports, s));
            break;
        case IPPROTO_UDP:    
            return (find_stat_p(&udp_ports, s));
            break;
        case IPPROTO_ICMP:    
            return (find_stat_p(&tcp_ports, s));
            break;
        default:
            return -1;
    }

}

bool Target::port_is_open(int proto, int port) {
	map <int, char>::iterator iter;
    switch(proto) {
        case IPPROTO_TCP:
			iter = tcp_ports.find(port);
			if (iter == tcp_ports.end()) return false;
			if (iter->second == XPROBE_TARGETP_OPEN) return true;
            break;
        case IPPROTO_UDP:    
			iter = udp_ports.find(port);
			if (iter == udp_ports.end()) return false;
			if (iter->second == XPROBE_TARGETP_OPEN || iter->second == XPROBE_TARGETP_FILTERED)
				return true;
            break;
        default:
            xprobe_debug(XPROBE_DEBUG_TARGET, "Unknown protocol: %i for port %i",
                            proto, port);
    }
	return false;
}

void Target::add_protocol(int proto, char s) {
        add_p(&protocols,  proto, s);
}

struct in_addr Target::get_interface_addr(void) {
    struct in_addr a;
//    a = xp_get_iface_addr(xp_get_interface(addr));
	a = xp_get_src_addr(addr);
    return a;
}

char * Target::get_interface(void) {
    char *in;
    in = xp_get_interface(addr);
    return in;
}

void Target::set_ttl(int type, int val) {
    /*XXX: do proper search in the base later */
    if (get_ttl(type) != FAIL) return; /* already  there */
    ttls.insert(pair<int, int>(type, val));
}

int Target::get_ttl(int type) {
    map <int, int>::iterator ttls_i;
			    
    ttls_i = ttls.find(type);
    if (ttls_i != ttls.end()) return (*ttls_i).second;
    return FAIL;

}

int Target::check_alive(void) {
    OS_Matrix *os;
    int ret = 0, alive_tests = xmh->loaded_mods_num(XPROBE_MODULE_ALIVETEST);

	if (alive_tests > 0) {
		os =  new OS_Matrix(xmh->loaded_mods_num(XPROBE_MODULE_ALIVETEST));
		xmh->exec(XPROBE_MODULE_ALIVETEST, this, os);

		if (os->get_score(os->get_top(0)) > 0) ret = 1;

		ui->msg("[+] Host: %s is %s (Guess probability: %i%%)\n",
    	        inet_ntoa(addr), ret == 1?"up":"down", ret ==1?os->get_prcnt_score(os->get_top(0)):0);
		xml->log(XPROBELOG_MSG_STATE, "%s%p", ret == 1?"up":"down", ret ==1?os->get_prcnt_score(os->get_top(0)):0);
		delete os;
	} else {
		/* All alive tests were disabled
		 * user wants to skip the reachability test
		 */
		ui->msg("[+] All alive tests disabled\n");
		ret = 1;
	}
    return(ret);
}

int Target::os_probe(void) {
//    OS_Matrix *os = new OS_Matrix(xmh->loaded_mods_num(XPROBE_MODULE_OSTEST));
    OS_Matrix *os;
    int ret = 0, i = xmh->loaded_mods_num(XPROBE_MODULE_OSTEST), keywordcount;

	if (i < 1) {
		ui->msg("[+] All fingerprinting modules were disabled\n");
		return OK;
	}
	os = new OS_Matrix(i);
    xmh->exec(XPROBE_MODULE_OSTEST, this, os);

    if (os->get_score(os->get_top(0)) != 0) ret = 1;

	if (gen_sig) {
		ui->msg("[+] Signature looks like:\n");
		ui->msg("[+]  %s (%i%%)\n", oses->osid2char(os->get_top(0)), os->get_prcnt_score(os->get_top(0)));
		ui->msg("[+] Generated signature for %s:\n", inet_ntoa(addr));
		ui->log("%s", (fingerprint.get_sig(&keywordcount)).c_str());
		if (keywordcount < xmh->loaded_mods_num(XPROBE_MODULE_OSTEST)) {
			ui->msg("[+] GENERATED FINGERPRINT IS INCOMPLETE!\n");
			ui->msg("[+] Please make sure you target is not firewalled and you have specified at least one open TCP port and one closed TCP and UDP ports!\n");
		}
	} else {
		xml->log(XPROBELOG_GUESS_SESS_START, "OS guess");
	    ui->msg("[+] Primary guess:\n");
    	ui->msg("[+] Host %s Running OS: %s (Guess probability: %i%%)\n",
        	    inet_ntoa(addr), oses->osid2char(os->get_top(0)), os->get_prcnt_score(os->get_top(0)));
		xml->log(XPROBELOG_MSG_PRIMARY, "%p%s", os->get_prcnt_score(os->get_top(0)), oses->osid2char(os->get_top(0)));
    	ui->msg("[+] Other guesses:\n");
    	i = 1;
    	while (os->get_top(i) && os->get_prcnt_score(os->get_top(i)) && i != copts->get_numofmatches()) {
        	ui->msg("[+] Host %s Running OS: %s (Guess probability: %i%%)\n",
            	    inet_ntoa(addr), oses->osid2char(os->get_top(i)),
                	os->get_prcnt_score(os->get_top(i)));
			xml->log(XPROBELOG_MSG_SECONDARY, "%p%s", os->get_prcnt_score(os->get_top(i)), oses->osid2char(os->get_top(i)));
        	i++;
    	}
		xml->log(XPROBELOG_GUESS_SESS_END, "end of guess");
	}
    delete os;
    return(ret);
}

int Target::gather_info(void) {
	OS_Matrix *os = new OS_Matrix(xmh->loaded_mods_num(XPROBE_MODULE_INFOGATHER));
	
	xml->log(XPROBELOG_INFO_SESS_START, "starting info gathering");
	xmh->exec(XPROBE_MODULE_INFOGATHER, this, os);
	xml->log(XPROBELOG_INFO_SESS_END, "info gathering ended\n");

	return OK;
}

void Target::set_tcp_ports(map <int, char> *tp) {
 	map <int, char>::iterator p_i;
 
	for (p_i = (*tp).begin(); p_i != (*tp).end(); p_i++) {
		// already inserted values should not be overwritten
		if (tcp_ports.find((*p_i).first) == tcp_ports.end()) 
			tcp_ports.insert((*p_i));
	}

}

void Target::set_udp_ports(map <int, char> *up) {
 	map <int, char>::iterator p_i;
 
	for (p_i = (*up).begin(); p_i != (*up).end(); p_i++) {
		// already inserted values should not be overwritten
		if (udp_ports.find((*p_i).first) == udp_ports.end()) 
			udp_ports.insert((*p_i));
	}

}

void Target::signature(string& key, string& val) {
	fingerprint.append_sig(key, val);
}

void Target::signature(const char *key, const char *val) {
	string keyw = key, value = val;
	fingerprint.append_sig(keyw, value);
}

string Target::signature() {
	int k; // dummy
	return fingerprint.get_sig(&k);
}

void Port_Range::set_range(u_short a, u_short b) {

	if (a >= b) {
		low = b;
		high = a;
	} else {
		low = a;
		high = b;
	}
	curr = 0;
}

int Port_Range::get_next(u_short *port) {
	int k, sz=size();
	
	if (curr+low > high)
		return 1;
	else if (curr == 0) { /* first call to get_next() */
		// initialize
		for (k=0; k < sz; k++) 
			ports.push_back(low + k);
		random_shuffle(ports.begin(), ports.end());
		*port = ports[curr++];
	} else 
		*port = ports[curr++];
	return 0;
}

void Port_Range::reset() {
	curr = 0;
}

void Signature::print_sig(void) {
	map<string, string>::iterator iter;

	ui->msg("%s", header.c_str());
	for (iter=key_val.begin(); iter!=key_val.end(); iter++) {
		ui->msg("%s = %s\n", iter->first.c_str(), iter->second.c_str());
	}
}

string Signature::get_sig(int *kcount) {
	string retval;
	map<string, string>::iterator iter;

	*kcount=0;
	retval.append(header);
	for (iter=key_val.begin(); iter!=key_val.end(); iter++) {
		retval.append("\t");
		retval.append(iter->first);
		retval.append(" = ");
		retval.append(iter->second);
		retval.append("\n");
		(*kcount)++;
	}
	retval.append("}\n");
	return retval;	
}
