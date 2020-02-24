/*
 * **
 * ** Copyright (C) 2005  Meder Kydyraliev <meder@o0o.nu>
 * ** Copyright (C) 2001-2005  Fyodor Yarochkin <fygrave@tigerteam.net>,
 * **                                           Ofir Arkin       <ofir@sys-security.com>
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
#include "config_set.h"
#include "snmp_mod.h"

extern Interface *ui;
extern Cmd_Opts *copts;
extern Config_Set *cfg;

int snmp_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {
	SNMP_Mod *snmp= new SNMP_Mod;
	snmp->set_name(nm);
	xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the SNMP module\n");
	pt->register_module(snmp);
	pt->add_keyword(snmp->get_id(), "snmp_sysdescr");
	return OK;
}

SNMP_Mod::SNMP_Mod(void): Xprobe_Module(XPROBE_MODULE_OSTEST, "fingerprint:snmp", "SNMPv2c fingerprinting module") {

}

SNMP_Mod::~SNMP_Mod(void) {
}


int SNMP_Mod::parse_keyword(int os_id, const char *kwd, const char *val) {
	string descr(val);

	xprobe_debug(XPROBE_DEBUG_SIGNATURES, "Parsing for %i : %s  = %s\n", os_id, kwd, val);
	sysdescrs.insert(pair<int, string>(os_id, descr));
	return OK;
}

int SNMP_Mod::init(void) {
	xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
	return OK;
}

int SNMP_Mod::exec(Target *tg, OS_Matrix *os) {
	char snmp_request_start[]=
								"\x30"
								"\x26"                          // length of the data that followd
								"\x02\x01\x01"                  // version 2c
								"\x04"                          // string
								"\x03";                         // length of community string
								// community string here
	char snmp_request_end[]=
								"\xa0\x1c"                      // PDU GET
								"\x02\x04\x22\xa2\x3d\x23"      // request ID
								"\x02\x01\x00"                  // Err status (NO ERR)
								"\x02\x01\x00"                  // Err index (NO ERR)
								"\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00" // SNMPv2 MIBD sysDescr.0
								"\x05\x00";                     // value NULL

	int sock, retval;
	unsigned int i, packlen;
	unsigned char *packet, buf[2048];
	unsigned long request_id;
	struct sockaddr_in to;
	vector<string> tokens;
	vector<string> snmpstrings;
	vector<unsigned long> snmpints;
	map<int, string>::iterator iter;
	SNMP snmp;


	if (!tg->port_is_open(IPPROTO_UDP, 161)) {
		ui->error("[-] %s: need UDP port 161 open\n", get_name());
		return FAIL;
	}
	bzero(&to, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons(161);
	to.sin_addr = tg->get_addr();

	if ((sock = xp_lib::OpenUDPSocket(&to, NULL)) == FAIL) {
		ui->error("[-] %s: OpenUDPSocket() failed (%s)!\n", get_name(), strerror(errno));
		return FAIL;
	}

	/*
	 * get a vector of community strings to try
	 */
	xp_lib::tokenize(cfg->get_comstrings().c_str(), ',', &tokens);

	for (i=0; i < tokens.size(); i++) {
		xprobe_debug(XPROBE_DEBUG_MODULES, "SNMP trying community string: %s\n", tokens[i].c_str());
		request_id = rand();

		/*
		 * set request ID
		 */
		snmp_request_end[4]   = (unsigned char)(request_id & 0xFF);
		snmp_request_end[5] = (unsigned char)((request_id >> 8) & 0xFF);
		snmp_request_end[6] = (unsigned char)((request_id >> 16) & 0xFF);
		snmp_request_end[7] = (unsigned char)((request_id >> 24) & 0xFF);

		packlen = tokens[i].size() + sizeof(snmp_request_start)-1 + sizeof(snmp_request_end)-1;
		packet = new unsigned char[packlen];
		snmp_request_start[6] = tokens[i].size();	// comunity string length
		snmp_request_start[1] = packlen - 2;		// length of the ASN sequence

		/*
		 * construct the SNMP request (ugly)
		 */
		memcpy(packet, snmp_request_start, sizeof(snmp_request_start)-1);
		memcpy(packet+sizeof(snmp_request_start)-1, tokens[i].c_str(), tokens[i].size());
		memcpy(packet+sizeof(snmp_request_start)-1+tokens[i].size(), snmp_request_end, sizeof(snmp_request_end)-1);

		if ((retval = send(sock, packet, packlen, 0)) < 0) {
			if (errno == ECONNREFUSED)
				tg->add_port(IPPROTO_UDP, 161, XPROBE_TARGETP_CLOSED);
			ui->error("[-] %s: send() failed (%s)\n", get_name(), strerror(errno));
			return FAIL;
		}
		delete []packet;
		retval = xp_lib::RecvTimeout(sock, buf, sizeof(buf), 1);
		if (retval == 0) {
			// timeout
			continue;
		} else if (retval == FAIL) {
			ui->error("[-] %s: RecvTimeout() failed!\n", get_name());
			return FAIL;
		}
		xprobe_debug(XPROBE_DEBUG_MODULES, "%s got %d bytes\n", get_name(), retval);
		if (snmp.parse(buf, retval) == FAIL) {
			ui->error("[-] %s: SNMP::parse() failed!\n", get_name());
			return FAIL;
		}
		snmp.get_strings(snmpstrings);
		snmp.get_integers(snmpints);
		if (snmpstrings.size()  < SNMP_MIN_STRINGS) {
			ui->error("[-] %s: Invalid number of strings %d (min is %d)\n",
							get_name(), snmpstrings.size(), SNMP_MIN_STRINGS);
			return FAIL;
		}
		if (snmpints.size() < SNMP_MIN_INTS) {
			ui->error("[-] %s: Invalid number of integers %d (min is %d)\n",
							get_name(), snmpints.size(), SNMP_MIN_INTS);
			return FAIL;
		}
		if (snmpints[SNMP_REQUESTID_IX] != htonl(request_id)) {
			ui->error("[-] %s: Got invalid request id from remote target 0x%lx (expected 0x%lx)\n",
						get_name(), snmpints[SNMP_REQUESTID_IX], htonl(request_id));
			return FAIL;
		}
		ui->msg("[+] SNMP [Community: %s] [sysDescr.0: %s]\n",
					snmpstrings[SNMP_COMMUNITY_IX].c_str(), snmpstrings[SNMP_SYSDESCR_IX].c_str());

		/*
		 * perform fingerprint matching
		 */
		for (iter = sysdescrs.begin(); iter != sysdescrs.end(); iter++) {

			string::size_type mypos = snmpstrings[SNMP_SYSDESCR_IX].find(iter->second);
			if (mypos == string::npos) {
				os->add_result(get_id(), iter->first, XPROBE_MATCH_NO);
			} else  {
				os->add_result(get_id(), iter->first, XPROBE_MATCH_YES);
			}
		}
		
		break;
	}	
	close(sock);
	return OK;
}

int SNMP_Mod::fini(void) {
	xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
	return OK;
}

