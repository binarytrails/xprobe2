/*
 * **
 * ** Copyright (C) 2005  Meder Kydyraliev <meder@o0o.nu>
 * ** Copyright (C) 2001-2005  Fyodor Yarochkin <fygrave@tigerteam.net>,
 * **						Ofir Arkin       <ofir@sys-security.com>
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
#include "smb_mod.h"

extern Interface *ui;
extern Cmd_Opts *copts;

int smb_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {
	SMB_Mod *smb= new SMB_Mod;
	smb->set_name(nm);
	xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the SMB module\n");
	pt->register_module(smb);
	pt->add_keyword(smb->get_id(), "smb_nativeos");
	pt->add_keyword(smb->get_id(), "smb_lanman");
	return OK;
}

SMB_Mod::SMB_Mod(void): Xprobe_Module(XPROBE_MODULE_OSTEST, "fingerprint:smb", "SMB fingerprinting module") {

}

SMB_Mod::~SMB_Mod(void) {
	map<int, SMBFingerprint *>::iterator iter;

	for (iter=smb_fingerprints.begin(); iter!=smb_fingerprints.end(); iter++) {
		delete iter->second;
	}
}


int SMB_Mod::parse_keyword(int os_id, const char *kwd, const char *val) {
	map<int, SMBFingerprint *>::iterator iter;
	SMBFingerprint *fingerprint=NULL;

	iter = smb_fingerprints.find(os_id);

	if (iter == smb_fingerprints.end()) {
		fingerprint = new SMBFingerprint;
	} else {
		fingerprint = iter->second;
	}

	if (strncasecmp(kwd, "smb_nativeos", strlen("smb_nativeos")) == 0) {
		fingerprint->nativeos = val;
	} else if (strncasecmp(kwd, "smb_lanman", strlen("smb_lanman")) == 0) {
		fingerprint->lanman = val;
	} else {
		ui->error("SMB_Mod::parse_keyword(): unknown keyword %s!\n", kwd);
		if (fingerprint != NULL)
			delete fingerprint;
		return FAIL;
	}

	// insert fingerprint
	if (iter == smb_fingerprints.end()) {
		smb_fingerprints.insert(pair<int, SMBFingerprint *>(os_id, fingerprint));
	}
	return OK;
}

int SMB_Mod::init(void) {
	xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
	return OK;
}

int SMB_Mod::exec(Target *tg, OS_Matrix *os) {
	SMB smb;
	map<int, SMBFingerprint *>::iterator iter;
	int retval;
	unsigned short port=0;

	if (tg->port_is_open(IPPROTO_TCP, 139)) {
		port = 139;
	} else if (tg->port_is_open(IPPROTO_TCP, 445)) {
		port = 445;
	} else {
		ui->msg("[-] %s need either TCP port 139 or 445 to run\n", get_name());
		return FAIL;
	}

	retval = smb.session_setup_and_x(tg->get_addr(), port);
	if (retval == FAIL) {
		ui->error("[-] %s module failed!\n", get_name());
		if (tg->generate_sig()) {
			tg->signature("smb_nativeos", "");
			tg->signature("smb_lanman", "");
		}
		return FAIL;
	} else {
		ui->msg("[+] SMB [Native OS: %s] [Native Lanman: %s] [Domain: %s]\n",
				smb.get_nativeos().c_str(), smb.get_lanman().c_str(), smb.get_domain().c_str());
		ui->msg("[+] SMB [Called name: %s] [MAC: %s]\n",
				smb.get_calledname().c_str(), smb.get_mac().c_str());
		if (tg->generate_sig()) {
			tg->signature("smb_nativeos", smb.get_nativeos().c_str());
			tg->signature("smb_lanman", smb.get_lanman().c_str());
		} else {
			for (iter=smb_fingerprints.begin(); iter!=smb_fingerprints.end(); iter++) {
				if (xp_lib::equal(iter->second->nativeos, smb.get_nativeos())) {
					os->add_result(get_id(), iter->first, XPROBE_MATCH_YES);
				} else {
					os->add_result(get_id(), iter->first, XPROBE_MATCH_NO);
				}
				if (xp_lib::equal(iter->second->lanman, smb.get_lanman())) {
					os->add_result(get_id(), iter->first, XPROBE_MATCH_YES);
				} else {
					os->add_result(get_id(), iter->first, XPROBE_MATCH_NO);
				}
			}
		}
	}
	return OK;
}

int SMB_Mod::fini(void) {
	xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
	return OK;
}
