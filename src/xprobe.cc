/* $Id: xprobe.cc,v 1.7 2004/09/05 07:18:00 mederchik Exp $ */
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
#include "cmd_opts.h"
#include "targets_list.h"
#include "config_set.h"
#include "xprobe_module.h"
#include "xprobe_module_hdlr.h"
#include "scan_engine.h"
#include "interface_con.h"
#include "os_matrix.h"
#include "log.h"

/* globals */

Cmd_Opts       *copts;
Targets_List   *targets;
Config_Set      *cfg;
Xprobe_Module_Hdlr     *xmh;
Interface       *ui;
Scan_Engine     *se;
OS_Name         *oses;
XML_Log			*xml;

int main(int argc, char *argv[]) {

    ui      = new Interface_Con; // we have only console for now
    copts   = new Cmd_Opts;
    targets = new Targets_List;
    xmh     = new Xprobe_Module_Hdlr;
    se      = new Scan_Engine;
    cfg     = new Config_Set;
    oses    = new OS_Name;
	xml 	= new XML_Log;
	time_t	start = time(NULL);

    ui->msg("%s\n",BANNER);
    copts->parse(argc, argv);

	/* should we show the route to target */
	cfg->show_route(copts->show_route());
	cfg->set_udp_ports(copts->get_udp_ports());
	cfg->set_tcp_ports(copts->get_tcp_ports());
	if (copts->do_xml())
		if (xml->set_logfile(copts->get_logfile()))
			exit(1);
    /* targets list */
    if (targets->init(copts->get_target()) == FAIL) {
        exit(1);
    }
	xml->log(XPROBELOG_XP_SESS_START, "%v%b", VERSION, BANNER);
	xml->log(XPROBELOG_MSG_RUN, "%c%a%d", argc, argv, start);
    
    /* config file */
    xprobe_debug(XPROBE_DEBUG_INIT, "[+] config file is: %s\n", copts->get_configfile());
    

    /* load modules first. register the keywords */
    xmh->load();

    /* parse config file */
    if (cfg->read_config(copts->get_configfile()) == FAIL) {
        exit(1);
    }

    /* debugging only! */
    oses->list_oses();
    
    /* initialize loaded tests */
    xmh->init();
    /* for debugging */
    xmh->print();

    /* scan stuff */
    se->init();
    se->run();
    se->fini();
    
    /* finite la comedia' */

    xmh->fini();
    ui->msg("[+] Execution completed.\n");
	xml->log(XPROBELOG_XP_SESS_END, "FIN");
    delete oses;
    delete copts;
    delete targets;
    delete cfg;
    delete xmh;
    delete se;
    delete ui;
	delete xml;

}
