/* $Id: static_modules.h,v 1.8 2005/07/21 11:42:31 mederchik Exp $ */
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

#ifndef STATIC_MODULES_H
#define STATIC_MODULES_H

#include "xprobe_module_hdlr.h"

extern int icmp_ping_mod_init(Xprobe_Module_Hdlr *, char *);
extern int tcp_ping_mod_init(Xprobe_Module_Hdlr *, char *);
extern int udp_ping_mod_init(Xprobe_Module_Hdlr *, char *);
extern int ttl_mod_init(Xprobe_Module_Hdlr *, char *);
extern int icmp_echo_id_mod_init(Xprobe_Module_Hdlr *, char *);
extern int icmp_timestamp_mod_init(Xprobe_Module_Hdlr *, char *);
extern int icmp_inforeq_mod_init(Xprobe_Module_Hdlr *, char *);
extern int icmp_addrmask_mod_init(Xprobe_Module_Hdlr *, char *);
extern int icmp_port_unreach_init(Xprobe_Module_Hdlr *, char *);
extern int tcp_handshake_mod_init(Xprobe_Module_Hdlr *, char *);
extern int portscan_mod_init(Xprobe_Module_Hdlr *, char *);
extern int tcp_rst_mod_init(Xprobe_Module_Hdlr *, char *);
extern int smb_mod_init(Xprobe_Module_Hdlr *, char *);
extern int snmp_mod_init(Xprobe_Module_Hdlr *, char *);



typedef struct xprobe_module_func {
	char *name;
	int(* func)(Xprobe_Module_Hdlr *, char *);
} xprobe_module_func_t;

xprobe_module_func_t mod_init_funcs[]= {
	{"ping:icmp_ping", icmp_ping_mod_init},
	{"ping:tcp_ping", tcp_ping_mod_init},
	{"ping:udp_ping", udp_ping_mod_init },
	{"infogather:ttl_calc",ttl_mod_init },
	{"infogather:portscan", portscan_mod_init},
	{"fingerprint:icmp_echo", icmp_echo_id_mod_init},
	{"fingerprint:icmp_tstamp", icmp_timestamp_mod_init},
	{"fingerprint:icmp_amask", icmp_addrmask_mod_init},
	{"fingerprint:icmp_info", icmp_inforeq_mod_init },
	{"fingerprint:icmp_port_unreach", icmp_port_unreach_init},
	{"fingerprint:tcp_hshake", tcp_handshake_mod_init},
	{"fingerprint:tcp_rst", tcp_rst_mod_init},
	{"fingerprint:smb", smb_mod_init},
	{"fingerprint:snmp", snmp_mod_init},
	{NULL, NULL}
};


#endif /* STATIC_MODULES_H */
