/*
 * **
 * ** Copyright (C) 2005 Meder Kydyraliev <meder@o0o.nu>
 * ** Copyright (C) 2001-2005  Fyodor Yarochkin <fygrave@tigerteam.net>,
 * **                                           Ofir Arkin <ofir@sys-security.com>
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

#ifndef SNMP_MOD_H
#define SNMP_MOD_H

#include "xprobe.h"
#include "xprobe_module.h"
#include "xprobe_module_param.h"
#include "snmp.h"

#define	SNMP_COMMUNITY_IX	0
#define SNMP_SYSDESCR_IX	1
#define	SNMP_REQUESTID_IX	1
#define SNMP_MIN_STRINGS	2
#define SNMP_MIN_INTS		4

class SNMP_Mod: public Xprobe_Module {
	private:
		map<int, string> sysdescrs;
	public:
		SNMP_Mod(void);
		~SNMP_Mod(void);
		int init(void);
		int parse_keyword(int, const char *, const char *);
		int exec(Target *, OS_Matrix *);
		int fini(void);
};

#endif /* SNMP_MOD_H */
