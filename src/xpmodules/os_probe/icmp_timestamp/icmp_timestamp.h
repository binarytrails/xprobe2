/* $Id: icmp_timestamp.h,v 1.8 2004/06/09 12:08:28 mederchik Exp $ */
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

#ifndef ICMP_TIMESTAMP_H
#define ICMP_TIMESTAMP_H

#include "xprobe.h"
#include "xprobe_module.h"
#include "xprobe_module_param.h"

typedef struct ttl_val {
    int high;
    int low;
} ttl_val_s;

class ICMP_Timestamp_Mod: public Xprobe_Module {
    private:
        OS_Matrix *current_os;
		map <string, Xprobe_Module_Param_ICMP *> kwd_chk;
		map <string, Xprobe_Module_Param_ICMP *>::iterator s_i;
        int do_icmp_query(Target *);
		void generate_signature(Target *, ICMP *, ICMP *);
    public:
        ICMP_Timestamp_Mod(void);
        ~ICMP_Timestamp_Mod(void);
        int init(void);
        int parse_keyword(int, const char *, const char *);
        int exec(Target *, OS_Matrix *);
        int fini(void);
};

class ICMP_Timestamp_Reply_Check: public Xprobe_Module_Param_ICMP {
	public:
		ICMP_Timestamp_Reply_Check(void):Xprobe_Module_Param_ICMP(XPROBE_MODULE_PARAM_BOOL) { return; }
		//~ICMP_Timestamp_Reply_Check(void) { return; }
		int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os);
};

class ICMP_Timestamp_Ip_Id_Check: public Xprobe_Module_Param_ICMP {
	public:
		ICMP_Timestamp_Ip_Id_Check(void): Xprobe_Module_Param_ICMP(XPROBE_MODULE_PARAM_ZNZORIG) {return;}
		//~ICMP_Timestamp_Ip_Id_Check(void) { return; }
		int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os);
};

class ICMP_Timestamp_Ttl_Check: public Xprobe_Module_Param_ICMP {
	public:
		ICMP_Timestamp_Ttl_Check(void): Xprobe_Module_Param_ICMP(XPROBE_MODULE_PARAM_RANGE) { return; }
		//~ICMP_Timestamp_Ttl_Check(void) { return; }
		int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os);
};

#endif /* ICMP_PING_H */
