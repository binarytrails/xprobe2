/* $Id: icmp_echo_id.h,v 1.8 2005/02/08 20:00:54 mederchik Exp $ */
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

#ifndef ICMP_ECHO_ID_H
#define ICMP_ECHO_ID_H

#include "xprobe.h"
#include "xprobe_module.h"
#include "xprobe_module_param.h"

typedef struct ttl_val {
    int high;
    int low;
} ttl_val_s;

class ICMP_Echo_Id_Mod: public Xprobe_Module {
    private:
        OS_Matrix *current_os;
        map <int, int> sig;
        map <int, int> sig_ttl;
        map <string, Xprobe_Module_Param_ICMP *> kwd_chk;

        int do_icmp_ping(Target *);
        void sig_insert(int, int);
        void sig_ttl_insert(int, int);
        void do_code_check(int);
        void do_ttl_check(int);
		void generate_signature(Target *, ICMP *, ICMP *);
    public:
        ICMP_Echo_Id_Mod(void);
        ~ICMP_Echo_Id_Mod(void);
        int init(void);
        int parse_keyword(int, const char *, const char *);
        int exec(Target *, OS_Matrix *);
        int fini(void);
};

class ICMP_Echo_Code_Chk:public Xprobe_Module_Param_ICMP {
    public:
    ICMP_Echo_Code_Chk(void):Xprobe_Module_Param_ICMP(XPROBE_MODULE_PARAM_ZNZ) {return; }
    //~ICMP_Echo_Code_Chk(void) {return; }
    int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os);
};

class ICMP_Echo_Id_Chk:public Xprobe_Module_Param_ICMP {
    public:
    ICMP_Echo_Id_Chk(void):Xprobe_Module_Param_ICMP(XPROBE_MODULE_PARAM_ZNZORIG)  {return; }
    //~ICMP_Echo_Id_Chk(void) {return; }
    int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os);
};


class ICMP_Echo_Tos_Chk:public Xprobe_Module_Param_ICMP {
    public:
    ICMP_Echo_Tos_Chk(void):Xprobe_Module_Param_ICMP(XPROBE_MODULE_PARAM_ZNZ){return; }
    //~ICMP_Echo_Tos_Chk(void) {return; }
    int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os);
};

class ICMP_Echo_Df_Bit_Chk:public Xprobe_Module_Param_ICMP {
    public:
    ICMP_Echo_Df_Bit_Chk(void):Xprobe_Module_Param_ICMP(XPROBE_MODULE_PARAM_INT) {return; }
    //~ICMP_Echo_Df_Bit_Chk(void) {return; }
    int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os);
};

class ICMP_Echo_Reply_Ttl_Chk:public Xprobe_Module_Param_ICMP {
    public:
    ICMP_Echo_Reply_Ttl_Chk(void) :Xprobe_Module_Param_ICMP(XPROBE_MODULE_PARAM_RANGE) {return; }
    //~ICMP_Echo_Reply_Ttl_Chk(void) {return; }
    int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os);
};

class ICMP_Echo_Reply_Check: public Xprobe_Module_Param_ICMP {
	public:
	ICMP_Echo_Reply_Check(void):Xprobe_Module_Param_ICMP(XPROBE_MODULE_PARAM_BOOL) { return; }
	int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os);
};


#endif /* ICMP_ECHO_ID_H */
