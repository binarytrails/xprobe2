/*
**
** Copyright (C) 2001, 2002, 2003 Meder Kydyraliev
**
** Copyright (C) 2001, 2002, 2003  Fyodor Yarochkin <fygrave@tigerteam.net>,
**									Ofir Arkin       <ofir@sys-security.com>
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

#ifndef TCP_HANDSHAKE_MOD_H
#define TCP_HANDSHAKE_MOD_H

#include "xprobe.h"
#include "xprobe_module.h"
#include "xprobe_module_param.h"

class TCP_Handshake_Mod: public Xprobe_Module {
    private:
		map<string, Xprobe_Module_Param_TCP *> kwd_chk;
		map<int, string> options_map;
		map<int, string>::iterator o_i;
		map<int, int> wscale_map;
		map<int, int>::iterator w_i;
		map<int, unsigned int> tsval;
		map<int, unsigned int> tsecr;
		map<int, unsigned int>::iterator ts_i;
		char opt_order[40];
		int wscale;
		unsigned int tse_first, tsv_first, tse_second, tsv_second;
	   	unsigned short used_port;
		bool got_timestamp;
		unsigned int timestamps[2];
		int get_tcpopts_pack(Target *, TCP *);
		int parse_options(char *tcp_options, int len);
		void generate_signature(Target *, TCP *, TCP *);
		int run_probe(Target *, OS_Matrix *);
    public:
        TCP_Handshake_Mod(void);
        ~TCP_Handshake_Mod(void);
        int init(void);
        int parse_keyword(int, const char *, const char *);
        int exec(Target *, OS_Matrix *);
        int fini(void);
};

class TCP_Handshake_Ttl_Check: public Xprobe_Module_Param_TCP {
	public:
		TCP_Handshake_Ttl_Check(void): Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_RANGE) { return; }
		//~TCP_Handshake_Ttl_Check(void) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

class TCP_Handshake_Ip_Id_Check: public Xprobe_Module_Param_TCP {
	public:
		TCP_Handshake_Ip_Id_Check(void): Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_ZNZORIG) { return; }
		//~TCP_Handshake_Ip_Id_Check(void) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

class TCP_Handshake_Tos_Check: public Xprobe_Module_Param_TCP {
	public:
		TCP_Handshake_Tos_Check(void): Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_ZNZVAL) { return; }
		//~TCP_Handshake_Tos_Check(void) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

class TCP_Handshake_Df_Bit_Check: public Xprobe_Module_Param_TCP {
	public: 
		TCP_Handshake_Df_Bit_Check(void): Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_INT) { return; }
		//~TCP_Handshake_Df_Bit_Check(void) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

class TCP_Handhake_Ack_Check: public Xprobe_Module_Param_TCP {
	public:
		TCP_Handhake_Ack_Check(void): Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_INT) { return; }
		//~TCP_Handhake_Ack_Check(void) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

class TCP_Handshake_Window_Check: public Xprobe_Module_Param_TCP {
	public: 
		TCP_Handshake_Window_Check(void): Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_INTLIST) { return; }
		//~TCP_Handshake_Window_Check(void) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

#endif /* TCP_HANDSHAKE_MOD_H */
