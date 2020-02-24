/*
 * **
 * ** Copyright (C) 2001-2005  Fyodor Yarochkin <fygrave@tigerteam.net>,
 * ** 						Ofir Arkin <ofir@sys-security.com>
 * **						Meder Kydyraliev <meder@o0o.nu>
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

#ifndef TCP_RST_MOD_H
#define TCP_RST_MOD_H

#include "xprobe.h"
#include "xprobe_module.h"
#include "xprobe_module_param.h"


class TCP_Rst_Mod: public Xprobe_Module {
	private:
		map<string, Xprobe_Module_Param_TCP *> kwd_chk;
//		void generate_signature(Target *, TCP *, TCP *);
		void generate_signature(Target *, TCP *, TCP *, TCP *);
	public:
		TCP_Rst_Mod(void);
		~TCP_Rst_Mod(void);
		int init(void);
		int parse_keyword(int, const char *, const char *);
		int exec(Target *, OS_Matrix *);
		int fini(void);
};

class TCP_Rst_Df_Bit_Check: public Xprobe_Module_Param_TCP {
	public:
		TCP_Rst_Df_Bit_Check(void) : Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_INT) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

class TCP_Rst_Ip_Id_Check: public Xprobe_Module_Param_TCP {
	public:
		TCP_Rst_Ip_Id_Check(void) : Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_ZNZORIG) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

class TCP_Rst_Ttl_Check: public Xprobe_Module_Param_TCP {
	public:
		TCP_Rst_Ttl_Check(void): Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_RANGE) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

class TCP_Rst_Ip_Id_Strategy: public Xprobe_Module_Param_TCP {
	public:
		TCP_Rst_Ip_Id_Strategy(void): Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_STRATEGY) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

class TCP_Rst_Reply_Check: public Xprobe_Module_Param_TCP {
	public:
		TCP_Rst_Reply_Check(void): Xprobe_Module_Param_TCP(XPROBE_MODULE_PARAM_BOOL) { return; }
		int check_param(TCP *p, TCP *o, OS_Matrix *os);
};

#endif /* TCP_RST_MOD_H */
