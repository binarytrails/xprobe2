/* $Id: xprobe_module_hdlr.h,v 1.7 2005/02/09 18:36:45 mederchik Exp $ */
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

#ifndef XPROBE_MODULE_HDLR_H
#define XPROBE_MODULE_HDLR_H

#include "xprobe.h"
#include "xprobe_module.h"
#include "target.h"
#include "os_matrix.h"
/*
#include <string>
#include <map>
*/

using namespace std;

class Xprobe_Module_Hdlr {
    private:
        map<int, Xprobe_Module *> modlist;
        map<string, int> kwdlist;
        int keywords;
        int mod_counter;
   public:
        int loaded_mods_num(int);
        int load(void);
        int init(void);
        int print(void);
        int exec(int, Target *, OS_Matrix *);
        int fini(void);
        
		void display_mod_names(void);
        int register_module(Xprobe_Module *);
        int add(int(*)(Xprobe_Module_Hdlr *, char *), char *);
        void add_keyword(int, char *);
		int get_module_count();
		int modbyname(char *nm);	
		bool mod_disabled_by_default(unsigned int ix) {
			unsigned int disabled_mods[] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};
			if (ix < sizeof(disabled_mods))
				return (disabled_mods[ix] == 1);
			else 
				return false;
		}
        Xprobe_Module *find_mod(string &);
        Xprobe_Module_Hdlr(void);
        ~Xprobe_Module_Hdlr(void);
};

#endif /* XPROBE_MODULE_HDLR_H */
