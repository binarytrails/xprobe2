/* $Id: xprobe_module.h,v 1.6 2005/02/08 20:00:35 mederchik Exp $ */
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

#ifndef XPROBE_MODULE_H
#define XPROBE_MODULE_H

#include "xprobe.h"
#include "target.h"
#include "os_matrix.h"
#include "usi++/usi++.h"
//#include <string>

using namespace std;

#define XPROBE_MODULE_ALIVETEST     1
#define XPROBE_MODULE_OSTEST        2
#define XPROBE_MODULE_INFOGATHER	3

class Xprobe_Module {
    private:
        string name;
        string description;
        int mod_id;
        int mod_type;
		bool enabled;
		virtual void generate_signature(Target *, ICMP *, ICMP *) { return; }
		virtual void generate_signature(Target *, TCP *, TCP *) { return; }
   public:
    void set_desc(const char *nm) { description = nm; }
    const char *get_desc(void) { return description.c_str(); }
    void set_name(const char *nm) { name = nm; }
    const char* get_name(void) { return name.c_str(); }
    string& get_sname(void) { return name; }
    void set_id(int id) { mod_id = id; }
    int get_id(void) { return mod_id; }
    void set_type(int type) { mod_type = type; }
    int get_type(void) { return mod_type; }
    Xprobe_Module(void) { set_name((const char *)"noname"); set_desc("No description is given");}
    Xprobe_Module(int type, const char *nm, const char *desc) { set_type(type); set_name(nm); set_desc(desc); }
	void enable(void) { enabled = true; }
	void disable(void) { enabled = false; }
	bool is_disabled(void) { return (enabled == false);};
    virtual ~Xprobe_Module(void) { return; }
    /* these to be overriden */
    virtual int init(void) =0;
    virtual int parse_keyword(int, const char *, const char *) =0;
    virtual int exec(Target *, OS_Matrix *) =0;
    virtual int fini(void) =0;
};

#endif /* XPROBE_MODULE */
