/* $Id: xprobe_module_hdlr.cc,v 1.7 2005/02/09 18:36:45 mederchik Exp $ */
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
#include "xprobe_module_hdlr.h"
#include "interface.h"
#include "cmd_opts.h"
#include "xpmodules/static_modules.h"
#include "log.h"

extern Interface *ui;
extern Cmd_Opts *copts;
extern XML_Log *xml;

int Xprobe_Module_Hdlr::load(void) {    
	int cnt=1;
    xprobe_module_func_t *ptr;

    ui->msg("[+] Loading modules.\n");

    ptr = mod_init_funcs;
    while (ptr !=NULL && ptr->name !=NULL && ptr->func !=NULL) { 
		if (!copts->mod_is_disabled(cnt++))
			add(ptr->func, ptr->name);
		ptr++;
	}
    return 1;

}

int Xprobe_Module_Hdlr::init(void) { 
    map<int, Xprobe_Module *>::iterator m_i;

    for (m_i = modlist.begin(); m_i != modlist.end(); m_i++) 
        (*m_i).second->init();
    return 1;
}

int Xprobe_Module_Hdlr::print(void) { 
    map<int, Xprobe_Module *>::iterator m_i;

    ui->msg("[+] Following modules are loaded:\n");
	xml->log(XPROBELOG_MOD_SESS_START, "Loaded modules");
    for (m_i = modlist.begin(); m_i != modlist.end(); m_i++) {
        ui->msg("[x] [%d] %s  -  %s\n", (*m_i).first, 
			(*m_i).second->get_name(), (*m_i).second->get_desc());
		xml->log(XPROBELOG_MSG_MODULE, "%t%n%d%s", m_i->second->get_type(), 
				m_i->second->get_name(), m_i->first, m_i->second->get_desc());
	}
   ui->msg("[+] %i modules registered\n", mod_counter);     
	xml->log(XPROBELOG_MOD_SESS_END, "End modules");
   return 1;     
}

int Xprobe_Module_Hdlr::exec(int mod_type, Target *tg, OS_Matrix *os) { 
    map<int, Xprobe_Module *>::iterator m_i;

    for (m_i = modlist.begin(); m_i != modlist.end(); m_i++)  {
        if ((*m_i).second->get_type() == mod_type) {
            xprobe_debug(XPROBE_DEBUG_MODULES, 
                        "[+] Executing module: %s\n", (*m_i).second->get_name());
                         (*m_i).second->exec(tg, os);
        }
    }
    return 1;
}

int Xprobe_Module_Hdlr::fini(void) { 
    map<int, Xprobe_Module *>::iterator m_i;

    //xprobe_debug(XPROBE_DEBUG_MODULES, "[+] Deinitializing modules\n");
    for (m_i = modlist.begin(); m_i != modlist.end(); m_i++) {
        xprobe_debug(XPROBE_DEBUG_MODULES, "[+] Deinitializing module: [%i] %s\n", (*m_i).first,
                (*m_i).second->get_name());
        (*m_i).second->fini();
    }

    for (m_i = modlist.begin(); m_i != modlist.end(); m_i++) 
        delete (*m_i).second;
        
    ui->msg("[+] Modules deinitialized\n");
    return 1;
}


int Xprobe_Module_Hdlr::add(int (*init_func)(Xprobe_Module_Hdlr *, char *), char *nm) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "[+] adding %s via function: %p\n", nm, init_func);
    return(init_func(this, nm));
}
    
int Xprobe_Module_Hdlr::register_module(Xprobe_Module *mod) {

    mod_counter++;
    mod->set_id(mod_counter);
    modlist.insert(pair<int, Xprobe_Module *>(mod_counter, mod));
    
    return 1;
}

void Xprobe_Module_Hdlr::add_keyword(int id, char *str) {
    string kwd(str);

    kwdlist.insert(pair<string, int>(kwd, id));
   	keywords++;
}

/* XXX: temp plug. Supposed to return module ptr which is registered for
 * keyword kwd
 */
Xprobe_Module *Xprobe_Module_Hdlr::find_mod(string &kwd) {
    map <string, int>::iterator kw_i;
    map<int, Xprobe_Module *>::iterator mod_i;
    
    kw_i = kwdlist.find(kwd);

    if (kw_i == kwdlist.end()) {
        xprobe_debug(XPROBE_DEBUG_CONFIG, "[x] failed to lookup module on %s keyword\n", kwd.c_str());
        return NULL;
    }
    mod_i = modlist.find((* kw_i).second);
    if (mod_i == modlist.end()) {
        ui->error("[x] failed to associate moule id!\n");
        return NULL;
    }
    xprobe_debug(XPROBE_DEBUG_CONFIG,"[x] keyword: %s handled by module: %s\n", kwd.c_str(),
    (*mod_i).second->get_name());
    return (*mod_i).second;
}

int Xprobe_Module_Hdlr::loaded_mods_num(int mod_type) { 
    map<int, Xprobe_Module *>::iterator m_i;
    int num = 0;

    for (m_i = modlist.begin(); m_i != modlist.end(); m_i++) 
        if ((*m_i).second->get_type() == mod_type) num++;

    /* sometimes os_test module handles multiple keywords */
    if (mod_type == XPROBE_MODULE_OSTEST && num < keywords)
        return keywords;

    return num;
}

int Xprobe_Module_Hdlr::modbyname(char *nm) {

    xprobe_module_func_t *ptr;
    int cnt = 0;

    ptr = mod_init_funcs;
    while (ptr !=NULL && ptr->name !=NULL && ptr->func != NULL) {
	    cnt++;
	    if (!strcasecmp(ptr->name, nm)) return cnt;
	    ptr++;
    }
    return -1;

}

void Xprobe_Module_Hdlr::display_mod_names(void) {

    xprobe_module_func_t *ptr;
    int cnt = 1;

    ptr = mod_init_funcs;
    while (ptr !=NULL && ptr->name !=NULL && ptr->func != NULL) {
/*
	    ui->msg("%s%c", ptr->name, cnt%4?'\t':'\n');
	    ptr++;
	    cnt++;
*/
		ui->msg("[%d] %s\n", cnt++, ptr->name);
		ptr++;

	}
}




Xprobe_Module_Hdlr::Xprobe_Module_Hdlr(void) {
    mod_counter = 0;
    keywords = 0;
}

Xprobe_Module_Hdlr::~Xprobe_Module_Hdlr(void) {
    /* do nothing now */
}

int Xprobe_Module_Hdlr::get_module_count() {
	int modcount=0;
	xprobe_module_func_t *ptr;

    ptr = mod_init_funcs;
    while (ptr !=NULL && ptr->name !=NULL && ptr->func != NULL) {
		modcount++;
		ptr++;
	}
	return modcount;
}
