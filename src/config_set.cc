/* $Id: config_set.cc,v 1.6 2005/07/21 11:42:31 mederchik Exp $ */
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
#include "config_set.h"
#include "interface.h"
#include "os_matrix.h"
#include "xprobe_module_hdlr.h"

extern Interface *ui;
extern OS_Name   *oses;
extern Xprobe_Module_Hdlr     *xmh;

int Config_Line::read_line(FILE *fd) {
    char *buf;
    
    buf = (char *)calloc(XP_CONFIG_LINEMAX+1, 1); 

    if ((buf = fgets(buf, XP_CONFIG_LINEMAX, fd)) == NULL)
        return FAIL; /* EOF or whatever */
    line = buf;
    free(buf);
    line = trim_comments(line);
    line = trim_whitespc(line);
    return OK;
}


const string Config_Line::trim_comments(string &l) {
    int p;

    p = l.find('#', 0);
    if (p != -1) 
        l.replace(p, l.length() - p, "");
    
    return l;
}


const string Config_Line::trim_whitespc(string &l) {
    unsigned int p;

    p = l.find_first_not_of("\n\r\t\v ");
    if (p != string::npos) 
        l.replace(0, p, "");
        
    p = l.find_last_not_of("\n\r\t\v ");
    if (p != string::npos) 
        l.replace(p + 1, l.length() - p, "");
 
    return l;
}


int Config_Line::get_tokid(void) {

    if (line.length() == 0) return XP_CONFIG_TK_EMPTY;
    if (line.find('{') != string::npos) return XP_CONFIG_TK_SECBEGIN;
    if (line.find('}') != string::npos) return XP_CONFIG_TK_SECEND;
    if (line.find('=') != string::npos) return XP_CONFIG_TK_KEYVAL;
    /* non empty line without these characters is either garbage
     * or option. Let Config_File deal with it.
     */
    return XP_CONFIG_TK_OPT;
} 



Config_SectionB::Config_SectionB(const string &l): Config_Line(l) {
   unsigned int p;
    
    p = l.find_first_of(" \n\r\t\v{");
    if (p != string::npos)
        sec_name = l.substr(0, p);
}


Config_KeyVal::Config_KeyVal(const string &l): Config_Line(l) {
   unsigned int p;
    
    p = l.find_first_of(" \n\r\t\v=");
    if (p != string::npos)
        key = l.substr(0, p);
    else {
        ui->error("corrupted string!");
        inc_error();
        return;
    }
            
    // get value
    p = l.find_first_of("=");

    if (p != string::npos) {
        val = l.substr(p + 1, l.length());
        val = trim_whitespc(val);
    } else {
        ui->error("corrupted string!");
        inc_error();
        return;
    }
    xprobe_debug(XPROBE_DEBUG_CONFIG, "\tkey = %s val = %s\n", key.c_str(), val.c_str());

}



int Config_Section::set_nextkey(void) {

    if (kv_i == key_val.end()) return FAIL;
    kv_i++;
    if (kv_i == key_val.end()) return FAIL;

    return OK;
}


int Config_Section::read_sec(void) {
    Config_Line line;

    while ((line.read_line(cf->get_fd())) == OK) {
        cf->inc_line();
        switch (line.get_tokid()) {
            case XP_CONFIG_TK_EMPTY:
                /* do nothing */
                break;

            case XP_CONFIG_TK_SECBEGIN:
            {
                if (get_state() != 0) {
                    ui->error("[x] Multiple open sections on line %i(%s)\n",
                    cf->get_linenum(), line.get_line().c_str());
                    return FAIL;
                }
                set_state(XP_CONFIG_TK_SECBEGIN);
                Config_SectionB  sec(line.get_line());
                set_secname(sec.get_secname());
            }
                break;

            case XP_CONFIG_TK_SECEND:
                if (get_state() != XP_CONFIG_TK_SECBEGIN) {
                    ui->error("[x] Multiple close sections on line: %i\n", cf->get_linenum());
                    return FAIL;
                }
                set_state(0);
                return OK; /* read a section */
                break;
            case XP_CONFIG_TK_KEYVAL:
            {
                Config_KeyVal kw(line.get_line());
                add_key_val(kw.get_key(), kw.get_val());
                /* section parse here..call parse stuff */
            }
                break;     
            case XP_CONFIG_TK_OPT:
                set_option(line.get_line());
                break;
            default:
                ui->error("unknown token!\n");    
        }/* case */
    } /* while */
    return FAIL; /* EOF or somtheing */
}

void Config_Section::add_key_val(const string &key, const string &val) {

    key_val.insert(pair<string, string>(key, val));

}

void Config_Section::set_option(const string &opt) {
    
    options.push_back(opt);
}

int Config_Section::find_key(const string &k) { 
    kv_i = key_val.find(k);
    if (kv_i == key_val.end()) return FAIL;
    return OK;
}


int Config_File::open_cfg(void) {
    
    if ((fd = fopen(filename.c_str(), "r")) == NULL)  {
        ui->error("error opening %s: %s\n", filename.c_str(),
                    strerror(errno));
        return FAIL;
    }
    return OK;
}

int Config_File::close_cfg(void) {

    if (fclose(fd) != 0) {
        ui->perror("fclose");
        return FAIL;
    }
    return OK;
}

int Config_File::process(char *fname) {

    filename = fname;
    if (open_cfg() != OK) {
        ui->error("failed to open config file: %s\n", fname);
        return FAIL;
    }
    for(;;) {
        Config_Section *sec = new Config_Section(this);
        if (sec->read_sec() != OK) break;
        xprobe_debug(XPROBE_DEBUG_CONFIG,"\tSECTION %s\n", sec->get_secname());
        /* process the file */
        if (!strcasecmp(sec->get_secname(),"GENERIC")) {
            xprobe_mdebug(XPROBE_DEBUG_CONFIG, "Parsing generic options\n");
            process_generic(sec);
        } else if (!strcasecmp(sec->get_secname(), "FINGERPRINT")) {
            xprobe_mdebug(XPROBE_DEBUG_CONFIG, "Parsing fingerprint\n");
            process_fingerprint(sec);
        } else {
            ui->error("[%s:%i]: Unknown section tag %s\n",
                       filename.c_str(), get_linenum(), sec->get_secname());
        }
        delete sec;

    }
    if (close_cfg() != OK) {
        ui->error("failed to close config file: %s\n", fname);
        return FAIL;
    }
 
    return OK;
}

int Config_File::process_generic(Config_Section *sec) {
    
    sec->reset_key();
    do {
        string key, val;
        key = sec->get_nextkey();
        val = sec->get_nextval();

        /* set generic options here */
        if (key == "timeout") cfset->set_timeout(atoi(val.c_str()));
		if (key == "community_strings") cfset->set_comstrings(val);
        
        xprobe_debug(XPROBE_DEBUG_CONFIG,"\t\tKEY %s VAL %s\n",
                key.c_str(), val.c_str());
    } while(sec->set_nextkey() != FAIL);
  return OK;  
}


int Config_File::process_fingerprint(Config_Section *sec) {
    int current_osid = -1;
    
    sec->reset_key();
    do {
        string key, val;
        key = sec->get_nextkey();
        val = sec->get_nextval();
        if (key == "OS_ID") {
            if((current_osid = oses->add_os(val)) == FAIL) {
                ui->error("[%s:%i]: Dublicate signature for %s\n",
                        filename.c_str(), get_linenum(), val.c_str());
                return FAIL;
            }
            
        } else {
            if (current_osid == -1) {
                ui->error("[%s:%i]: keyword %s appears before OS_ID\n",
                        filename.c_str(), get_linenum(), val.c_str());
                return FAIL;
            }
            Xprobe_Module *mod;
            if ((mod = xmh->find_mod(key)) == NULL) {
                xprobe_debug(XPROBE_DEBUG_CONFIG,
                        "[x][%s:%i] No active module handles: %s keyword\n",
                        filename.c_str(), get_linenum(), key.c_str());
            } else {
                mod->parse_keyword(current_osid, key.c_str(), val.c_str());
            }
        } /* else OS_ID */

        xprobe_debug(XPROBE_DEBUG_CONFIG,"\t\tKEY %s VAL %s\n",
                key.c_str(), val.c_str());
    } while(sec->set_nextkey() != FAIL);
  return OK;  
}


Config_File::Config_File(Config_Set *cfs) {
    
    line_num = 0;
    fd = NULL;
    cfset = cfs;
}

Config_Set::Config_Set(void) {

    cf = new Config_File(this);
	showroute = false;    
}

int Config_Set::read_config(char *fname) {
    return (cf->process(fname));
}

Config_Set::~Config_Set(void) {

    delete cf;
}
