/* $Id: config_set.h,v 1.8 2005/07/21 11:42:31 mederchik Exp $ */
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

#ifndef CONFIG_SET_H
#define CONFIG_SET_H

#include "xprobe.h"
/*
#include <string>
#include <map>
#include <vector>
*/

using namespace std;

#define XP_CONFIG_LINEMAX       2048
#define XP_CONFIG_TK_EMPTY      1
#define XP_CONFIG_TK_SECBEGIN   2
#define XP_CONFIG_TK_SECEND     3
#define XP_CONFIG_TK_KEYVAL     4
#define XP_CONFIG_TK_OPT        5

class Config_Line {
    private:
        string line;
        int errors;
    public:
        const string trim_comments( string &l);
        const string trim_whitespc( string &l);
        Config_Line(void) { errors = 0; line = "BUG"; /* for troubleshooting */ return; };
        Config_Line(const string &l) : line(l) { errors = 0; }
        // Config_Line(const Config_Line &cf) { line = cf.get_line(); line_num = cf.get_linenum(); }
        int read_line(FILE *fd);
        int get_tokid(void);
        void inc_error(void) { errors++; }
        int get_error(void) { return errors; }
        const string get_line(void) { return line; }
};

class Config_SectionB: public Config_Line {
    private:
        string sec_name;
    public:
        Config_SectionB(const string &l);
        const string get_secname(void) { return sec_name; }
};

class Config_KeyVal: public Config_Line {
    private:
        string key;
        string val;
     public:
        Config_KeyVal(const string &l);
        const string get_key(void) { return key; }
        const string get_val(void) { return val; }   
};
        
class Config_File;        

class Config_Section  {
    private:
        Config_File *cf;
        string sec_name;
        int state;
        map<string, string> key_val;
        map<string, string>::iterator kv_i;
        vector<string> options;

        void set_secname(const string &s) { sec_name = s; }
        void add_key_val(const string &key, const string &val);
        int get_state(void) { return state; }
        void set_state(int st) { state = st; }
        void set_option(const string &opt);
    public:
        Config_Section(Config_File *c) { cf = c; state=0; }
        int read_sec(void);
        void reset_key(void) { kv_i = key_val.begin(); }
        int set_nextkey(void);
        const string get_nextkey(void) { return (*kv_i).first; }
        const string get_nextval(void) { return (*kv_i).second; }
        int find_key(const string &k);
        const char *get_secname(void) { return sec_name.c_str(); }
        const string gets_secname(void) { return sec_name; }
};
           
        
class Config_Set;

class Config_File {
    private:
        string filename;
        FILE *fd;
        int line_num;
        Config_Set *cfset;
    public:
        Config_File(Config_Set *);
        FILE *get_fd(void) { return fd; }
        int process(char *);
        int process_generic(Config_Section *);
        int process_fingerprint(Config_Section *);
        int open_cfg(void);
        int close_cfg(void);
        void inc_line(void) { line_num++; }
        int get_linenum(void) { return line_num; }
};
        

class Config_Set {
    private:
        Config_File *cf;
        int timeout;
		bool showroute;
        map <int, char> *tcp_ports;
        map <int, char> *udp_ports;
		string comstrings;
    public:
        Config_Set();
        ~Config_Set(void);
        void set_timeout(int t) { timeout = t; }
        int  get_timeout(void) { return timeout; }
        int read_config(char *);
		bool show_route(void) { return showroute; }
		void show_route(bool sr) { showroute = sr; }
		map <int, char> *get_tcp_ports(void) { return tcp_ports; }
		map <int, char> *get_udp_ports(void) { return udp_ports; }
		void set_tcp_ports(map <int, char> *tp) { tcp_ports = tp; }
		void set_udp_ports(map <int, char> *up) { udp_ports = up; }
		void set_comstrings(string v) { comstrings = v; }
		string get_comstrings(void) { return comstrings; }
};

#endif /* CONFIG_SET_H */
