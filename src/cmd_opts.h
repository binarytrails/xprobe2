/* $Id: cmd_opts.h,v 1.14 2005/02/14 18:05:17 mederchik Exp $ */
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

#ifndef CMD_OPTS_H
#define CMD_OPTS_H

#include "xprobe.h"
#include "target.h"
/*
#include <map>
#include <string>
#include <vector>
*/

using namespace std;

class Cmd_Opts {
    private:
        Xprobe::Timeval receive_timeout;
        Xprobe::Timeval send_delay;
        char verbose;
        bool modules_disable_used, modules_enable_used;
        char flags;
        char *logfile;
        char *config_file;
        char *default_config_file;
        unsigned long debuglevel;
        char *target;
		bool showroute, portscan, rtt_forced, sgen, xml, brute_force_tcp_ports, analyze_samples;
		map <int, char> tcp_ports;
		map <int, char> udp_ports;
		vector <Port_Range> tcp_ports_toscan;
		vector <Port_Range> udp_ports_toscan;
		int *mods;
		int numofmatches;
		int parse_port(char *);
		int parse_range(char *, vector<Port_Range> *);
    public:
        Cmd_Opts(void);
        int is_verbose(void);
        unsigned long debug(void);
        Xprobe::Timeval& get_timeout(void);
        Xprobe::Timeval& get_send_delay(void);
        char *get_target(void);
        char *get_configfile(void);
		char *get_logfile(void);
        int parse(int argc, char *argv[]);
        void usage(char *);
		bool show_route(void);
		map <int, char> *get_tcp_ports(void);
		map <int, char> *get_udp_ports(void);
		bool mod_is_disabled(int);
		int get_numofmatches();
		bool do_portscan() { return portscan; }
        bool is_rtt_forced() { return rtt_forced; }
		bool generate_sig() { return sgen; }
		bool do_xml();
		bool tcp_port_brute();
		bool analyze_packets() { return analyze_samples; }
		vector<Port_Range> *get_tcp_ports_to_scan() { return &tcp_ports_toscan; }
		vector<Port_Range> *get_udp_ports_to_scan() { return &udp_ports_toscan; }
};


extern char *optarg;
extern int optind;

#endif /* CMD_OPTS_H */
