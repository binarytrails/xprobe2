/*
** Copyright (C) 2003 Meder Kydyraliev <meder@areopag.net>
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

#ifndef PORTSCAN_MOD_H
#define PORTSCAN_MOD_H

#include "xprobe.h"
#include "xprobe_module.h"

#define TIMEOUT 2
#define LISTENTIMEOUT 1

class Portscanner: public Xprobe_Module {
    private:
		class packet_sample {
			private:
				TCP pack;
				int counter;
			public:
				packet_sample(void) { counter = 0; /*pack = NULL;*/ }
				void incr(void) { counter++; }
				void set_pack(TCP _pack) { 
					pack = _pack;
				}
				TCP get_pack(void) { 
					return pack; 
				}
				int get_counter(void) { return counter; }
		};
        Xprobe::Timeval send_delay;
		int tcpopen, tcpclosed, tcpfiltered;
		int udpopen, udpclosed, udpfiltered;
		unsigned int tcpportnum, udpportnum;
		int send_packets(Target *);
		int receive_packets(Target *);
		map <int, char> tcp_ports;
		map <int, char> udp_ports;
		vector<Port_Range> tcpport;
		vector<Port_Range> udpport;
		multimap <int, packet_sample> packet_samples;
		char get_ignore_state(int proto);
		int analyze_packet(TCP&);
		void analyze_packets(void);
		typedef multimap<int, packet_sample>::iterator multimap_iter;
    public:
        Portscanner(void) : Xprobe_Module(XPROBE_MODULE_INFOGATHER, "infogather:portscan", "TCP and UDP PortScanner") { 
			send_delay=tcpopen=tcpclosed=tcpfiltered=udpopen=udpclosed=udpfiltered=tcpportnum=udpportnum=0;
		}
        ~Portscanner(void) { return; }
        int init(void);
        int parse_keyword(int, const char *, const char *) { return OK; }
        int exec(Target *, OS_Matrix *);
        int fini(void);
};

#endif /* TEST_MOD_H */
