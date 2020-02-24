/* $Id: target.h,v 1.13 2005/06/23 11:53:50 mederchik Exp $ */
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

#ifndef TARGET_H
#define TARGET_H

#include "xprobe.h"

using namespace std;

extern int h_errno;

class Target_Net {
    private:
        unsigned long addr, mask, counter;
        char *ascii_name;
        int parse_mask(char *mask);
        int parse_host(char *host);
        int resolve_host(char *host);
    public:
        int init(char *target);
        unsigned long getnext(void);
        void reset(void) { counter = addr; };
        Target_Net(void);
        Target_Net(char *target);
        ~Target_Net() { free(ascii_name); };
};


#define XPROBE_TTL_TCP_SYNACK   1
#define XPROBE_TTL_TCP_RST      2
#define XPROBE_TTL_ICMP_ECHO    3
#define XPROBE_TTL_ICMP_PUNR    4

class Port_Range {
	private:
		vector <int> ports;
		u_int low, high, curr;
	public:
		void set_range(u_short, u_short);
		int get_next(u_short *);
        unsigned int size() { return (high - low + 1); }
		void reset();
};

class Signature {
	private:
		map<string, string> key_val;
		string header;
	public:
		Signature(void) { header="fingerprint {\n\tOS_ID =\n\t#Entry inserted to the database by:\n"
								 "\t#Entry contributed by:\n\t#Date:\n\t#Modified:\n"; }
		void append_sig(string key, string val) {  key_val.insert(pair<string, string>(key, val)); }
		void print_sig(void);
		string get_sig(int *);
		void signull(void) { key_val.clear(); } 
};
class Target {
    private:
        struct in_addr addr;
		long send_delay; // delay in microsecs when sending packs
        map <int, char> tcp_ports;
        map <int, char> udp_ports;
        map <int, char> protocols;
		vector <Port_Range> tcp_toscan;
		vector <Port_Range> udp_toscan;
        map <int, int> ttls;
        int distance; /* ttl sets it */
        Xprobe::Timeval rtt; /* round-trip time */
		Signature fingerprint;
		bool showroute, gen_sig;
        //void add_p(map <int, char> &, int, char);
        void add_p(map <int, char> *, int, char);
        //int find_stat_p(map <int, char> &, char);
        int find_stat_p(map <int, char> *, char);
   public:
    Target(void) { addr.s_addr = INADDR_NONE; gen_sig = showroute = false; send_delay = distance = 0; rtt = 0.0; }
    Target(struct in_addr a) { set_addr(a); gen_sig = showroute = false; send_delay = distance = 0; rtt = 0.0; }
    Target(unsigned long int a) { addr.s_addr = a; gen_sig = showroute = false; send_delay = distance = 0; rtt = 0.0; }
    void set_addr(struct in_addr a) {
        memcpy((void *)&addr, (void *)&a, sizeof(struct in_addr));     
    }
    struct in_addr get_addr(void) { return addr; }
    /*              protocol, port, status */
    void add_port(int , int , char );
    /*                  protocol, status */
    void add_protocol(int , char );
    int get_port(int, int);
    struct in_addr get_interface_addr(void);
    char *get_interface(void);
    /* Scan_Engine interface */
    int check_alive(void);
    int os_probe(void);
    void set_distance(int d) { distance = d; }
    int get_distance(void) { return distance; }
    void set_rtt(Xprobe::Timeval& t) { rtt = t; }
    Xprobe::Timeval& get_rtt(void) { return rtt; }
    void set_ttl(int, int);
    int get_ttl(int);
	void set_delay(long k) { send_delay = k; }
	long get_delay(void) { return send_delay; }
   	bool show_route(void) { return showroute; } 
	void show_route(bool sr) { showroute = sr; }
	void set_tcp_ports (map <int, char> *tp);
	void set_udp_ports (map <int, char> *up);
	void set_tcp_toscan(vector<Port_Range> *tr) { tcp_toscan = *tr; }
	void set_udp_toscan(vector<Port_Range> *ur) { udp_toscan = *ur; }
	vector<Port_Range> *get_tcp_toscan() { return &tcp_toscan; }
	vector<Port_Range> *get_udp_toscan() { return &udp_toscan; }
	int gather_info(void);
	void generate_sig(bool val) { gen_sig = val; }
	bool generate_sig(void) { return gen_sig; }
	string signature(void);
	void signature(string& key, string& val);
	void signature(const char *, const char *);
	void signull(void) { fingerprint.signull(); }
	bool port_is_open(int proto, int port);
};

#endif /* TARGET_H */
