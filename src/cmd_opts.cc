/* $Id: cmd_opts.cc,v 1.20 2005/02/14 18:25:12 mederchik Exp $ */
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
#include "cmd_opts.h"
#include "interface.h"
#include "xprobe_module_hdlr.h"
#include "xplib/xplib.h"

extern Interface *ui;
extern Xprobe_Module_Hdlr *xmh;

int Cmd_Opts::is_verbose(void) {
    return verbose;
}

unsigned long Cmd_Opts::debug(void) {
    return debuglevel;
}
Xprobe::Timeval& Cmd_Opts::get_send_delay(void) {
    return send_delay;
}
Xprobe::Timeval& Cmd_Opts::get_timeout(void) {
    return receive_timeout;
}
char *Cmd_Opts::get_target(void) {
    return target;
}

char *Cmd_Opts::get_configfile(void) {
    if (config_file)
        return config_file;
   else
       return default_config_file;
}

char *Cmd_Opts::get_logfile(void) {
	return logfile;
}

bool Cmd_Opts::do_xml(void) {
	return xml;
}

bool Cmd_Opts::tcp_port_brute(void) {
	return brute_force_tcp_ports;
}

int Cmd_Opts::parse(int argc, char *argv[]) {
    int c, modcount = xmh->get_module_count(), mod_to_disable, mod_to_enable;

    if ((mods = new int[modcount]) == NULL) {
        ui->error("Cmd_Opts::parse: memory allocation failed\n");
        return FAIL;
    }
    // initialize each module entry to be enabled 
    for (c=0; c < modcount; c++) {
		if (xmh->mod_disabled_by_default(c)) 
			mods[c] = XPROBE_MODULE_DISABLED;
		else
			mods[c] = XPROBE_MODULE_ENABLED;
	}

    while((c = getopt(argc, argv, "vi:p:ho:t:d:c:rD:m:M:PT:U:s:fLFXBA")) !=EOF) 
        switch(c) {
            case 'd':
                debuglevel = atol(optarg);
                break;
            case 'v':
                verbose++;
                break;
            case 'o':
                logfile = optarg;    
                break;
            case 'c':
                config_file = optarg; 
                break;
            case 's':
                send_delay = atof(optarg);
                break;     
            case 't':
                receive_timeout = atof(optarg);    
                if ((double)receive_timeout <0) {
                    ui->error("Incorrect receive timeout %s\n", optarg);
                    usage(argv[0]);
                }
                break;
	    	case 'L':
				ui->msg("Following modules are available (by keyword)\n");
				xmh->display_mod_names();
				ui->msg("\n\n");
				usage(argv[0]);
				break; 
            case 'r':
                showroute = true;
                break;
            case 'p':
                if (parse_port(optarg) < 0)
                    usage(argv[0]);
                break;
            case 'D':
                if (modules_enable_used) {
                    ui->error("-D and -M options are not compatible\n");
                    usage(argv[0]);
                }
                if (!modules_disable_used) {
                    for (c=0; c < modcount; c++) mods[c] = XPROBE_MODULE_ENABLED;
                    modules_disable_used = true;
                }
                errno = 0;
		if ((mod_to_disable = xmh->modbyname(optarg)) == -1)
			mod_to_disable = strtol(optarg, NULL, 0);
                if (errno == ERANGE && (mod_to_disable == LONG_MAX || mod_to_disable == LONG_MIN)) {
                    ui->error("Incorrect module number specified %s\n", optarg);
                    usage(argv[0]);
                } else if (mod_to_disable < 1 || mod_to_disable > modcount) {
                    ui->error("Module number %d is incorrect, must be in range from 1 to %d\n",mod_to_disable, modcount);
                    usage(argv[0]);
                }
                mods[mod_to_disable-1] = XPROBE_MODULE_DISABLED;    
                break;
                
            case 'M':
                if (modules_disable_used) {
                    ui->error("-D and -M options are not compatible\n");
                    usage(argv[0]);
                }
                if (!modules_enable_used) {
                    for (c=0; c < modcount; c++) mods[c] = XPROBE_MODULE_DISABLED;
                    modules_enable_used = true;
                }
                errno = 0;
		if ((mod_to_enable = xmh->modbyname(optarg)) == -1)
			mod_to_enable = strtol(optarg, NULL, 0);
                if (errno == ERANGE && (mod_to_enable == LONG_MAX || mod_to_enable == LONG_MIN)) {
                    ui->error("Incorrect module number specified %s\n", optarg);
                    usage(argv[0]);
                } else if (mod_to_enable < 1 || mod_to_enable > modcount) {
                    ui->error("Module number %d is incorrect, must be in range from 1 to %d\n",mod_to_enable, modcount);
                    usage(argv[0]);
                }
                mods[mod_to_enable-1] = XPROBE_MODULE_ENABLED;    
                break;
    
            case 'm':
                errno = 0;
                numofmatches = strtol(optarg, NULL, 0);
                if (errno == ERANGE && (numofmatches == LONG_MAX || numofmatches == LONG_MIN)) {
                    ui->error("Incorrect number of matches to display specified %s\n", optarg);
                    usage(argv[0]);
                } else if (numofmatches < 1) {
                    ui->error("Are you sure you know what this program is doing? Number of matches must be greater than 0\n");
                    usage(argv[0]);
                }
                break;
            case 'T':
                if (parse_range(optarg, &tcp_ports_toscan)) {
                    ui->msg("-T syntax error: %s\n", optarg);
                    usage(argv[0]);
                }
				portscan = true;
                break;
            case 'U':
                if (parse_range(optarg, &udp_ports_toscan)) {
                    ui->msg("-U syntax error: %s\n", optarg);
                    usage(argv[0]);    
                }
				portscan = true;
                break;
            case 'f':
                rtt_forced = true;
                break;    
			case 'F':
				sgen = true;
				break;
			case 'X':
				xml = true;
				break;
			case 'B':
				brute_force_tcp_ports = true;
				break;
			case 'A':
				analyze_samples = true;
				break;
            case 'h':
            default:
                usage(argv[0]);
        }
	/* need here a method that will track comand line options dependencies */
	if (xml && !logfile) {
		ui->msg("-X you need to specify output file with -o\n");
		usage(argv[0]);
	}
	if (analyze_samples && !portscan)
		usage(argv[0]);

    if (argc < optind + 1)
        usage(argv[0]);
    target = argv[optind];    

return 1;
}

void Cmd_Opts::usage(char *progname) {

    ui->error("usage: %s [options] target\n", progname);
    ui->error("Options:\n");
    ui->error("          -v                       Be verbose\n");
    ui->error("          -r                       Show route to target(traceroute)\n");
    ui->error("          -p <proto:portnum:state> Specify portnumber, protocol and state.\n");
    ui->error("                                   Example: tcp:23:open, UDP:53:CLOSED\n");
    ui->error("          -c <configfile>          Specify config file to use.\n");
    ui->error("          -h                       Print this help.\n");
    ui->error("          -o <fname>               Use logfile to log everything.\n");
    ui->error("          -t <time_sec>            Set initial receive timeout or roundtrip time.\n");
    ui->error("          -s <send_delay>          Set packsending delay (milseconds).\n");
    ui->error("          -d <debuglv>             Specify debugging level.\n");
    ui->error("          -D <modnum>              Disable module number <modnum>.\n");
    ui->error("          -M <modnum>              Enable module number <modnum>.\n");
    ui->error("          -L                       Display modules.\n");
    ui->error("          -m <numofmatches>        Specify number of matches to print.\n");
    ui->error("          -T <portspec>            Enable TCP portscan for specified port(s).\n");
    ui->error("                                   Example: -T21-23,53,110\n");
    ui->error("          -U <portspec>            Enable UDP portscan for specified port(s).\n");
    ui->error("          -f                       force fixed round-trip time (-t opt).\n");
    ui->error("          -F                       Generate signature (use -o to save to a file).\n");
    ui->error("          -X                       Generate XML output and save it to logfile specified with -o.\n");
    ui->error("          -B                       Options forces TCP handshake module to try to guess open TCP port\n");
	ui->error("          -A                       Perform analysis of sample packets gathered during portscan in\n");
	ui->error("                                   order to detect suspicious traffic (i.e. transparent proxies,\n");
   	ui->error("                                   firewalls/NIDSs resetting connections). Use with -T.\n");
    exit(1);
}

bool Cmd_Opts::show_route(void) {

    return showroute;
}

int Cmd_Opts::parse_port (char *portptr) {

    string portstr(portptr);
    int iportnum = 0; 
    char istate = 0;
    vector<string> tokens;

    /* max len = strlen("tcp:65535:closed"); */
    if (portstr.length() > 16) {
        ui->error("-p syntax error (toolong ?)\n");
        return FAIL;    
    }

    if(xp_lib::tokenize(portptr, ':', &tokens)) {
        ui->error("Error tokenizing\n");
        return FAIL;
    }
    if (tokens.size() != 3){    /* either not enough or too many */
        ui->error ("-p syntax error (Not enought or too many \":\"\'s? %d)\n", tokens.size());
        return FAIL;    
    }
    if (!(iportnum = atoi(tokens[1].c_str())) || iportnum > 65535 || iportnum < 1) {
        ui->error("-p syntax error (Incorrect port number specification)\n");
        return FAIL;
    }
    
    if (!strncasecmp(tokens[2].c_str(), "open", 4))
        istate = XPROBE_TARGETP_OPEN;
    else if (!strncasecmp(tokens[2].c_str(), "closed", 6))
        istate = XPROBE_TARGETP_CLOSED;
    else  {
        ui->error("-p syntax error (Unknown port state)\n");
        return FAIL;
    }

    if (!strncasecmp(tokens[0].c_str(), "tcp", 3)) 
        tcp_ports.insert(pair<int, char>(iportnum, istate));
    else if (!strncasecmp(tokens[0].c_str(), "udp", 3))
        udp_ports.insert(pair<int, char>(iportnum, istate));
    else {
        ui->error("-p syntax error (Unknown protocol)\n");
        return FAIL;
    }

    return OK;
    
}

map <int, char> *Cmd_Opts::get_tcp_ports(void) {

    return &tcp_ports;

}

map <int, char> *Cmd_Opts::get_udp_ports(void) {

    return &udp_ports;
}

Cmd_Opts::Cmd_Opts(void) {

    receive_timeout = DEF_TIMEOUT;
    send_delay = DEF_SEND_DELAY;
    verbose = 0;
    flags = 0;
    logfile = NULL;
    config_file = NULL;
    default_config_file = DEFAULT_CONFIG;
    debuglevel = DEFAULT_DEBUG_LEVEL;
    target = NULL;
    showroute = false;
    numofmatches = DEFAULT_MATCHES;
    portscan = false;
    rtt_forced = false;
    modules_disable_used = modules_enable_used = analyze_samples = false;
	sgen = false;
	xml = false;
	brute_force_tcp_ports = false;
}

bool Cmd_Opts::mod_is_disabled(int modnum) {

    if (modnum > 0 && modnum <= xmh->get_module_count())
        if (mods[modnum-1])
            return true;
    return false;
}

int Cmd_Opts::get_numofmatches() {

    return numofmatches;
}

int Cmd_Opts::parse_range(char *arg, vector<Port_Range> *vec) {
    Port_Range range;
    vector<string> tokens, range_tokens;
    u_short hi, lo;
    unsigned int k;
    /* first we need to split
     * the input into entries 
     * separated by commas, 
     * then we parse each entry
     * and see if range was
     * specified
     */
    if (xp_lib::tokenize(arg, ',', &tokens)) {
        ui->msg("Cmd_Opts::parse_range() something went wrong!\n");
        return FAIL;
    }
    for (k=0; k < tokens.size(); k++) {
        if (tokens[k].find_first_of('-') == string::npos) {
            //not a range just a simple port spec
            errno = 0;
            lo = strtol(tokens[k].c_str(), NULL, 0);
            if (errno == ERANGE || lo == 0)
                return FAIL;
            range.set_range(lo, lo);
            vec->push_back(range);
        } else {
            //range specified
            //tokenize it 
				xp_lib::tokenize(tokens[k].c_str(), '-', &range_tokens);
            if (range_tokens.size() != 2) 
                return FAIL;
            errno = 0;
            lo = strtol(range_tokens[0].c_str(), NULL, 0);
            if (errno == ERANGE || lo == 0) 
                return FAIL;
            errno = 0;
            hi = strtol(range_tokens[1].c_str(), NULL, 0);
            if (errno == ERANGE || hi == 0)
                return FAIL;
            range.set_range(lo, hi);
            vec->push_back(range);
        }
    }
    return OK;
}
