#include "xprobe.h"
#include <stdarg.h>
#include "interface.h"
#include "cmd_opts.h"
#include "xprobe_module.h"
#include "log.h"

int Log::write(const char *fmt, ...) {
	va_list va;

	va_start(va, fmt);
	if (logopened) 
		return vfprintf(ofile, fmt, va);
	else
		return 0;
}

int Log::open() {
	if ((ofile = fopen(logfile.c_str(), "w")) == NULL) {
		ui->msg("fopen(): %s\n", strerror(errno));
		return 1;
	}
	logopened = true;
	return 0;
}

int XML_Log::log(unsigned int type, const char *fmt, ...) {
	va_list varg;
	va_start(varg, fmt);
	if (!is_opened())
		return 0;
	switch(type) {
		case XPROBELOG_XP_SESS_START:
			write_tabs();
			tags_opened++;
			log_start(fmt, varg);
			break;
		case XPROBELOG_MSG_RUN:
			write_tabs();
			log_run(fmt, varg);
			break;
		case XPROBELOG_MOD_SESS_START:
			write_tabs();
			tags_opened++;
			if (fmt)
				write("<modules caption=\"%s\">\n", fmt);
			break;
		case XPROBELOG_MSG_MODULE:
			write_tabs();
			log_module(fmt, varg);
			break;
		case XPROBELOG_MOD_SESS_END:
			tags_opened--;
			write_tabs();
			write("</modules>\n");
			break;
		case XPROBELOG_TG_SESS_START:
			write_tabs();
			tags_opened++;
			log_target(fmt, varg);
			break;
		case XPROBELOG_REACH_SESS_START:
			write_tabs();
			tags_opened++;
			write("<reachability>\n");
			break;
		case XPROBELOG_MSG_STATE:
			write_tabs();
			log_state(fmt, varg);
			break;
		case XPROBELOG_MSG_RTT:
			write_tabs();
			log_rtt(fmt, varg);
			break;
		case XPROBELOG_REACH_SESS_END:
			tags_opened--;
			write_tabs();
			write("</reachability>\n");
			break;
		case XPROBELOG_INFO_SESS_START:
			write_tabs();
			tags_opened++;
			write("<information_gathering>\n");
			break;
		case XPROBELOG_PS_SESS_START:
			write_tabs();
			tags_opened++;
			log_pscan(fmt, varg);
			break;
		case XPROBELOG_STATS_SESS_START:
			write_tabs();
			tags_opened++;
			write("<stats>\n");
			break;
		case XPROBELOG_MSG_PS_TCPST:
			write_tabs();
			log_port_stats(6, fmt, varg);
			break;
		case XPROBELOG_MSG_PS_UDPST:
			write_tabs();
			log_port_stats(17, fmt, varg);
			break;
		case XPROBELOG_STATS_SESS_END:
			tags_opened--;
			write_tabs();
			write("</stats>\n");
			break;
		case XPROBELOG_PSDET_SESS_START:
			write_tabs();
			tags_opened++;
			write("<details>\n");
			break;
		case XPROBELOG_MSG_PORT:
			write_tabs();
			log_port(fmt, varg);
			break;
		case XPROBELOG_PSDET_SESS_END:
			tags_opened--;
			write_tabs();
			write("</details>\n");
			break;
		case XPROBELOG_PS_SESS_END:
			tags_opened--;
			write_tabs();
			write("</portscan>\n");
			break;
		case XPROBELOG_INFO_SESS_END:
			tags_opened--;
			write_tabs();
			write("</information_gathering>\n");
			break;
		case XPROBELOG_GUESS_SESS_START:
			write_tabs();
			tags_opened++;
			write("<os_guess>\n");
			break;
		case XPROBELOG_MSG_PRIMARY:
		case XPROBELOG_MSG_SECONDARY:
			write_tabs();
			log_guess(type, fmt, varg);
			break;
		case XPROBELOG_GUESS_SESS_END:
			tags_opened--;
			write_tabs();
			write("</os_guess>\n");
			break;
		case XPROBELOG_TG_SESS_END:
			tags_opened--;
			write_tabs();
			write("</target>\n");
			break;
		case XPROBELOG_XP_SESS_END:
			tags_opened--;
			write_tabs();
			write("</Xprobe2>");
			break;
		case XPROBELOG_OTHER_TCPP:
		case XPROBELOG_OTHER_UDPP:
			write_tabs();
			log_other_ports(type, fmt, varg);
			break;
		default:
			ui->error("Unknown XML message type %d\n", type);
			return FAIL;
	}
	return OK;
}

/* s-state */
int XML_Log::log_other_ports(char type, const char *fmt, va_list varg) {
	int st=-1;
	const char *state=NULL;

	while(*fmt)
		switch (*fmt++) {
			case 's':
				st = va_arg(varg, int);
				break;
		}
	if (st > -1) {
		switch(st) {
			case XPROBE_TARGETP_CLOSED:
				state="closed";
				break;
			case XPROBE_TARGETP_OPEN:
				state="open";
				break;
			case XPROBE_TARGETP_FILTERED:
				state="filtered";
				break;
			default:
				state = "unknown";
		}
		write("<other proto=\"%s\" state=\"%s\"/>\n", type == XPROBELOG_OTHER_TCPP ? "tcp" : "udp", state);
		return OK;
	} else
		return FAIL;
}

/* p-probability, s-caption */
int XML_Log::log_guess(int type, const char *fmt, va_list varg) {
	int prob=-1;
	char *os=NULL;
	const char *tp = type == XPROBELOG_MSG_PRIMARY ? "primary" : "secondary";
	
	while(*fmt)
		switch(*fmt++) {
			case 'p':
				prob = va_arg(varg, int);
				break;
			case 's':
				os = va_arg(varg, char *);
				break;
		}
	if (os && prob > -1) {
		write("<%s probability=\"%d\" unit=\"percent\"> %s </%s>\n", tp, prob, os, tp);
		return OK;
	} else
		return FAIL;
}

/*  n-number, p-proto, t-state, s-service */
int XML_Log::log_port(const char *fmt, va_list varg) {
	int portnum=-1, proto=-1, st=-1;
	char *state=NULL, *service=NULL;

	while (*fmt) 
		switch(*fmt++) {
			case 'n':
				portnum = va_arg(varg, int);
				break;
			case 'p':
				proto = va_arg(varg, int);
				break;
			case 't':
				st= va_arg(varg, int);
				break;
			case 's':
				service = va_arg(varg, char *);
				break;
		}
	if (service && portnum > -1 && proto > -1 && st > -1) {
		switch(st) {
			case XPROBE_TARGETP_CLOSED:
				state="closed";
				break;
			case XPROBE_TARGETP_OPEN:
				state="open";
				break;
			case XPROBE_TARGETP_FILTERED:
				state="filtered";
				break;
			default:
				state="unknown";
		}
		write("<port number=\"%d\" proto=\"%s\" state=\"%s\" service=\"%s\" />\n", portnum, proto==IPPROTO_TCP ? "tcp" : "udp", state, service);
		return OK;
	} else
		return FAIL;

}

/* o-open, c-closed, f-filtered */
int XML_Log::log_port_stats(char proto, const char *fmt, va_list varg) {
	int opn=-1, closed=-1, filtered=-1;

	while(*fmt) 
		switch(*fmt++) {
			case 'o':
				opn = va_arg(varg, int);
				break;
			case 'c':
				closed = va_arg(varg, int);
				break;
			case 'f':
				filtered = va_arg(varg, int);
				break;
		}
	if (opn > -1 && closed > -1 && filtered > -1) {
		write("<%s open=\"%d\" closed=\"%d\" filtered=\"%d\"/>\n", proto == 6 ? "tcp" : "udp", opn, closed, filtered);
		return OK;
	} else
		return FAIL;

}

int XML_Log::log_pscan(const char *fmt, va_list varg) {
	double duration=-1;

	while(*fmt)
		switch(*fmt++) {
			case 'd':
				duration = va_arg(varg, double);
				break;
		}
	if (duration > -1) {
		write("<portscan duration=\"P%.5fS\">\n", duration);
		return OK;
	} else
		return FAIL;
}

/* r-real, s-selected */
int XML_Log::log_rtt(const char *fmt, va_list varg) {
	double real=-1, selected=-1;

	while (*fmt)
		switch(*fmt++) {
			case 'r':
				real = va_arg(varg, double);
				break;
			case 's':
				selected = va_arg(varg, double);
				break;
		}
	if (real > -1 && selected > -1) {
		write("<rtt real=\"P%.5fS\" selected=\"P%.5fS\"/>\n", real, selected);
		return OK;
	} else 
		return FAIL;
}
/* s-state,p-probability */
int XML_Log::log_state(const char *fmt, va_list varg) {
	char *state=NULL;
	int prob=-1;

	while(*fmt)
		switch(*fmt++) {
			case 's':
				state = va_arg(varg, char *);
				break;
			case 'p':
				prob = va_arg(varg, int);
				break;
		}
	if (state && prob> -1) {
		write("<state state=\"%s\" probability=\"%d\" unit=\"percent\"/>\n", state, prob);
		return OK;
	} else
		return FAIL;
}

/* a-address */
int XML_Log::log_target(const char *fmt, va_list varg) {
	char *addr=NULL;
	
	while (*fmt)
		switch(*fmt++) {
			case 'a':
				addr = va_arg(varg, char *);
				break;
		}
	if (addr) {
		write("<target ip=\"%s\">\n", addr);
		return OK;
	} else
		return FAIL;
}

/* t-type, n-name, d-modnumber, s-caption */
int XML_Log::log_module(const char *fmt, va_list varg) {
	char *name=NULL, *caption=NULL;
	int modnum=-1, type=-1;
	const char *tp=NULL;

	while (*fmt) 
		switch(*fmt++) {
			case 't':
				type = va_arg(varg, int);
				break;
			case 'n':
				name = va_arg(varg, char *);
				break;
			case 'd':
				modnum = va_arg(varg, int);
				break;
			case 's':
				caption = va_arg(varg, char *);
				break;
		}
	if (type > -1 && name && caption && modnum > -1) {
		switch(type) {
			case XPROBE_MODULE_ALIVETEST:
				tp="reachability";
				break;
			case XPROBE_MODULE_OSTEST:
				tp ="fingerprinting";
				break;
			case XPROBE_MODULE_INFOGATHER:
				tp ="information gathering";
				break;
			default:
				tp="unknown";
		}
		write("<module type=\"%s\" name=\"%s\" number=\"%d\"> %s </module>\n", tp, name, modnum, caption);
		return OK;
	} else
		return FAIL;
}


/* c-count(argc), a-arguments(argv), d-datetime */
int XML_Log::log_run(const char *fmt, va_list varg) {
	char **argv=NULL;
   	time_t date=0;
	int argc=-1, k, hr, min;
	struct tm *tms=NULL;
	
	while(*fmt)
		switch(*fmt++) {
			case 'c':
				argc = va_arg(varg, int);
				break;
			case 'a':
				argv = va_arg(varg, char **);
				break;
			case 'd':
				date = va_arg(varg, time_t);
		}
	if (argv && date && argc > -1) {
		write("<run arguments=\"");
		for (k=0; k < argc; k++)
			write("%s ", argv[k]);
		tms = localtime(&date);
		// 2003-04-02T14:39:01-05:00
		if (tms) {
			hr = (tms->tm_gmtoff / 60) / 60;
			min = (tms->tm_gmtoff / 60) % 60;

			write("\" date=\"%d-%.2d-%.2dT%.2d:%.2d:%.2d%s%.2d:%.2d\"/>\n",
							tms->tm_year+1900, tms->tm_mon+1, tms->tm_mday,
							tms->tm_hour, tms->tm_min, tms->tm_sec,
							tms->tm_gmtoff < 0 ? "-" : "+", hr, min);
		}
		return OK;
	} else
		return FAIL;
}

/* v-version; b-banner */
int XML_Log::log_start(const char *fmt, va_list varg) {
	char *ver=NULL, *banner=NULL;

	while (*fmt)
		switch(*fmt++) {
			case 'v': // version
				ver = va_arg(varg, char *);
				break;
			case 'b': // banner
				banner = va_arg(varg, char *);
				break;
		}
	if (ver && banner) {
		write("<?xml version=\"1.0\"?>\n<Xprobe2 version=\"%s\">\n<!-- %s -->\n", ver, banner);
		return OK;
	} else
		return FAIL;
}
