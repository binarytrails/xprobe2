#include <xprobe.h>
#include "ttl_calc.h"
#include "util.h"
#define _XPROBE_MODULE
#include "xplib.h"
#include "xprobe_module.h"
#include "interface.h"
#include "cmd_opts.h"

extern Interface *ui;
extern Cmd_Opts *copts;

int TTL_Mod::init (void) {
	
	xprobe_mdebug(XPROBE_DEBUG_MODULES, "[TTL_Mod]: Initialized\n");
return OK;

}

int TTL_Mod::exec (Target *Tgt, OS_Matrix *osmtx) {
	int ttldistance;

	if ((ttldistance = get_ttl_distance (Tgt)) > 0) {
		Tgt->set_distance(ttldistance);
		osmtx->add_result (get_id(), 1, XPROBE_MATCH_YES);
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] TTL distance to target is: %d\n", get_name(), Tgt->get_distance());
		ui->log("[+] TTL distance to target: %d hops\n", Tgt->get_distance());
	} else {
		osmtx->add_result (get_id(), 1, XPROBE_MATCH_NO);
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] TTL distance calculation failed\n", get_name());
	}
	
	return OK;

}

int TTL_Mod::fini (void) {
	xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
return OK;
}


int TTL_Mod::parse_keyword(int os_id, const char *keyword, const char *value){
    xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Parsing for %i : %s  = %s\n", 
				get_name(), os_id, keyword, value);
return OK;
}



int ttl_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {

	TTL_Mod *ttl_mod = new TTL_Mod;

	ttl_mod->set_name(nm);
	xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the TTL precalculation module\n");
	/* register module and keywords */
	pt->register_module(ttl_mod);
return(OK);
}

int TTL_Mod::get_ttl_distance(Target *tgt) {

    Xprobe::Timeval timeo;
	struct in_addr remote = tgt->get_addr();
	struct in_addr local = tgt->get_interface_addr();
	struct in_addr gateway;
	struct icmp_hdr *icmph;
	struct tcphdr *tcph;
	struct ip *iph;
    int retval, ttl_distance = 0, failures=0, done = 0;
	u_char *buf, *udppayload;
	u_short orig_sport, echoed_sport, echoed_dport;
	char hname[MAXHOSTLEN];
	char filter[BUFSIZE];
	bool tcptest=true;
	bool showroute = tgt->show_route();

	// we don't do distance calculation if we don't know any port on target system which
	// we can trace to.
	//
	// and we don't do traceroute if system appeared to be dead based on alive reachability tests

	if ((double)tgt->get_rtt() == 0.0 || (tgt->get_port(IPPROTO_TCP, XPROBE_TARGETP_OPEN) == -1 &&
			 	      tgt->get_port(IPPROTO_TCP, XPROBE_TARGETP_CLOSED) == -1 &&
			 	      tgt->get_port(IPPROTO_UDP, XPROBE_TARGETP_CLOSED) == -1)) {
		ui->msg("[-] No distance calculation. %s appears to be dead or no ports known\n",
				inet_ntoa(tgt->get_addr()));
		return FAIL;
	}
	
	if (showroute)
		ui->msg("[%s] Showing route to %s:\n", get_name(), inet_ntoa(tgt->get_addr()));
	if ( (buf = (u_char *) malloc (BUFSIZE)) == NULL ) {
		ui->error("get_ttl_distance: failed to malloc()\n");
		return (-1);
	}
	if ( (udppayload = (u_char *) malloc (sizeof (struct DNSHEADER))) == NULL ) {
		ui->error("get_ttl_distance: failed to malloc()\n");
		return (-1);
	}
	memset (buf, 0, BUFSIZE);
	memset (udppayload, 0, sizeof(struct DNSHEADER));
	memset (hname, 0, sizeof(hname));
	build_DNS_reply(udppayload);
    TCP tcp(inet_ntoa(remote));
    UDP udp(inet_ntoa(remote));
    IP sn(inet_ntoa(local), 123);
	sn.init_device (tgt->get_interface(), 0, 1024);
	tcp.set_src(inet_ntoa(local));
	tcp.set_id(getrandom(U_INTMAX));
	tcp.set_fragoff(IP_DF);

	if (tgt->get_port(IPPROTO_TCP, XPROBE_TARGETP_OPEN) != -1) 
		tcp.set_dstport(tgt->get_port(IPPROTO_TCP, XPROBE_TARGETP_OPEN));
	else 		
		tcp.set_dstport(tgt->get_port(IPPROTO_TCP, XPROBE_TARGETP_CLOSED));

	snprintf(filter, sizeof(filter), "proto ICMP or src port %d", tcp.get_dstport());
	sn.setfilter(filter);
	tcp.set_flags (TCPPACKETFLAGS);
	tcp.set_seq (getrandom(U_INTMAX));
	tcp.set_ack (0);

	udp.set_src (inet_ntoa(local));
	udp.set_id (getrandom(U_INTMAX));
	udp.set_fragoff(IP_DF);
	//udp.set_srcport (53);
	udp.set_dstport (tgt->get_port(IPPROTO_UDP, XPROBE_TARGETP_CLOSED));

	// We are actually only information gathering module. So if rtt was calculated, the target system is dead
	// therefore we don't run. Consider it to be dead. :)
	
	// for some reason smaller timeout timeouts too quickly :) 
	timeo = ((double)tgt->get_rtt() * 5); // if not 0 

	tcp.timeout(timeo);
	udp.timeout(timeo);
	sn.timeout(timeo);

	while (1) {
		orig_sport = getrandom(U_SHORTMAX);
		if (tcptest) {
			tcp.set_ttl(ttl_distance + 1);
			tcp.set_srcport (orig_sport);
			tcp.sendpack("");
		} else {
			udp.set_ttl(ttl_distance + 1);
			udp.set_srcport (orig_sport);
			udp.sendpack((char *)udppayload, sizeof(struct DNSHEADER));	
		}
		done = 0;
		while (!done) {
			retval = sn.sniffpack(buf, BUFSIZE);	
			if (retval > 0 ) {
				if (sn.get_proto() == IPPROTO_ICMP && 
					retval >= (int) (sizeof(struct ip) + sizeof (struct icmp_hdr) + 8)) {
						icmph = (struct icmp_hdr *) buf;
						// echoed IP header
						iph = (struct ip *) (buf + sizeof (struct icmp_hdr));
						// echoed 64-bits of transport layer data
						memcpy(&echoed_sport, buf + (sizeof(struct icmp_hdr)+sizeof(struct ip)), sizeof(unsigned short));
						memcpy(&echoed_dport, buf + (sizeof(struct icmp_hdr)+sizeof(struct ip)+sizeof(unsigned short)), 
									sizeof(unsigned short));
						echoed_sport = ntohs(echoed_sport);
						echoed_dport = ntohs(echoed_dport);
						if (icmph->type == ICMP_TIMXCEED &&
							icmph->code == ICMP_TIMXCEED_INTRANS &&
							iph->ip_src.s_addr == local.s_addr &&
							iph->ip_dst.s_addr == remote.s_addr) {

								// check if it is really the ICMP packet for the 
								// original packet sent
								if (echoed_sport == orig_sport) {
									if (showroute) {
										gateway.s_addr = sn.get_src();
										ui->msg("[x]   %d hop: %s [%s]\n", ttl_distance, 
												sn.get_src(1, hname, MAXHOSTLEN),
												inet_ntoa(gateway));
										memset(hname, 0, MAXHOSTLEN);
									}
									ttl_distance++;
									break;
								}
						} else if (tcptest == false &&
							icmph->type == ICMP_UNREACH &&
							icmph->code == ICMP_UNREACH_PORT &&
                        	iph->ip_src.s_addr == local.s_addr &&
                        	iph->ip_dst.s_addr == remote.s_addr) {
								free (buf);
								free (udppayload);
								if (showroute)
									ui->msg("[x]   %d hop: %s [TARGET]\n", ttl_distance,
                                            sn.get_src(1, hname, MAXHOSTLEN));
								return ttl_distance;
						}
				} else if (tcptest == true && sn.get_proto() == IPPROTO_TCP &&
					retval >= (int) sizeof (struct tcphdr) ) {
						tcph = (struct tcphdr *) buf;
						if (ntohl (tcph->th_ack) == tcp.get_seq()+1) {
							free (buf);
							free (udppayload);
                            if (showroute)
                                ui->msg("[x]   %d hop: %s [TARGET]\n", ttl_distance,
                                        sn.get_src(1, hname, MAXHOSTLEN));
							return ttl_distance;
						}
				}
			}
			/* this is ugly need something more efficient and nice */
			if (sn.timeout()) {
				if (failures == 2) {
					xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] UDP test failed also\n", get_name());
					free (buf);
					free(udppayload);
					if (showroute)
						ui->msg("[%s] Failed to reach target\n", get_name());
					return (0);
				}
				if (tcptest == true && failures == 1) {
					xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Switched to UDP test\n", get_name());
					tcptest = false;
					if (showroute) 
						ui->msg("[x]   %d hop: *\n", ttl_distance);
					failures++;
					done = 1;
				}
				if (tcptest == true) {
					xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Switching TCP test, now sending to closed port\n", get_name());
					tcp.set_dstport(tgt->get_port(IPPROTO_TCP, XPROBE_TARGETP_CLOSED));
					tcp.set_tcpsum(0);
                    if (showroute)  
                        ui->msg("[x]   %d hop: *\n", ttl_distance);
					failures++;
					done = 1;
				}
			}
		} /* inside while() */
	} /* outside while() */
free (buf);
free (udppayload);
return 0;
}
