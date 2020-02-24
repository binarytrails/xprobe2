/* $Id: portscanner.cc,v 1.9 2005/02/14 18:05:17 mederchik Exp $ */
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

#include "xprobe.h"
#define _XPROBE_MODULE
#include "xplib.h"
#include "xprobe_module_hdlr.h"
#include "target.h"
#include "interface.h"
#include "cmd_opts.h"
#include "portscanner.h"
#include "usi++/usi++.h"
#include "log.h"
#include <sys/wait.h>

extern Interface *ui;
extern Cmd_Opts *copts;
extern XML_Log *xml;
int done_sending=0;

void child_handler (int signum) {
	while(wait(NULL) > 0);
	signum++; //suspend warn
	done_sending = 1;
}

int Portscanner::init(void) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module initialized\n", get_name());
    return OK;
}


int Portscanner::exec(Target *tg, OS_Matrix *os) {
	pid_t childpid;
	unsigned int k;
	u_short j;
	u_char tcp_ignore_state, udp_ignore_state;
	map<int, char>::iterator m_i;
	struct servent *serv;
	struct timeval start, end;
	struct sigaction act, oact;

	os = os; /* suspend warning */
    xprobe_debug(XPROBE_DEBUG_MODULES, "--%s module has been executed against: %s\n", get_name(),
            inet_ntoa(tg->get_addr()));

//	signal(SIGCHLD, child_handler); 
	act.sa_handler= child_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGCHLD, &act, &oact)) {
		ui->error("Portscanner::sigaction failed!\n");
		return FAIL;
	}

	tcpport = *(tg->get_tcp_toscan());
	udpport = *(tg->get_udp_toscan());
	if (tcpport.size() == 0 && udpport.size() == 0) {
		return FAIL;
	}
	for (k=0; k < tcpport.size(); k++)
		tcpportnum += tcpport[k].size();
	for (k=0; k < udpport.size(); k++)
		udpportnum += udpport[k].size();

	if ((gettimeofday(&start, NULL))<0) {
		ui->msg("Portscanner::exec gettimeofday failed\n");
		return FAIL;
	}
	/* flush before fork()ing */
	xml->flush();
	if ((childpid = fork()) < 0) {
		// error
		ui->msg("[%s] fork() failed: %s\n", get_name(), strerror(errno));
		return FAIL;
	} else if (childpid) {
		// parent
		receive_packets(tg);
	} else {
		// child
		send_packets(tg);
		xprobe_mdebug(XPROBE_DEBUG_MODULES, "BUG!! send_packets returned!\n");
		/* UNEARCH: child never returns */
	}
	// everyone meets here
	
	if ((gettimeofday(&end, NULL)) < 0) {
		ui->msg("Portscanner::exec gettimeofday failed\n");
		return FAIL;
	}
	// 1st thing to do is to see what ports where filtered
    for (k=0; k < tcpport.size(); k++)
        while(!tcpport[k].get_next(&j))
			if (tcp_ports.find(j) == tcp_ports.end()){
				tcpfiltered++;
				tcp_ports.insert(pair<int, char>(j, XPROBE_TARGETP_FILTERED));
            }
        tcp_ignore_state = get_ignore_state(IPPROTO_TCP);
        if ((tcpopen && !tcpclosed && !tcpfiltered) ||
            (!tcpopen && tcpclosed && !tcpfiltered) ||
            (!tcpopen && !tcpclosed && tcpfiltered)) {
            tcp_ignore_state = 255; //lame :)
        }

    for (k=0; k < udpport.size(); k++)
        while(!udpport[k].get_next(&j))
			if (udp_ports.find(j) == udp_ports.end()){
				udpfiltered++;
				udp_ports.insert(pair<int, char>(j, XPROBE_TARGETP_FILTERED));
			}
	xml->log(XPROBELOG_PS_SESS_START, "%d", ((end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec)/1000)/1000.0);
	
	xml->log(XPROBELOG_STATS_SESS_START, "pscan stats");
	ui->msg("\n[+] Portscan results for %s:\n", inet_ntoa(tg->get_addr()));
	ui->msg("[+]  Stats:\n");
	ui->msg("[+]   TCP: %d - open, %d - closed, %d - filtered\n", tcpopen, tcpclosed, tcpfiltered);
	xml->log(XPROBELOG_MSG_PS_TCPST, "%o%c%f", tcpopen, tcpclosed, tcpfiltered); 
	ui->msg("[+]   UDP: %d - open, %d - closed, %d - filtered\n", udpopen, udpclosed, udpfiltered);
	xml->log(XPROBELOG_MSG_PS_UDPST, "%o%c%f", udpopen, udpclosed, udpfiltered);
	xml->log(XPROBELOG_STATS_SESS_END, "stats done");
	ui->msg("[+]   Portscan took %.2f seconds.\n",
	// convert seconds into milliseconds
	((end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec)/1000)/1000.0);
	ui->msg("[+]  Details:\n");
	xml->log(XPROBELOG_PSDET_SESS_START, "details");
	ui->msg("[+]   Proto\tPort Num.\tState\t\tServ. Name\n");

	/* TCP */
	for (m_i = tcp_ports.begin(); m_i != tcp_ports.end(); m_i++) {
		if (m_i->second == tcp_ignore_state)
			continue;
		ui->msg("[+]   TCP\t%d\t\t", m_i->first);
		if (m_i->second == XPROBE_TARGETP_OPEN)
			ui->msg("open\t");
		else if (m_i->second == XPROBE_TARGETP_CLOSED)
			ui->msg("closed\t"); 
		else if (m_i->second ==XPROBE_TARGETP_FILTERED)
			ui->msg("filtered");
		ui->msg("\t");
		if ((serv=getservbyport(htons(m_i->first), "tcp")) != NULL)
			if(serv->s_name != NULL) {
				ui->msg("%-s\t", serv->s_name);
			} else {
				ui->msg("%-s\t", "N/A");
			}
		else
			ui->msg("N/A\t");
		ui->msg("\n");
		xml->log(XPROBELOG_MSG_PORT, "%n%p%t%s", m_i->first, IPPROTO_TCP, m_i->second, (serv != NULL && serv->s_name != NULL) ? serv->s_name: "N/A");
	}


	udp_ignore_state = get_ignore_state(IPPROTO_UDP);
	if ((udpopen && !udpclosed && !udpfiltered) ||
		(!udpopen && udpclosed && !udpfiltered) ||
		(!udpopen && !udpclosed && udpfiltered)) {
		udp_ignore_state = 255; //lame :)
	}

   	/* UDP */ 
	for (m_i = udp_ports.begin(); m_i != udp_ports.end(); m_i++) {
		if (m_i->second == udp_ignore_state)
			continue;
		ui->msg("[+]   UDP\t%d\t\t", m_i->first);
		if (m_i->second == XPROBE_TARGETP_OPEN)
			ui->msg("open\t");
		else if (m_i->second == XPROBE_TARGETP_CLOSED)
			ui->msg("closed\t"); 
		else if (m_i->second ==XPROBE_TARGETP_FILTERED)
			ui->msg("filtered/open");
		ui->msg("\t");
		if ((serv=getservbyport(htons(m_i->first), "udp")) != NULL)
			if(serv->s_name != NULL) {
				ui->msg("%-s\t", serv->s_name);
			} else {
				ui->msg("%-s\t", "N/A");
			}
		else
			ui->msg("N/A\t");
		ui->msg("\n");
		xml->log(XPROBELOG_MSG_PORT, "%n%p%t%s", m_i->first, IPPROTO_UDP, m_i->second, (serv != NULL && serv->s_name != NULL) ? serv->s_name: "N/A");
	}

	
	//XXX: ugly fix later
	if (tcp_ignore_state == XPROBE_TARGETP_OPEN ||
		tcp_ignore_state == XPROBE_TARGETP_CLOSED ||
		tcp_ignore_state == XPROBE_TARGETP_FILTERED) {
		ui->msg("[+]  Other TCP ports are in ");
		if (tcp_ignore_state == XPROBE_TARGETP_OPEN)
			ui->msg("open");
		if (tcp_ignore_state == XPROBE_TARGETP_CLOSED)
			ui->msg("closed");
		if (tcp_ignore_state == XPROBE_TARGETP_FILTERED)
			ui->msg("filtered");
		ui->msg(" state.\n");
		xml->log(XPROBELOG_OTHER_TCPP, "%s", tcp_ignore_state);
	}
	if (udp_ignore_state == XPROBE_TARGETP_OPEN ||
		udp_ignore_state == XPROBE_TARGETP_CLOSED ||
		udp_ignore_state == XPROBE_TARGETP_FILTERED) {
		ui->msg("[+]  Other UDP ports are in ");
		if (udp_ignore_state == XPROBE_TARGETP_OPEN)
			ui->msg("open");
		if (udp_ignore_state == XPROBE_TARGETP_CLOSED)
			ui->msg("closed");
		if (udp_ignore_state == XPROBE_TARGETP_FILTERED)
			ui->msg("filtered");
		ui->msg(" state.\n");
		xml->log(XPROBELOG_OTHER_UDPP, "%s", tcp_ignore_state);
	}
	xml->log(XPROBELOG_PSDET_SESS_END, "end of portscan details");
	xml->log(XPROBELOG_PS_SESS_END, "end of portscan");
	// ok now we need to save this data into Target object
	tg->set_tcp_ports(&tcp_ports);
	tg->set_udp_ports(&udp_ports);
	// tg->set_udp_ports(&udp_ports);
	if (sigaction(SIGCHLD, &oact, NULL)) {
		ui->error("Portscanner::sigaction failed!\n");
		return FAIL;
	}
	if (copts->analyze_packets()) {
		for (multimap_iter iter = packet_samples.begin(); iter != packet_samples.end(); iter++) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "Sample #%d (count=%d):\n%s", k, iter->second.get_counter(),
							((iter->second.get_pack()).to_string()).c_str());
			k++;
		}
		analyze_packets();
	}
    return OK;
}

int Portscanner::fini(void) {
    xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
    return OK;
}

int Portscanner::send_packets(Target *tg) {
	struct in_addr remote=tg->get_addr(), local=tg->get_interface_addr();
	TCP tcpp(inet_ntoa(remote));
	UDP udpp(inet_ntoa(remote));
	unsigned int k, seq, j=0; //, onestar, percent=0;
	unsigned short dport,sport;
	unsigned char digest[20];
	xp_SHA1 sha;
	struct _shainput {
		struct in_addr src;
		struct in_addr dst;
		u_short sport;
		u_short dport;
	} shainput;	

	if (tg->get_delay())
		send_delay.usec(tg->get_delay());
	else
		send_delay = copts->get_send_delay();

	memset(&shainput, 0, sizeof(shainput));
	shainput.src.s_addr = local.s_addr;
	shainput.dst.s_addr = remote.s_addr;
	tcpp.set_src(inet_ntoa(local));
	tcpp.set_flags(TH_SYN);
	tcpp.set_ack(0);
    tcpp.set_win(5840);
	tcpp.set_ttl(64);
	srand(time(NULL));

	udpp.set_src(inet_ntoa(local));
	udpp.set_ttl(64);
	udpp.set_id(rand());

	
    for (k=0; k < udpport.size(); k++) {
        while(!udpport[k].get_next(&dport)) {
		    if (send_delay.microsec()) usleep(send_delay.microsec());
			udpp.set_id(rand());
			udpp.set_dstport(dport);
			/* XXX: bug in libusi++ */
			udpp.set_udpsum(0);
			shainput.sport = 0;
			shainput.dport = udpp.get_dstport();
			sha.get_digest(digest,(const u_char *) &shainput, sizeof(shainput));
			// XXX: shouldn't be messing w/ int's on that level
			memcpy(&sport, digest, sizeof(sport));
			udpp.set_srcport(sport);
			udpp.sendpack("");
		}
    }


	/* XXX: check that fflush() stuff overhead and
	 * maybe find a better solution
	 */
/*	onestar = tcpportnum / 100;
	ui->msg("[+] TCP portscan progress:    ");	
	fflush(stdout);
*/
    for (k=0; k < tcpport.size(); k++) {
        while(!tcpport[k].get_next(&dport)) {
/*
			if (j >= onestar) {
				percent+=1;
				ui->msg("\b\b\b%.2d%%", percent);
				j=0;
				fflush(stdout);
			}
*/
			usleep(send_delay.microsec());
            //if (send_delay.microsec()) usleep(send_delay.microsec());
			tcpp.set_id(rand());
			tcpp.set_tcpsum(0); // recalc tcp checksum
			tcpp.set_srcport(rand() + 1024);
			tcpp.set_dstport(dport);
			shainput.sport = tcpp.get_srcport();
			shainput.dport = tcpp.get_dstport();
			sha.get_digest(digest,(const u_char *) &shainput, sizeof(shainput));
			// XXX: shouldn't be messing w/ int's on that level
			memcpy(&seq, digest, sizeof(seq));
			tcpp.set_seq(seq);
			tcpp.sendpack("");
			j++;
		}
    }
/*
	ui->msg("\n");
	fflush(stdout);
*/
	exit (OK);
}

int Portscanner::receive_packets(Target *tg) {
		/*
    unsigned int tcpportnum = 0, udpportnum = 0, k;

    for (k=0; k < tcpport.size(); k++) 
                tcpportnum += tcpport[k].size();

    for (k=0; k < udpport.size(); k++) 
                udpportnum += udpport[k].size();
 
				*/
	int ret, done=0;
    //XXX: Modify timeout here
    Xprobe::Timeval timeout = (double)(tg->get_rtt() * 2 + (((double)copts->get_send_delay() + 0.01) * 
			    (tcpportnum + udpportnum)));
    Xprobe::Timeval tv;
	unsigned int seq, optlen;
    unsigned short sport;
	struct in_addr remote=tg->get_addr(), local=tg->get_interface_addr();
	Xprobe::Timeval start;
	char payload[1024], *tcp_options;
	unsigned char digest[20];
	IP sn(inet_ntoa(local), IPPROTO_IP);
	TCP tcp_packet("127.0.0.1");
    struct ip *iph;
    struct usipp::tcphdr *tcph;
    struct usipp::udphdr *udph;
    struct usipp::icmphdr *icmph;
	xp_SHA1 sha;
	struct _shainput {
		struct in_addr src;
		struct in_addr dst;
		u_short sport;
		u_short dport;
	} shainput;

	memset(&shainput, 0, sizeof(shainput));
	sn.init_device(tg->get_interface(), 0, 1500);
	tv = tg->get_rtt();
	//sn.timeout(tv);
	start = Xprobe::Timeval::gettimeofday();

    /* libUSI needs a major redesign. So hard to demultiplex packets of
     * different protocol
     */
	while (!done) {
		ret = sn.sniffpack(payload, sizeof(payload));
		if (!sn.timeout()) {
            if (sn.get_proto() == IPPROTO_TCP) {
                /* should be objects iph and tcph respectively */
				/* create tcp_packet */
				tcp_packet.set_iphdr(sn.get_iphdr());
                tcph = (struct usipp::tcphdr *)(payload);
				tcp_packet.set_tcphdr(*tcph);
				optlen = (tcph->th_off<<2) - sizeof(struct usipp::tcphdr);
				if (optlen > 0) {
					tcp_options = payload + sizeof(struct usipp::tcphdr);
					tcp_packet.set_tcpopt(tcp_options, optlen);
				}

                shainput.src.s_addr = sn.get_dst();
                shainput.dst.s_addr = sn.get_src();
                /* should be Object TCP and method get->tcph here, do it in
                 * C way for now */
                //shainput.sport = ntohs(tcph->th_dport);
                //shainput.dport = ntohs(tcph->th_sport);
				shainput.sport = tcp_packet.get_dstport();
				shainput.dport = tcp_packet.get_srcport();
                sha.get_digest(digest,(const u_char *) &shainput, sizeof(shainput));
                memcpy(&seq, digest, sizeof(seq));
                //if (seq == ntohl(tcph->th_ack) - 1) {
                if (seq == tcp_packet.get_ack() - 1) {
                    /* should be an object too */
                    //if ((tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
                    if ((tcp_packet.get_flags() & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
                        tcp_ports.insert(pair<int, char>(tcp_packet.get_srcport(), XPROBE_TARGETP_OPEN));
                        tcpopen++;
                    //} else if (tcph->th_flags & TH_RST) {
                    } else if (tcp_packet.get_flags() & TH_RST) {
                        tcp_ports.insert(pair<int, char>(tcp_packet.get_srcport(), XPROBE_TARGETP_CLOSED));
                        tcpclosed++;
                    }
					if (copts->analyze_packets()) 
						analyze_packet(tcp_packet);
                }
				tcp_packet.reset_tcpopt();
            } else if (sn.get_proto() == IPPROTO_ICMP) {
                /* should be objects iph and tcph respectively */
                //iph = (struct ip *)payload;
                icmph = (struct usipp::icmphdr *)((char *)payload);

                if (icmph->type == ICMP_DEST_UNREACH &&
                        icmph->code == ICMP_PORT_UNREACH) {
                    // THIS IS LAME SHIT.. fix later!
                    iph = (struct ip *)((char *)icmph +  sizeof(struct usipp::icmphdr));
                    udph = (struct udphdr *)((char *)iph + sizeof(struct ip));     

                    shainput.src.s_addr = sn.get_dst();
                    shainput.dst.s_addr = sn.get_src();
                    shainput.dport = ntohs(udph->dest);
                    shainput.sport = 0;
                    sha.get_digest(digest,(const u_char *) &shainput, sizeof(shainput));
                    memcpy(&sport, digest, sizeof(sport));
                    if (sport == ntohs(udph->source)) {
                        udp_ports.insert(pair<int, char>(ntohs(udph->dest), XPROBE_TARGETP_CLOSED));
                        udpclosed++;
                    }
                }
            } else if (sn.get_proto() == IPPROTO_UDP) {
                /* should be objects iph and tcph respectively */
                udph = (struct udphdr *)(payload);

                shainput.src.s_addr = sn.get_dst();
                shainput.dst.s_addr = sn.get_src();
                shainput.dport = ntohs(udph->source);
                shainput.sport = 0;
                sha.get_digest(digest,(const u_char *) &shainput, sizeof(shainput));
                memcpy(&sport, digest, sizeof(sport));
                if (sport == ntohs(udph->dest)) {
	                udp_ports.insert(pair<int, char>(ntohs(udph->source), XPROBE_TARGETP_OPEN));
                    udpopen++;
                }

            }
                
		}
//		if (done_sending && start == 0)
//			start = time(NULL);
        if (tcpportnum != 0 && (unsigned)(tcpopen + tcpclosed) == tcpportnum) // all responses received
            done = 1;
        if (tcpportnum == 0 && (unsigned)(udpopen + udpclosed) == udpportnum) // all responses received
            done = 1;
		if (done_sending) {
			if (((double)Xprobe::Timeval::gettimeofday()-(double)start) > (double)timeout)
				done=1;
			//printf("tcp open: %d closed %d portnum %d\n", tcpopen, tcpclosed, portnum);
			//printf("exit by timeout %.2f - %.2f = %.2f > %.2f\n",
			//(double)Xprobe::Timeval::gettimeofday(),
			//(double)start,
			//(double)Xprobe::Timeval::gettimeofday() - (double)start,
		       	//(double)timeout);
		}
	}
	return OK;
}

char Portscanner::get_ignore_state(int proto) {
	char retval = 0;

    switch(proto) {
        case IPPROTO_TCP:
			if (!tcpopen && !tcpclosed && !tcpfiltered)
				return 255;
            if (tcpopen > tcpclosed) {
                retval = XPROBE_TARGETP_OPEN;
                if (tcpfiltered > tcpopen) {
                    retval = XPROBE_TARGETP_FILTERED;
                }
            } else if (tcpclosed > tcpfiltered){
                retval = XPROBE_TARGETP_CLOSED;
            } else {
                retval = XPROBE_TARGETP_FILTERED;
            }
            break;
        case IPPROTO_UDP:
			if (!udpopen && !udpclosed && !udpfiltered)
				return 255;
             if (udpopen > udpclosed) {
                retval = XPROBE_TARGETP_OPEN;
                if (udpfiltered > udpopen) {
                    retval = XPROBE_TARGETP_FILTERED;
                }
            } else if (udpclosed > udpfiltered){
                retval = XPROBE_TARGETP_CLOSED;
            } else {
                retval = XPROBE_TARGETP_FILTERED;
            }
             break;
    }
	return retval;

}

/* initialization function */

int portscan_mod_init(Xprobe_Module_Hdlr *pt, char *nm) {

    Portscanner *port_scan= new Portscanner;

    port_scan->set_name(nm);
    xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the portscanning module\n");
    pt->register_module(port_scan);

return OK;
}


int Portscanner::analyze_packet(TCP& packet) {
	int packet_class = -1;
	packet_sample psample;
	bool got_same_sample=false;
	pair<multimap_iter, multimap_iter> irange;

	if (packet.get_flags() & TH_RST)
		packet_class = TH_RST;
	else if (packet.get_flags() & (TH_SYN|TH_ACK))
		packet_class = TH_SYN|TH_ACK;

	irange = packet_samples.equal_range(packet_class);

	for (multimap_iter iter = irange.first; iter != irange.second; ++iter) {
		if (packet == iter->second.get_pack()) {
			iter->second.incr();
			got_same_sample=true;
		}
	}
	if (!got_same_sample) {
			psample.set_pack(packet);
			psample.incr();
			packet_samples.insert(pair<int, packet_sample>(packet_class, psample));
	}
	return OK;
}

void Portscanner::analyze_packets(void) {
	pair<multimap_iter, multimap_iter> irange;
	int packet_class, counter=0;
	bool detected=false;
	/*
	 * only two packet classes for now, RST and SYN|ACK 
	 */
	packet_class = TH_RST;
	/*
	 * do we have more than 1 sample packet of the same type?
	 */
	if (packet_samples.count(packet_class) > 1) {
		detected=true;
		ui->msg("[+] Possible firewall/NIDS configured to reply/reset with RST packets as\n");
		ui->msg("[+] variation in packets of the same class (RST) was detected:\n");
		irange = packet_samples.equal_range(packet_class);
		for (multimap_iter iter = irange.first; iter != irange.second; ++iter) {
			ui->msg("[Sample #%d]\n%s", counter++, iter->second.get_pack().to_string().c_str());
		}
	}
	packet_class = TH_SYN|TH_ACK;
	counter = 0;
	if (packet_samples.count(packet_class) > 1) {
		detected=true;
		ui->msg("[+] Possible transparent proxy/honeypot detected as\n");
		ui->msg("[+] variation in packets of the same class (SYN|ACK) was detected:\n");
		irange = packet_samples.equal_range(packet_class);
		for (multimap_iter iter = irange.first; iter != irange.second; ++iter) {
			ui->msg("[Sample #%d]\n%s", counter++, iter->second.get_pack().to_string().c_str());
		}
	}
}
