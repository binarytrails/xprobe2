#include <xprobe.h>
#include "usi++/usi++.h"
#define _XPROBE_MODULE
#include "xplib.h"
#include "xprobe_module.h"
#include "xprobe_module_hdlr.h"
#include "interface.h"
#include "target.h"
#include "icmp_port_unreach.h"
#include "util.h"

extern Interface *ui;

int icmp_port_unreach::init (void) {
	
	xprobe_debug(XPROBE_DEBUG_MODULES, "[%s]: Initialized\n", get_name());
return OK;

}

int icmp_port_unreach::exec (Target *Tgt, OS_Matrix *osmtx) {

	Fingerprint *icmp_unr= new Fingerprint;

    if ((get_icmp_unreach(Tgt, icmp_unr)) > 0) {
    /*****************
    * FINGERPRINTING *
    *****************/
		for (iter = os2finger.begin(); iter != os2finger.end(); iter++) {

			if (icmp_unr->get_reply() && iter->second.get_reply()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);
			} else if (!icmp_unr->get_reply() && !iter->second.get_reply()) {
				osmtx->add_result(get_id(), iter->first, XPROBE_MATCH_YES, 11);
				continue;
			}
			/* match TTLs in a fuzzy way */
			if (icmp_unr->get_p_unreach_ttl() - TTL_DELTA < iter->second.get_p_unreach_ttl() && 
				icmp_unr->get_p_unreach_ttl() + TTL_DELTA > iter->second.get_p_unreach_ttl() ){
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}
			if (icmp_unr->get_icmp_prec_bits() == iter->second.get_icmp_prec_bits()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}
			if (icmp_unr->get_icmp_df() == iter->second.get_icmp_df()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}
			if (icmp_unr->get_echoed_size() == iter->second.get_echoed_size()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}
			if (icmp_unr->get_echoed_udpsum() == iter->second.get_echoed_udpsum()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}
			if (icmp_unr->get_echoed_ipsum() == iter->second.get_echoed_ipsum()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}
			if (icmp_unr->get_echoed_ipid() == iter->second.get_echoed_ipid()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}
			if (icmp_unr->get_echoed_totlen() == iter->second.get_echoed_totlen()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}
			if (icmp_unr->get_echoed_3bit() == iter->second.get_echoed_3bit()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}	
			if(icmp_unr->get_icmp_ipid() == iter->second.get_icmp_ipid()) {
				osmtx->add_result (get_id(), iter->first, XPROBE_MATCH_YES);	
			}
		}
	}

	delete icmp_unr;
return OK;
}

int icmp_port_unreach::fini (void) {
	close (sock);
	xprobe_debug(XPROBE_DEBUG_MODULES, "%s module has been deinitilized\n", get_name());
return OK;

}


int icmp_port_unreach_init(Xprobe_Module_Hdlr *pt, char *nm) {

	icmp_port_unreach *port_unreach= new icmp_port_unreach;
	int i;
	extern char *keyarr[];
	port_unreach->set_name(nm);
	xprobe_mdebug(XPROBE_DEBUG_MODULES, "Initializing the ICMP port unreach module\n");
	/* register module and keywords */
	pt->register_module(port_unreach);
	for (i = 0; keyarr[i] != NULL; i++) 
		pt->add_keyword (port_unreach->get_id(), keyarr[i]);
	return(OK);
}

/* fingerptr - is a what we return */
int icmp_port_unreach::get_icmp_unreach(Target *Tgt, Fingerprint *fingerptr) {

	u_int sniffedbytes, echoed_dtsize, ttl;
    u_char *payload;
	u_char echoedpack[1024];
	u_short port = ICMP_UNREACH_DEF_PORT;
	int iphlen=0;
	bool gensig = Tgt->generate_sig();
    struct timeval timeo;
    struct in_addr local = Tgt->get_interface_addr(),
                target = Tgt->get_addr();
	struct ip *iph;
	struct udphdr *udph;
	string keyword, value;

	memset (echoedpack, 0, sizeof(echoedpack));
    timeo = Tgt->get_rtt();
    /* XXX: we need a datagram of 70 bytes size */
    if ( (payload = (u_char *) malloc (sizeof (struct DNSHEADER) )) == NULL ) {
        ui->error ("icmp_port_unreach: failed to allocate memory for payload\n");
        return 0;
    }

	if (Tgt->get_port(IPPROTO_UDP, XPROBE_TARGETP_CLOSED) != -1)
		port = Tgt->get_port(IPPROTO_UDP, XPROBE_TARGETP_CLOSED);
    build_DNS_reply(payload);
    UDP udp(inet_ntoa(target));
    ICMP sn(inet_ntoa(local));
	sn.init_device (Tgt->get_interface(), 0, 1024);
    udp.set_src(inet_ntoa(local));
	udp.set_ttl(255);
	udp.set_tos(0);
	udp.set_id(getrandom(U_INTMAX));
	udp.set_fragoff(IP_DF);
    udp.set_srcport(53);
    udp.set_dstport(port);
    udp.timeout(timeo);
    udp.sendpack((char *)payload, sizeof (struct DNSHEADER));
    sn.timeout(timeo);
sniff_again:
    sniffedbytes = sn.sniffpack (echoedpack, sizeof(echoedpack));
	echoed_dtsize = sniffedbytes - sizeof (struct ip);
    if (sn.timeout()) { /* timedout */
		fingerptr->put_reply("n");
		if (gensig) {
			Tgt->signature("icmp_unreach_reply", "n");
			Tgt->signature("icmp_unreach_echoed_dtsize", "8");
			Tgt->signature("icmp_unreach_reply_ttl", "<255");
			Tgt->signature("icmp_unreach_precedence_bits", "0");
			Tgt->signature("icmp_unreach_df_bit", "0");
			Tgt->signature("icmp_unreach_ip_id",  "!0");
			Tgt->signature("icmp_unreach_echoed_udp_cksum", "OK");
			Tgt->signature("icmp_unreach_echoed_ip_cksum", "OK");
			Tgt->signature("icmp_unreach_echoed_ip_id", "OK");
			Tgt->signature("icmp_unreach_echoed_total_len", "OK");
			Tgt->signature("icmp_unreach_echoed_3bit_flags", "OK");
		}
		free(payload);
        return 0;
	} else {
		if (sniffedbytes >= sizeof (struct ip)) {
			iph = (struct ip *) echoedpack;
			if (iph->ip_dst.s_addr != target.s_addr && iph->ip_src.s_addr != local.s_addr) /* not our icmp unreach */
				goto sniff_again;   /* labels/gotos are bad :) */
		}
	}
	/* XXX: that shit here is a MESS
	 * need to make it more readable
	 */
	fingerptr->put_reply("y");
	if (gensig) Tgt->signature("icmp_unreach_reply", "y");
	/*** tos ***/
	xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ICMP IP ToS is: 0x%x\n", get_name(), sn.get_tos());
	keyword = "icmp_unreach_precedence_bits";
	if (sn.get_tos() == 0xc0) {
		fingerptr->put_icmp_prec_bits(2);
		 value="0xc0";
	} else if (sn.get_tos() == 0) {
		fingerptr->put_icmp_prec_bits(0);
		value ="0";
	} else  {
		fingerptr->put_icmp_prec_bits(1);	/* !0 */
		value="!0";
	}
	if (gensig) Tgt->signature(keyword, value);

	/*** DF ***/
	keyword = "icmp_unreach_df_bit";
	if (sn.get_fragoff() & IP_DF) {
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ICMP IP DF bit set\n", get_name());
		value = "1";
		fingerptr->put_icmp_df(value.c_str());
	} else {
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ICMP IP DF bit not set\n", get_name());
		value = "0";
		fingerptr->put_icmp_df(value.c_str());
	}
	if (gensig) Tgt->signature(keyword, value);
	/*** IP ID ***/
	keyword = "icmp_unreach_ip_id";
	if (sn.get_id() == udp.get_id()) {
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ICMP IP ID = SENT\n", get_name());
		value = "SENT";
		fingerptr->put_icmp_ipid(value.c_str());
	} else if (sn.get_id() == 0) {
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ICMP IP ID = 0\n", get_name());
		value = "0";
		fingerptr->put_icmp_ipid(value.c_str());
	} else {
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ICMP IP ID != 0\n", get_name());
		value = "!0";
		fingerptr->put_icmp_ipid(value.c_str());
	}
	if (gensig) Tgt->signature(keyword, value);

	/* check if we have enuff for ip header */
	if (sniffedbytes >= sizeof (struct ip)) {
		iph = (struct ip *) echoedpack;
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED Header len: %d\n", 
						get_name(), iph->ip_hl<<2);
		iphlen = iph->ip_hl<<2;

		/*** ttl ***/
		if (Tgt->get_distance() < 1) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Figuring distance out from ICMP port unr\n", get_name());
			Tgt->set_distance (udp.get_ttl() - iph->ip_ttl);
		}
		keyword="icmp_unreach_reply_ttl";
		fingerptr->put_p_unreach_ttl(sn.get_ttl());
		ttl = sn.get_ttl() + Tgt->get_distance();
		value = "<";
		if (ttl <= 32)
			value.append("32");
		else if (ttl <= 60)
			value.append("60");
		else if (ttl <= 64)
			value.append("64");
		else if (ttl <= 128)
			value.append("128");
		else if (ttl <= 255)
			value.append("255");
		if (gensig) Tgt->signature(keyword, value);
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ICMP TTL is: %d\n", get_name(), fingerptr->get_p_unreach_ttl());
		/*** ip id ***/
		keyword = "icmp_unreach_echoed_ip_id";
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP ID: 0x%x Orig IP ID: 0x%x (flipp: 0x%x)\n", 
					get_name(), ntohs(iph->ip_id), udp.get_id(), flipp(udp.get_id()) );
		if (ntohs(iph->ip_id) == udp.get_id()) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP ID OK\n", get_name());
			value = "OK";
			fingerptr->put_echoed_ipid(value.c_str());
		} else  if (ntohs(iph->ip_id) == flipp(udp.get_id())) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP ID FLIPPED\n", get_name()); 
			value = "FLIPPED";
			fingerptr->put_echoed_ipid(value.c_str());
			udp.set_id(ntohs(iph->ip_id));
		} else {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP ID BAD\n", get_name());
			value = "BAD";
			fingerptr->put_echoed_ipid(value.c_str());
			udp.set_id(ntohs(iph->ip_id));
		}
		if (gensig) Tgt->signature(keyword, value);
		/*** ip len ***/
		keyword = "icmp_unreach_echoed_total_len";
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP LEN: %d Orig IP LEN: %d\n", 
					get_name(), ntohs(iph->ip_len), udp.get_totlen());
		if (ntohs (iph->ip_len) == udp.get_totlen()) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP Len OK\n", get_name());
			value ="OK";
			fingerptr->put_echoed_totlen(value.c_str());
		} else 
		if (ntohs (iph->ip_len) == udp.get_totlen() - 20) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP totlen < 20\n", get_name());
			fingerptr->put_echoed_totlen("<");
			value ="<20";
			udp.set_totlen(ntohs(iph->ip_len));
		} else
		if (ntohs (iph->ip_len) == udp.get_totlen() + 20) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP totlen > 20\n", get_name());
			fingerptr->put_echoed_totlen(">");
			value = ">20";
			udp.set_totlen(ntohs(iph->ip_len));
		} else {
            xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP totlen is unexpected (%i)\n", get_name(), ntohs(iph->ip_len));
			udp.set_totlen(ntohs(iph->ip_len));
			value = "unexpected";
        }
		if (gensig) Tgt->signature(keyword, value);
		
		/*** 3bit flags ***/
		keyword="icmp_unreach_echoed_3bit_flags";
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP_OFF: 0x%x  Orig: 0x%x (flipp: 0x%x)\n",
						get_name(), ntohs(iph->ip_off), udp.get_fragoff(), flipp(udp.get_fragoff()) ); 
		if (ntohs (iph->ip_off) == udp.get_fragoff()) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED Frag Off Ok\n", get_name());
			value = "OK";
			fingerptr->put_echoed_3bit(value.c_str());
		} else
		if (ntohs (iph->ip_off) == flipp (udp.get_fragoff())) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED Frag Off FLIPPED\n", get_name());
			value = "FLIPPED";
			fingerptr->put_echoed_3bit(value.c_str());
			udp.set_fragoff(ntohs(iph->ip_off));
		} else {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED Frag Off unexpected\n", get_name());
			udp.set_fragoff(ntohs(iph->ip_off));
			value = "unexpected";
		}
		if (gensig) Tgt->signature(keyword, value);

        /*** ip checksum ***/

        /* set the ttl that target saw and
         * calculate the IP header checksum
         * to verify it
         */
		keyword = "icmp_unreach_echoed_ip_cksum";
        udp.set_ttl(iph->ip_ttl);
        xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP checksum: 0x%x Original: 0x%x\n",
                    get_name(), iph->ip_sum, udp.calc_ipsum());
        if (udp.calc_ipsum() == iph->ip_sum) {
            xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP checksum OK\n", get_name());
			value = "OK";
            fingerptr->put_echoed_ipsum(value.c_str());
        } else if (iph->ip_sum == 0) {
            xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP checksum = 0\n", get_name());
			value = "0";
            fingerptr->put_echoed_ipsum("0");
        } else {
            xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED IP checksum BAD\n", get_name());
			value = "BAD";
            fingerptr->put_echoed_ipsum(value.c_str());
        }
		if (gensig) Tgt->signature(keyword, value);
	}
	/* check if we have enuff for udp header */
	if (sniffedbytes >= (sizeof (struct ip) + sizeof (struct udphdr))) {
        
		udph = (struct udphdr *) (echoedpack+iphlen);
		xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED UDP checksum: 0x%x Original UDP checksum: 0x%x\n", 
			 get_name(), ntohs(udph->check),ntohs(udp.get_udpsum()));
		/*** udp checksum ***/
		keyword="icmp_unreach_echoed_udp_cksum";
		if (udph->check == udp.get_udpsum()) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED UPD checksum OK\n", get_name());
			value = "OK";
			fingerptr->put_echoed_udpsum(value.c_str());
		} else
		if (udph->check == 0) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED UPD checksum  = 0\n", get_name());
			value ="0";
			fingerptr->put_echoed_udpsum("0");
		} else {
			xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] ECHOED UPD checksum  BAD\n", get_name());
			value = "BAD";
			fingerptr->put_echoed_udpsum(value.c_str());
		}
		if (gensig) Tgt->signature(keyword, value);
	}
        /*** echoed size ***/
	xprobe_debug(XPROBE_DEBUG_MODULES, "[%s] Size of echoed data: %d\n", get_name(), echoed_dtsize);
	keyword = "icmp_unreach_echoed_dtsize";
	/*
	if (echoed_dtsize == 64) {
		fingerptr->put_echoed_size(echoed_dtsize);
		value = "64";
	} else if (echoed_dtsize > 64) {
		value = ">64";
		fingerptr->put_echoed_size(value.c_str());
	} else if (echoed_dtsize == 8) {
		fingerptr->put_echoed_size (echoed_dtsize);
		value = "8";
	} else {
		value = "unexpected";	
	}
	*/
	if (echoed_dtsize > 64) {
		value = ">64";
	} else {
		value = xp_lib::int_to_string(echoed_dtsize);
	}
	fingerptr->put_echoed_size(value.c_str());
	if (gensig) Tgt->signature(keyword, value);
	
free(payload);
return 1;
}
