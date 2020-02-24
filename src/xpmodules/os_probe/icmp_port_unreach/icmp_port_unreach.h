/* $Id: icmp_port_unreach.h,v 1.9 2005/02/15 15:15:52 mederchik Exp $ */
/*
** Copyright (C) 2001, 2002 Meder Kydyraliev
**
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

#ifndef ICMP_PORT_UNREACH_H
#define ICMP_PORT_UNREACH_H

#include "xprobe.h"
#include <pcap.h>
#include "xprobe_module.h"
#include "xprobe_module_hdlr.h"
#include "interface.h"
#define _XPROBE_MODULE
#include "xplib.h"

#define NUMOFKEYWORDS 3
#define TCP_RST 0
#define TCP_SYN_ACK 1
#define ICMP_P_UNR 2

#define MORETHAN64  65

#define IPID_SENT	2

#define ICMP_UNREACH_DEF_PORT 65534
#ifndef __USE_BSD
#define __USE_BSD
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

class icmp_port_unreach: public Xprobe_Module {
    private:
    int sock;
	/* CLASS THAT STORES FINGERPRINT */
	/* Fyodor's idea :) */
    class Fingerprint {
        private:
			u_short icmp_port_unreach_ttl; /* u_short not u_char cuz we need to +- TTL_ERROR */
			u_char icmp_precedence_bits;	/* values: 0xc0, 0, !0 */
			u_char icmp_ip_df;				/* values: [0 , 1 ] */
			u_char icmp_ipid;				/* values: [0, !0, SENT] */
			int echoed_size;		/* values: [>< decimal num] */
			u_char echoed_udpsum;	/* values: [0, OK, BAD] */
			u_char echoed_ipsum;
			u_char echoed_ipid;		/* values: [OK, FLIPPED] */
			int echoed_totlen;		/* values: [<20, OK, >20] */
			u_char echoed_3bit_flags;	/* values: [OK, FLIPPED] */
			bool reply;
        public:
			Fingerprint (void) { icmp_port_unreach_ttl=0; }
            u_short get_p_unreach_ttl (void) { return icmp_port_unreach_ttl;}
			u_char get_icmp_prec_bits (void) { return icmp_precedence_bits; }
			u_char get_icmp_df (void) { return icmp_ip_df; }
			int get_echoed_size (void) { return echoed_size; }
			u_char get_echoed_udpsum (void) { return echoed_udpsum; }
			u_char get_echoed_ipsum (void) { return echoed_ipsum; }
			u_char get_echoed_ipid (void) { return echoed_ipid; }
			int get_echoed_totlen (void) { return echoed_totlen; }
			u_char get_echoed_3bit (void) { return echoed_3bit_flags; }
			u_char get_icmp_ipid(void) { return icmp_ipid; }
			bool get_reply(void) { return reply; }
			
            void put_p_unreach_ttl (const char *v) { icmp_port_unreach_ttl = atoi(v) - 1; }
			void put_p_unreach_ttl (int v)	{ icmp_port_unreach_ttl = v; }
            void put_icmp_prec_bits (const char *v) { 
				if (!strcmp(v, "0xc0"))
					icmp_precedence_bits = 2;
				else if (!strcmp(v, "0"))
					icmp_precedence_bits = 0;
				else if (v[0] == '!')
					icmp_precedence_bits = 1;
                else
                   fprintf(stderr,"icmp_port_unreach precedence: %s - unknown value!\n", v);      
			}
			void put_icmp_prec_bits (int v) { icmp_precedence_bits = v; }
            void put_icmp_df (const char *v) { icmp_ip_df = atoi(v); }
            void put_echoed_size (const char *v) { 
				if (v[0] == '>')	
					echoed_size = MORETHAN64;
				else
					echoed_size = atoi(v);
			}
			void put_echoed_size (int v) { echoed_size = v; }
            void put_echoed_udpsum (const char *v) { 
				if (!strncmp(v, "OK", 2))
					echoed_udpsum = UDP_CKSUM_GOOD;
				else if (!strncmp(v, "BAD", 3))
					echoed_udpsum = UDP_CKSUM_BAD;
				else if ((atoi(v)) == 0)
					echoed_udpsum = UDP_CKSUM_ZERO;
			}
            void put_echoed_ipsum (const char *v) { 
                if (!strncmp(v, "OK", 2))
                    echoed_ipsum = IP_CKSUM_GOOD;
                else if (!strncmp(v, "BAD", 3))
                    echoed_ipsum = IP_CKSUM_BAD;
                else if ((atoi(v)) == 0)
                    echoed_ipsum = IP_CKSUM_ZERO; 
			}
            void put_echoed_ipid (const char *v) { 
				if (!strncmp(v, "OK", 2))
					echoed_ipid = IP_ID_GOOD;
				else if (!strncmp(v, "FLIPPED", 7)) 
					echoed_ipid = IP_ID_FLIPPED;
				else if (!strncmp(v, "BAD", 3))
					echoed_ipid = IP_ID_BAD;
			}
            void put_echoed_totlen (const char *v) { 
				if (!strncmp(v, "OK", 2))
					echoed_totlen = ICMPUNREACH_LEN_OK;
				else if (v[0] == '<')
					echoed_totlen = ICMPUNREACH_LEN_LS;
				else if (v[0] == '>')
					echoed_totlen = ICMPUNREACH_LEN_GT;
					
			}
            void put_echoed_3bit (const char *v) { 
				if (!strncmp(v, "OK", 2))
					echoed_3bit_flags = FRAG_BITS_OK;
				else if (!strncmp(v, "FLIPPED", 7))
					echoed_3bit_flags = FRAG_BITS_FLIPPED;
			}			
			void put_icmp_ipid(const char *v) {
				if (v[0] == '!' && v[1]=='0')
					icmp_ipid = 1;
				else if (v[0] == '0')
					icmp_ipid = 0;
				else if (!strncasecmp(v, "SENT", 4))
					icmp_ipid = IPID_SENT;
			}
			void put_reply(const char *v) {
				if (v[0] == 'Y' || v[0] == 'y')
					reply = true;
				else 
					reply = false;
								
			}
			
    };
	/* MAP TO STORE FINGEPRINTS */
    map <int, Fingerprint> os2finger;
	map <int, Fingerprint>::iterator iter;
    void build_DNS_reply (u_char *);
	int getrandom(int limit);
	int get_icmp_unreach(Target *, Fingerprint *);
	u_int flipp(u_int toflipp) {	
		unsigned int mask=0x0000ff00;
		int n = sizeof (toflipp)/2;
		while (n > 1){
			mask  = (mask << 16)|mask; n--;
    	}
    	return (((toflipp & (mask>>8))<<8)|((toflipp & mask)>>8));	
	}
    public:
		/* constructor */
        icmp_port_unreach(void) : Xprobe_Module(XPROBE_MODULE_OSTEST , 
			"fingerprint:icmp_port_unreach","ICMP port unreachable fingerprinting module") { return; }
		/* destructor */
        ~icmp_port_unreach(void) { return; }
        int init(void);
        int parse_keyword(int, const char *, const char *);
        int exec(Target *, OS_Matrix *);
        int fini(void);
};

#endif
