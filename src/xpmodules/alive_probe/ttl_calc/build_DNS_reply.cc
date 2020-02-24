#include "ttl_calc.h"
#include "util.h"

/* build_DNS_reply builds a payload for the UDP packet
 * so that it apears to be a DNS reply for www.securityfocus.com
 */

extern Interface *ui;

void TTL_Mod::build_DNS_reply (u_char *packet)
{
        struct DNSHEADER *dnsh;
		struct hostent *hostip;
		struct in_addr secfocip;
        u_char *localpacket = packet;

		if ((hostip = gethostbyname(DNSMASQUERADE)) == NULL) {
			ui->error("[-] icmp_port_unreach::build_DNS_reply(): gethostbyname() failed! Using static ip for www.securityfocus.com in UDP probe\n");
			inet_aton("205.206.231.10", &secfocip);
		} else 
			memcpy (&secfocip, hostip->h_addr, hostip->h_length);
#if BYTE_ORDER == LITTLE_ENDIAN
        u_short one = htons(1);
#else
        u_short one = 1;
#endif
        dnsh = (struct DNSHEADER *) localpacket;
        dnsh->id = getrandom(U_SHORTMAX);
        dnsh->qr = 1;
        dnsh->opcode = 0;
        dnsh->aa = 0;
        dnsh->tc = 0;
        dnsh->rd = 1;
        dnsh->ra = 1;
        dnsh->cd = 1;
        dnsh->ad = 1;
        dnsh->rcode = 0;
        dnsh->qdcount = htons(1);
        dnsh->ancount = htons(1);
        dnsh->nscount = 0; 
        dnsh->arcount = 0;
        localpacket+=12;
		memcpy (localpacket, DNSREPLYSTRING, DNSREPLYLEN);
        localpacket+=DNSREPLYLEN;
        memcpy(localpacket, &one, 2);
        localpacket+=2;
        memcpy(localpacket, &one, 2);
        localpacket+=2;
		memcpy (localpacket, DNSREPLYSTRING, DNSREPLYLEN);
        localpacket+=DNSREPLYLEN;
        memcpy(localpacket, &one, 2);
        localpacket+=2;
        memcpy(localpacket, &one, 2);
        localpacket+=2;
        one=0xffff;
        memcpy(localpacket, &one, 4);
        localpacket+=4;
        one=4;
        memcpy(localpacket, &one, 2);
        localpacket+=2;
//        inet_aton("66.38.151.10",&dnsh->replydata);
		dnsh->replydata = secfocip;
} /* END OF BUILD_DNS_REPLY */
