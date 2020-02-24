/* $Id: util.h,v 1.4 2003/04/22 20:00:50 fygrave Exp $ */
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

#ifndef TTL_PRECALC_H
#define TTL_PRECALC_H

#include <xprobe.h>

#define DNSREPLYSIZE sizeof(struct ip) + 8 +sizeof(struct DNSHEADER)
#define TCPPACKETSIZE sizeof(struct ip) + sizeof (struct tcphdr)
#define SA struct sockaddr
#define U_CHARMAX 254
#define U_SHORTMAX 65535
#define U_INTMAX 0xffffffffU
#define U_DOUBLEMAX 4294967296

#define TRUE 1
#define FALSE 0

#define TIMEOUT 5

#define DEFPORT 80

#define TCPPACKETFLAGS TH_SYN

#define TTL_ERROR 3

#define BUFSIZE 1024

#define DNSREPLYSTRING "\003www\015securityfocus\003com"
#define DNSMASQUERADE "www.securityfocus.com"
#define DNSREPLYLEN             sizeof(DNSREPLYSTRING)

struct DNSHEADER{
        unsigned        id :16;         /* query identification number */
#if BYTE_ORDER == BIG_ENDIAN
                        /* fields in third byte */
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritive answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        rcode :4;       /* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritive answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif
                        /* remaining bytes */
        unsigned        qdcount :16;    /* number of question entries */
        unsigned        ancount :16;    /* number of answer entries */
        unsigned        nscount :16;    /* number of authority entries */
        unsigned        arcount :16;    /* number of resource entries */
        u_char      	domainname[DNSREPLYLEN-1]; 
	u_short		querytype;
	u_short		queryclass;
        u_char      	replyname[DNSREPLYLEN-1]; 
	u_short		type;
	u_short		classs;
	u_long		ttl;
	u_short	 	dl;
	struct in_addr		replydata;
        
};

#define ICMP_UNREACH            3               /* dest unreachable, codes: */
#define         ICMP_UNREACH_HOST               1       /* bad host */
#define         ICMP_UNREACH_PROTOCOL           2       /* bad protocol */
#define         ICMP_UNREACH_PORT               3       /* bad port */
#define ICMP_TIMXCEED           11              /* time exceeded, code: */
#define         ICMP_TIMXCEED_INTRANS   0               /* ttl==0 in transit */
#define         ICMP_TIMXCEED_REASS     1               /* ttl==0 in reass */

struct icmp_hdr {
	u_char type;
	u_char code;
	u_short checksum;
	u_int zero;
};

struct icmp_ping {
    u_char type;
    u_char code;
    u_short checksum;
	u_short id;
	u_short seq;
	};
#endif /* TTL_PRECALC */
