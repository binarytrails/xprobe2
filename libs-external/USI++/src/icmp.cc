/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights. If not,
 *** you can get it at http://www.cs.uni-potsdam.de/homepages/students/linuxer
 *** the logit-package. You will also find some other nice utillities there.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
 
#include "usi++/usi-structs.h"
#include "usi++/datalink.h"
#include "usi++/icmp.h"
#include "usi++/ip.h"

#include <string.h>
#include <errno.h>
#include <iostream>

namespace usipp {

ICMP::ICMP(const char* host) 
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
      : IP(host, IPPROTO_ICMP)
{        
        // clear memory
        memset(&icmphdr, 0, sizeof(icmphdr));
                
}

ICMP::ICMP(u_int32_t dst) : IP(dst, IPPROTO_ICMP)
{
        memset(&icmphdr, 0, sizeof(icmphdr));
}
		

ICMP::~ICMP()
{
}

ICMP::ICMP(const ICMP &rhs)
	: IP(rhs)
{
	if (this == &rhs)
		return;
	
	this->icmphdr = rhs.icmphdr;
}

ICMP &ICMP::operator=(const ICMP &rhs)
{
	if (this == &rhs)
		return *this;

	IP::operator=(rhs);
	this->icmphdr  = rhs.icmphdr;
	return *this;
}


ICMP &ICMP::operator=(const IP &rhs)
{
    iphdr iph;
	if (this == &rhs)
		return *this;
	IP::operator=(rhs);
    iph = IP::get_iphdr();
	icmphdr = *(struct icmphdr *)((char *)&iph + IP::get_hlen() * 4);
	return *this;
}


/* Set the type-field in the actuall ICMP-packet.
 */
int ICMP::set_type(u_int8_t t)
{       
        icmphdr.type = t;
        return 0;
}

/*! Get the type-field from the actuall ICMP-packet.
 */
u_int8_t ICMP::get_type()
{
   	return icmphdr.type;
}

/* Set ICMP-code.
 */
int ICMP::set_code(u_int8_t c)
{
   	icmphdr.code = c;
        return 0;
}

/* Get ICMP-code.
 */
u_int8_t ICMP::get_code()
{
   	return icmphdr.code;
}

int ICMP::set_gateway(u_int32_t g)
{
   	icmphdr.un.gateway = htonl(g);
        return 0;
}

u_int32_t ICMP::get_gateway()
{
   	return ntohl(icmphdr.un.gateway);
}

int ICMP::set_mtu(u_int16_t mtu)
{
   	icmphdr.un.frag.mtu = mtu;
   	return 0;
}

u_int16_t ICMP::get_mtu()
{
   	return icmphdr.un.frag.mtu;
}

/* Set id field in the actuall ICMP-packet 
 */
int ICMP::set_icmpId(u_int16_t id)
{
   	icmphdr.un.echo.id = id;
        return 0;
}

/* Get the id field from actuall ICMP-packet.
 */
u_int16_t ICMP::get_icmpId()
{
   	return icmphdr.un.echo.id;
}

/* Set the sequecenumber of the actuall ICMP-packet.
 */
int ICMP::set_seq(u_int16_t s)
{
   	icmphdr.un.echo.sequence = s;
        return 0;
}

/* Get the sequence-number of actuall ICMP-packet
 */
u_int16_t ICMP::get_seq()
{
   	return icmphdr.un.echo.sequence;
}

/* get orig datagram from icmp unreachable
 *
 */
iphdr ICMP::get_orig() {
    iphdr iph = *(iphdr *)((char *)(&icmphdr + 1));
    return iph;
}


/* send an ICMP-packet containing 'payload' which
 *  is 'paylen' bytes long
 */
int ICMP::sendpack(void *payload, size_t paylen)
{
   	size_t len = sizeof(struct icmphdr) + paylen;	// the packetlenght
                
        struct icmphdr *i;

        // s will be our packet
   	char *s = new char[len];
        memset(s, 0, len);
        
        // copy ICMP header to packet
        memcpy((char*)s, (struct icmphdr*)&this->icmphdr, sizeof(icmphdr));

   	if (payload)
           	memcpy(s+sizeof(icmphdr), payload, paylen);

        i = (struct icmphdr*)s;
        
        // calc checksum over packet
        //i->sum = 0;
	
	if (i->sum == 0)
		i->sum = in_cksum((unsigned short*)s, len, 0);
        
        int r = IP::sendpack(s, len);
    	delete[] s;
	return r;    
}

/* send a ICMP-packet with string 'payload' as payload.
 */
int ICMP::sendpack(char *payload)
{
   	return sendpack(payload, strlen(payload));
}

/* send standard UNIX-like ICMP echo request payload 
 */
int ICMP::send_ping_payload()
{
	struct _Timestamp {
		u_int sec;
		u_int usec;
	} Timestamp;
	struct timeval tv;
	int tocopy, iii=0;
	char payload[PING_PAYLOAD_SIZE];

	if ((gettimeofday(&tv, NULL)) < 0)
		die ("ICMP::send_ping_payload: gettimeofday()", PERROR, 1);
	Timestamp.sec = htonl(tv.tv_sec);
	Timestamp.usec = htonl(tv.tv_usec);
	tocopy = PING_PAYLOAD_SIZE;
	while (tocopy > 0) {
		payload[iii] = iii;
		tocopy--;
		iii++;
	}
	memcpy (payload, &Timestamp, sizeof(Timestamp));
	return sendpack(payload, PING_PAYLOAD_SIZE);
}

int ICMP::send_timestamp_payload() 
{
	struct timeval tv;
	char payload[TIMESTAMP_PAYLOAD_SIZE];

	if ((gettimeofday(&tv, NULL)) < 0)
		die("ICMP::send_timestamp_payload: gettimeofday()", PERROR, 1);	
	memset (payload, 0, TIMESTAMP_PAYLOAD_SIZE);
	tv.tv_usec = htonl(tv.tv_usec);
	memcpy(payload, &tv.tv_usec, sizeof(tv.tv_usec));
	return sendpack(payload, TIMESTAMP_PAYLOAD_SIZE);
}

int ICMP::send_addrmask_payload()
{
	char payload[ADDRMASK_PAYLOAD_SIZE];
	memset (payload, 0, ADDRMASK_PAYLOAD_SIZE);
	return sendpack(payload, ADDRMASK_PAYLOAD_SIZE);
}

/* handle packets, that are NOT actually for the
 *  local adress!
 */
int ICMP::sniffpack(void *s, size_t len)
{
	size_t plen = len + sizeof(struct icmphdr);
   	char *tmp = new char[plen];
        int r = 0;
	memset(s, 0, len);
	memset(tmp, 0, plen);
	
   	r = IP::sniffpack(tmp, plen);

	if (r == 0 && Layer2::timeout()) {	// timeout
		delete[] tmp;
		return 0;
	}
	
        // point to ICMP header
        struct icmphdr *icmph = (struct icmphdr*)(tmp);

	memset(&icmphdr, 0, sizeof(icmphdr));

        // save ICMP header for public functions
        memcpy(&icmphdr, icmph, sizeof(struct icmphdr));
        
        // and give user the payload
	if (s)
    		memcpy(s, ++icmph, len);
        
        delete[] tmp;
        return r - sizeof(struct icmphdr);
}    

/*  Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
int ICMP::init_device(char *dev, int promisc, size_t snaplen)
{
        int r = Layer2::init_device(dev, promisc, snaplen);
	if (r < 0)
		die("ICMP::init_device", STDERR, 1);
	r = Layer2::setfilter("icmp");
	if (r < 0)
		die("ICMP::init_device", STDERR, 1);
        return r;
}

} // namespace usipp

