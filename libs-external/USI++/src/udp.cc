/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
 

#include "usi++/usi-structs.h"
#include "usi++/udp.h"

#include <string.h>
#include <errno.h>

namespace usipp {

UDP::UDP(const char *host)
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
      : IP(host, IPPROTO_UDP)
{
   	memset(&d_udph, 0, sizeof(d_udph));        
        memset(&d_pseudo, 0, sizeof(d_pseudo));
}

UDP::~UDP()
{
}


UDP::UDP(const UDP &rhs)
	: IP(rhs)
{
	if (this == &rhs)
		return;
	d_udph = rhs.d_udph;
	d_pseudo = rhs.d_pseudo;
}

UDP &UDP::operator=(const UDP &rhs)
{
	if (this == &rhs)
		return *this;
	IP::operator=(rhs);
	d_udph = rhs.d_udph;
	d_pseudo = rhs.d_pseudo;
	return *this;
}


UDP &UDP::operator=(const IP &rhs)
{
    iphdr iph;
	if (this == &rhs)
		return *this;
	IP::operator=(rhs);
    iph = IP::get_iphdr();
	d_udph = *(udphdr *)((char *)&iph + IP::get_hlen() * 4);
	return *this;
}


/* Get the sourceport of UDP-datagram.
 */
u_int16_t UDP::get_srcport()
{
   	return ntohs(d_udph.source);
}

/* Get the destinationport of the UDP-datagram
 */
u_int16_t UDP::get_dstport()
{
   	return ntohs(d_udph.dest);
}

/* Return length of UDP-header plus contained data.
 */
u_int16_t UDP::get_len()
{
   	return ntohs(d_udph.len);
}

/* Return the checksum of UDP-datagram.
 */
u_int16_t UDP::get_udpsum()
{
   	return d_udph.check;
}

/* Set the sourceport in the UDP-header.
 */
int UDP::set_srcport(u_int16_t sp)
{
   	d_udph.source = htons(sp);
        return 0;
}

/* Set the destinationport in the UDP-header.
 */
int UDP::set_dstport(u_int16_t dp)
{
   	d_udph.dest = htons(dp);
        return 0;
}

/* Set the length of the UDP-datagramm.
 */
int UDP::set_len(u_int16_t l)
{
   	d_udph.len = htons(l);
        return 0;
}

/* Set the UDP-checksum. Calling this function with s != 0
 *  will prevent sendpack() from setting the checksum!!!
 */
int UDP::set_udpsum(u_int16_t s)
{
   	d_udph.check = s;
        return 0;
}

udphdr UDP::get_udphdr()
{
	return d_udph;
}


/* Send an UDP-datagramm, containing 'paylen' bytes of data.
 */
int UDP::sendpack(void *buf, size_t paylen)
{
	size_t len = paylen + sizeof(d_udph) + sizeof(d_pseudo);
	char *tmp = new char[len+1];	// for padding, if needed
	memset(tmp, 0, len+1);

    memset(&d_pseudo, 0, sizeof(d_pseudo));
   	// build a pseudoheader for IP-checksum, as
        // required per RFC ???	
	d_pseudo.saddr = get_src();	// sourceaddress
	d_pseudo.daddr = get_dst();	// destinationaddress
	d_pseudo.zero = 0;
	d_pseudo.proto = IPPROTO_UDP;
	d_pseudo.len = htons(sizeof(d_udph) + paylen);


	if (d_udph.len == 0)
		d_udph.len = htons(paylen + sizeof(d_udph));


        // copy pseudohdr+header+data to buffer
	memcpy(tmp, &d_pseudo, sizeof(d_pseudo));
	memcpy(tmp + sizeof(d_pseudo), &d_udph, sizeof(d_udph));
	memcpy(tmp + sizeof(d_pseudo) + sizeof(d_udph), buf, paylen);

        // calc checksum over it
	struct udphdr *u = (struct udphdr*)(tmp + sizeof(d_pseudo));

	if (d_udph.check == 0) {
		u->check = in_cksum((unsigned short*)tmp, len, 1);
		d_udph.check = u->check;
	}

	IP::sendpack(tmp + sizeof(d_pseudo), len - sizeof(d_pseudo));

	delete [] tmp;
	return 0;
}


int UDP::sendpack(char *s)
{
	return sendpack(s, strlen(s));
}

        
/* Capture packets that are not for our host.
 */ 
int UDP::sniffpack(void *buf, size_t len)
{  	
        char *tmp = new char[len+sizeof(d_udph)];
	int r = 0;
        memset(tmp, 0, len + sizeof(d_udph));
        
        r = IP::sniffpack(tmp, len + sizeof(d_udph));
	if (r == 0 && Layer2::timeout()) {	// timeout
		delete[] tmp;
		return 0;
	}

	memset(&d_udph, 0, sizeof(d_udph));
        memcpy(&d_udph, tmp, sizeof(d_udph));

	if (buf)
    		memcpy(buf, tmp + sizeof(d_udph), len);
        
        delete [] tmp;
        return r-sizeof(d_udph);
}

/* Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
int UDP::init_device(char *dev, int promisc, size_t snaplen)
{
        int r = Layer2::init_device(dev, promisc, snaplen);
	
	if (r < 0)
		die("UDP::init_device", STDERR, 1);
	r = Layer2::setfilter("udp");
	if (r < 0)
		die("UDP::init_device::setfilter", STDERR, 1);
        return r;
}

} // namespace usipp


