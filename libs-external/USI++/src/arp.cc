/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#include <stdio.h>
#include "config.h"
#include "usi++/usi-structs.h"
#include "usi++/arp.h"

#include <string.h>

namespace usipp {

ARP::ARP()
{
   	memset(&arphdr, 0, sizeof(arphdr));
}	

ARP::~ARP()
{
}

/*! Return the source-hardware-adress of a ARP-packet
 */
char *ARP::get_sha(char *hwaddr, size_t len) const
{
        
        // switch over the hardware-layer of the ARP-packet 
	switch (ntohs(arphdr.ea_hdr.ar_hrd)) {
   	case ARPHRD_ETHER:
                memcpy(hwaddr, arphdr.arp_sha, len<6?len:6);
                break;
        default:
           	return NULL;
        }
        return hwaddr;
}

/*! Return the destination-hardware-adress.
 */
char *ARP::get_tha(char *hwaddr, size_t len) const
{
        switch (ntohs(arphdr.ea_hdr.ar_hrd)) {
   	case ARPHRD_ETHER:
                memcpy(hwaddr, arphdr.arp_tha, len<6?len:6);
		break;
        default:
           	return NULL;
        }
        return hwaddr;
}

/*! Get target protocol-address.
 *  Only IP is supportet yet!
 */
char *ARP::get_tpa(int resolve, char *pa, size_t len) const
{
   	struct in_addr in;
        struct hostent *he;
        memset(pa, 0, len);
        
        // switch over protocol
	switch (ntohs(arphdr.ea_hdr.ar_pro)) {
	case ETH_P_IP:
                memcpy(&in, arphdr.arp_tpa, 4);
                if (!resolve || (he = gethostbyaddr((char*)&in, sizeof(in), AF_INET)) == NULL)
            	      	strncpy(pa, inet_ntoa(in), len);
                else
            	      	strncpy(pa, he->h_name, len);
                break;
        default:
           	return NULL;
        }
   	return pa;
}

/*! Get source protocol-adress.
 */
char *ARP::get_spa(int resolve, char *pa, size_t len) const
{
   	struct in_addr in;
        struct hostent *he;
        memset(pa, 0, len);
        
	switch (ntohs(arphdr.ea_hdr.ar_pro)) {
	case ETH_P_IP:
                memcpy(&in, arphdr.arp_spa, 4);
                if (!resolve || (he = gethostbyaddr((char*)&in, sizeof(in), AF_INET)) == NULL)
            	      	strncpy(pa, inet_ntoa(in), len);
                else
            	      	strncpy(pa, he->h_name, len);
                break;
        default:
           	return NULL;
        }
   	return pa;
}

/* Return the ARP-command.
 */
u_int16_t ARP::get_op() const
{
	return ntohs(arphdr.ea_hdr.ar_op);
}

int ARP::init_device(char *dev, int p, size_t len)
{
	return Layer2::init_device(dev, p, len);
}

int ARP::setfilter(char *s)
{
	return Layer2::setfilter(s);
}

/* Sniff for an ARP-request/reply ...
 */
int ARP::sniffpack()
{
	return Layer2::sniffpack((char*)&arphdr, sizeof(arphdr));
}

} // namespace usipp
