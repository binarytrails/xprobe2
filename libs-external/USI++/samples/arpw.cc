/* Output looks similar to tcpdump -p arp ;-)
 */
#include <usi++/usi++>
#include <usi++/arp.h>
#include <iostream>

using namespace usipp;

char *print_mac(unsigned char *mac)
{
	static char m[100];	// uhhh.... :)
	
	memset(m, 0, sizeof(m));
	snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x", *mac, mac[1], mac[2], mac[3], mac[4], mac[5]);
	return m;
}


int main()
{

   	ARP *a = new ARP;

	a->init_device("eth0", 1, 100);
	    
        char shw[100], sip[100], dip[100];
        
        while (1) {
           	a->sniffpack();
		if (a->get_op() == ARPOP_REQUEST) {
			cout<<"arp who has "<<a->get_tpa(0, dip, 100)
			    <<" tell "<<a->get_spa(1, sip, 100)<<endl;
		}
		if (a->get_op() == ARPOP_REPLY) {
			cout<<a->get_spa(0, sip, 100)<<" is at "
			    <<print_mac((unsigned char*)a->get_sha(shw, 100))<<endl;
		}
        }
        return 0;
}

        
