#include <stdio.h>
#include <usi++/usi++.h>

int main(int argc, char **argv)
{

	if (argc < 2) {
		printf("Usage: %s destination\n", argv[0]);
		exit(1);
	}
	
   	IP ip(argv[1], IPPROTO_TCP);
	IP ip2(argv[1], IPPROTO_ICMP);
	
	ip.set_id(11);

	ip.set_fragoff(1);
	ip.sendpack("YYYYYYYY");


        ip.set_fragoff(IP_MF|0);
        ip.sendpack("XXXXXXXX");

	ip2.set_id(112);

	ip2.set_fragoff(IP_MF|0);
	ip2.sendpack("xxxxxxxx");
        
	ip.set_id(77);
	ip.set_fragoff(IP_DF);
	ip.sendpack("AAA");	


	ip2.set_fragoff(2);
	ip2.sendpack("zzzzzzzz");

	IP *ip3 = new IP(ip2);
	IP *ip4;
        
	*ip4 = *ip3;
	
	delete ip3;
	ip4->set_fragoff(IP_MF|1);
	ip4->sendpack("yyyyyyyy");

	
        return 0;
}

