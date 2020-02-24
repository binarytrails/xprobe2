#include <usi++/usi++.h>
#include <string.h>
#include <iostream.h>

int main()
{
	char sip[100], dip[100];
   	IP ip("lucifer", IPPROTO_ICMP);
                
	char buf[100];
#ifdef linux
	ip.init_device("eth0", 1, 500);
#else
	ip.init_device("ed0", 1, 500);
#endif
	
	while (1) {
		int s = ip.sniffpack(buf, 10);
		printf("%s -> %s : ", ip.get_src(0, sip, 100), 
		                              ip.get_dst(0, dip, 100));
		for (int i = 0; i < s; i++)
			printf("%c", buf[i]);
		printf(" <-\n");
	}
        return 0;
}

        
