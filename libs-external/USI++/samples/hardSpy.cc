/* For educational purposes only!!!
 * Works only in a LAN, ofcorse.
 * Under the GPL
 */
#include <iostream>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <usi++/usi++.h>

const char *datfile = "../data/ethercodes.dat";

int decodeHW(char *, char *);

int main(int argc, char **argv)
{
   	if (argc < 2) {
           	cout<<"Usage: "<<argv[0]<<" host\n";
                exit(1);
        }
        srand(time(NULL));
        int r = rand() % 31337;
        char buf[100];
        
        ICMP icmp(argv[1]);

	cout<<"HardSpy v 0.1 by S. Krahmer\n"
	    <<"Pinging host "<<argv[1]<<" ... \n";

#ifdef linux	            
        icmp.init_device("eth0", 1, 100);
#else
	icmp.init_device("ed0", 1, 500);
#endif
        icmp.set_type(ICMP_ECHO);
        icmp.set_icmpId(r);
        icmp.sendpack("Hi, this is hardSpy!");
        icmp.set_icmpId(0);
        
        while (icmp.get_icmpId() != r || icmp.get_type() != ICMP_ECHOREPLY) {
           	icmp.sniffpack(buf, 100);
	}
		
	cout<<"Btw, the reply was: "<<buf<<endl;        
        char mac[100];
        decodeHW(argv[1], icmp.get_hwsrc(mac, 100));
        
        return 0;
}

                
int decodeHW(char *host, char *mac)
{
   	FILE *f;
        char s[10];
        char rbuf[1000];
        unsigned char c[3];
        
        memset(s, 0, 10);
        
        cout<<"The MAC of "<<host<<" is '"<<mac<<"'\n";
        
        if ((f = fopen(datfile, "r")) == NULL) {
           	perror("fopen");
                exit(errno);
        }
	
        mac[8] = 0;
        sscanf(mac, "%02x:%02x:%02x", c, &c[1], &c[2]);
        sprintf(s, "%x:%x:%x%c", c[0], c[1], c[2], 0x09);
        
        bool found = false;
	memset(rbuf, 0, 1000);
        while (fgets(rbuf, 1000-1, f) != NULL) {
		if (strncmp(rbuf, s, strlen(s)) == 0) {
                   	cout<<"That is -> "<<rbuf<<endl;
			found = true;
                }
                memset(rbuf, 0, 1000);
        }
	if (!found) {
		cout<<"Sorry, can't find "<<s<<" in my database.\n";
	}
        fclose(f);
        return 0;
}
                 
  	
