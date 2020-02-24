#include <iostream>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <usi++/usi++.h>


int main(int argc, char **argv)
{
	char buf[100];
	
   	if (argc < 3) {
           	cout<<"Usage: "<<argv[0]<<" host port\n";
                exit(1);
        }
        TCP *tmp = new TCP(argv[1]);

	TCP tcp("0");

	tcp = *tmp;	// test for operator=()

	delete tmp;
	tcp.init_device("eth0", 1, 100);
	tcp.setfilter("tcp and dst port 8000");

        tcp.set_flags(TH_SYN|TH_ACK);
        tcp.set_dstport(atoi(argv[2]));
	tcp.set_srcport(8000);


	tcp.set_src("192.0.0.1");
    	
	tcp.sendpack("");
	tcp.sniffpack(buf, 100);
	cout<<tcp.get_id();
			
        return 0;
}
