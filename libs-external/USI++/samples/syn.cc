#include <iostream>
#include <usi++/usi++.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace usipp;

int main(int argc, char **argv)
{
	if (argc < 5) {
		cerr<<"Usage: "<<*argv<<" <src-ip> <dst-ip> <src-port> <dst-port>\n";
		exit(1);
	}

	u_int16_t sport = atoi(argv[3]);
	u_int16_t dport = atoi(argv[4]);

	TCP tcp(argv[2]);

	tcp.set_srcport(sport);
	tcp.set_dstport(dport);

	if (strcmp(argv[1], "0") != 0)
		tcp.set_src(argv[1]);

	tcp.set_seq(1);
	tcp.set_ack(0);
	tcp.set_flags(TH_SYN);
	
	tcp.sendpack("");

	return 0;
}

