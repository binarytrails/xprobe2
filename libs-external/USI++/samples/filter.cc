// Small program to find out packet-filtered ports
// (SYN) (C) 2001 Sebastian Krahmer, use at your own risk
#include <stdio.h>
#include <usi++/tcp.h>
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>
#include <time.h>
#include <map>

using namespace usipp;
using namespace std;

#define MINPORT 1
#define MAXPORT 2 


int main(int argc, char **argv)
{
	char s[1000], filter[1000];

	// only TRUEs allowed. Closed ports dont
	// appear here
	map<unsigned short, bool> push_open, syn_open;
	
	unsigned short port = 0;
	struct timeval tv;
	
	if (argc <= 3) {
		printf("usage: %s <target> <source> <interface>\n", argv[0]);
		exit(1);
	}

	TCP tcp(argv[1]), sn("localhost");	
	
	// setting port to >1023 will avoid source-port alerts in IDS
	tcp.set_srcport(7350);

	if (strcmp(argv[2], "0") != 0)
		tcp.set_src(argv[2]);
	
	// one might change this to TH_URG to have an urgent-scan then
	tcp.set_flags(TH_PUSH);

	// Do push-scan
	sn.init_device(argv[3], 1, 60);
	snprintf(filter, sizeof(filter), 
		"tcp and src %s and dst %s and port 7350", argv[1], argv[2]);
	sn.setfilter(filter);
	for (port = MINPORT; port <= MAXPORT; port++) {
		tcp.set_dstport(port);
    		tcp.sendpack("");
		tv.tv_usec = 0;
		tv.tv_sec = 2;
		sn.timeout(tv);
		if (sn.sniffpack(s, 60) == 0 && sn.timeout())
			push_open[port] = true;

	}

	tcp.set_flags(TH_SYN);
	for (port = MINPORT; port <= MAXPORT; port++) {
		tcp.set_dstport(port);
    		tcp.sendpack("");
		tv.tv_usec = 0;
		tv.tv_sec = 2;
		sn.timeout(tv);
		if (sn.sniffpack(s, 60) == 0 && sn.timeout())
			continue;
		if (sn.get_flags() == (TH_ACK|TH_SYN))
			syn_open[port] = true;
	}
	map<unsigned short, bool>::iterator i;
	for (i = push_open.begin(); i != push_open.end(); ++i)
		printf("%d P-open.\n", i->first);

	printf("---\n");
	for (i = syn_open.begin(); i != syn_open.end(); ++i)
		printf("%d S-open.\n", i->first);

	return 0;
}

