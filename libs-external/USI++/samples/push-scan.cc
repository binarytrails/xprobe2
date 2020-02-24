/*** Implementation of a modified NULL-scan.
 *** One can set the flags PUSH, URG or any other (not SYN, ACK or RST)
 *** (1<<10 for example) which UNIX systems will reply with RST packets
 *** on open ports and silent discard on open ports. This makes one
 *** able to detect open ports and to bypass some IDS which at most
 *** expect a flag of 0 (NULL-scan). Please update your snort rule-file
 *** to detect urg or push-scans.
 *** This program is (C) 2000 by S. Krahmer under the GPL.
 ***
 *** Thanx to Mike, Scut and Cyberlord for allowing scans to
 *** their machines. 
 ***
 *** Sebastian.
 ***/
#include <stdio.h>
#include <usi++/tcp.h>
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>

using namespace usipp;

#define MINPORT 1
#define MAXPORT 2 

int port = 0;
sigjmp_buf foo;

void handler(int)
{
	printf("Port %d open.\n", port);

	// you might get a segfault here if a probe of MINPORT
	// exceeds the alarm-time, and foo is therefore not defined.
	siglongjmp(foo, 1);
}

int set_breakout()
{
	if (sigsetjmp(foo, 1) == 0)
		return 0;
	else {
		printf("No ports open, or scan doesn't work.\n");
		exit(1);
	}
}


int main(int argc, char **argv)
{
	char s[1000], filter[1000];
	
	if (argc <= 3) {
		printf("usage: %s <target> <source> <interface>\n", argv[0]);
		exit(1);
	}
	printf("Silent push-scan. (C) 2000 by S. Krahmer. FOR EDUCATIONAL PURPOSES ONLY.\n\n");

	set_breakout();
	
	TCP *tmp = new TCP(argv[1]), sn("localhost");	
	signal(SIGALRM, handler);
	
	TCP tcp(*tmp);	// test for copy-constructor
	
	// setting port to >1023 will avoid source-port alerts in IDS
	tcp.set_srcport(7350);

	if (strcmp(argv[2], "0") != 0)
		tcp.set_src(argv[2]);
	
	// one might change this to TH_URG to have an urgent-scan then
	tcp.set_flags(TH_PUSH);

	sn.init_device(argv[3], 60, 1);
	snprintf(filter, sizeof(filter), "tcp and src %s and dst %s and port 7350", argv[1], argv[2]);
	sn.setfilter(filter);
	for (port = MINPORT; port <= MAXPORT; port++) {
		tcp.set_dstport(port);
    		tcp.sendpack("");
		alarm(3);
		signal(SIGALRM, handler);
		sn.sniffpack(s, 60);
		sigsetjmp(foo, 1);
	}
	return 0;
}

