/* Sall testprogram for broadcast()
 * capabilities. (C) Sebastian Krahmer, use at your own risk.
 */
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <usi++/usi++.h>
#include <pcap.h>

int main(int argc, char **argv)
{
	char buf[100];

	if (argc < 2) {
		printf("i <broadcast-ip> <src-ip>\n");	
		return -1;
	}

	ICMP icmp(argv[1]);

	icmp.set_type(ICMP_ECHO);
	icmp.set_code(0);

	icmp.tx()->broadcast();

	icmp.set_src("0");
	icmp.sendpack("X");

	ICMP icmp2("0");
	
	icmp2.init_device("lo", 0, 500);
	struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	icmp2.timeout(tv);
	for (;;) {
		icmp2.sniffpack(buf, sizeof(buf));
		if (icmp2.timeout())
			break;
		cout<<icmp2.get_src(1, buf, sizeof(buf))<<endl;
	}
	return 0;
}

