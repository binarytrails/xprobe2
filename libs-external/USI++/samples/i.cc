#include <stdio.h>
#include <usi++/usi++.h>
#include <sys/time.h>


int main()
{
	char buf[1024], sbuf[1024], s[100], d[100];
	ICMP sn("127.0.0.1"), icmp("192.0.0.2");
 	
	sn.init_device("eth0", 0, 500);

	icmp.set_src("192.0.0.1");
	icmp.set_type(ICMP_ECHO);
//	icmp.sendpack("XYZ");

	cout<<sn.setfilter("ip and dst 192.0.0.1")<<endl;
	cout<<sn.sniffpack(sbuf, sizeof(buf))<<endl;
	cout<<sn.get_src(1, s,100)<<"->"<<sn.get_dst(1, d,100)<<endl;
	
	usipp::iphdr iph = sn.get_iphdr();

	sn.set_dst("192.0.0.3");
	icmp.set_gateway(ntohl(sn.get_dst()));
	icmp.set_type(ICMP_REDIRECT);
	icmp.set_code(ICMP_REDIR_HOSTTOS);
	iph.tos = 0x10;
	memcpy(buf, &iph, sizeof(iph));
	memcpy(&buf[sizeof(iph)], sbuf, 8);
	for (;;) {
		icmp.sendpack(buf, 28);
		sleep(10);
	}
	
	return 0;
}

