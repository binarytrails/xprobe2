// Simplified traceroute using SYN packets to fool IDS's and filters
// (C) 2001 by Sebastian Krahmer
// sample program to demonstrace power of libUSI++
// licensed under the GPL
// Don't run multiple instances of this program at the same
// time. Also don't run normal traceroute meanwhile, sicne
// they probably confuse each other.
#include <iostream.h>
#include <usi++/usi++.h>
#include <usi++/tcp.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int udp_trace(char *, char *, char *, int);
int tcp_trace(char *, char *, char *, int);
int icmp_trace(char *, char *, char *, int);
int ip_trace(char *, char *, char *, int);

void usage()
{
	cout<<"Usage: trace <-s src> <-d dst> [-T port] [-t type] [-D dev] [-U port] [-Ii]\n\n"
	      "-U use normal UDP style trace to 'port'\n"
	      "-T use TCP style trace (SYN) to 'port'\n"
	      "-I use ICMP trace with type 'type' (defaults to ECHO_REPLY)\n"
	      "-D use 'dev' for capturing. default eth0\n"
	      "-i use raw IP packets for trace\n\n";
	exit(0);
}

int main(int argc, char **argv)
{
		
	int c;
	int type = 1, port = 53;
	bool udp = false, tcp = false, icmp = false, ip = false, dst = false, src = false;
	char source[1000], dest[1000], dev[10];

	strcpy(dev, "eth0");
	while ((c = getopt(argc, argv, "D:d:s:t:U:T:Ii")) != -1) {
		switch (c) {
		case 't':
			type = atoi(optarg);
			break;
		case 's':
			strncpy(source, optarg, sizeof(source));
			src = true;
			break;
		case 'd':
			strncpy(dest, optarg, sizeof(dest));
			dst = true;
			break;
		case 'U':
			udp = true;
			port = atoi(optarg);
			break;
		case 'T':
			tcp = true;
			port = atoi(optarg);
			break;
		case 'I':
			icmp = true;
			break;
		case 'D':
			strncpy(dev, optarg, sizeof(dev));
			break;
		case 'i':
			ip = true;
			break;
		default:
			usage();
		}
	}

	if (!dest || !src)
		usage();
		
	cout<<"[=== IP datagrams to "<<dest<<" are routed through ===]\n\n";
	if (udp)
		udp_trace(dest, source, dev, port);
	else if (tcp)
		tcp_trace(dest, source, dev, port);
	else if (icmp)
		icmp_trace(dest, source, dev, type);
	else if (ip)
		ip_trace(dest, source, dev, type);
	else 
		cerr<<"You must at least give me UDP,TCP,ICMP or IP!\n";
	cout<<endl;
	return 0;
}

int ip_trace(char *dst, char *src, char *dev, int type)
{
	char buf[1000], buf2[1000];
	ICMP sn("127.0.0.1");
	IP ip(dst, type);
	
	ip.set_src(src);
	
	sn.init_device(dev, 0, 500);
	sn.setfilter("icmp and (icmp[0] == 11 or icmp[0] == 0 or icmp[0] == 3)");
	
	for (int i = 1; i < 64; i++) {
		memset(buf, 0, sizeof(buf));
		memset(buf2, 0, sizeof(buf2));
		ip.set_ttl(i);
		ip.sendpack("");
		sn.sniffpack(NULL, 0);
		
		cout<<"  "<<i<<"  "<<sn.get_src(1, buf, 100)<<" ("<<sn.get_src(0,buf2,100)<<")\n";
		if (sn.get_type() == 3 || sn.get_type() == 0)
			break;
	}
	return 0;
}
	
int icmp_trace(char *dst, char *src, char *dev, int type)
{
	char buf[1000], buf2[1000];
	ICMP sn("127.0.0.1");
	ICMP icmp(dst);
	
	icmp.set_src(src);
	icmp.set_type(type);
	
	sn.init_device(dev, 0, 500);
	sn.setfilter("icmp and (icmp[0] == 11 or icmp[0] == 0 or icmp[0] == 3)");
	
	for (int i = 1; i < 64; i++) {
		memset(buf, 0, sizeof(buf));
		memset(buf2, 0, sizeof(buf2));
		icmp.set_ttl(i);
		icmp.sendpack("");
		sn.sniffpack(NULL, 0);
		
		cout<<"  "<<i<<"  "<<sn.get_src(1, buf, 100)<<" ("<<sn.get_src(0,buf2,100)<<")\n";
		if (sn.get_type() == 3 || sn.get_type() == 0)
			break;
	}
	return 0;
}
	


int udp_trace(char *dst, char *src, char *dev, int port)
{
	char buf[1000], buf2[1000];
	ICMP sn("127.0.0.1");
	UDP udp(dst);
	
	udp.set_src(src);
	udp.set_dstport(port);
	udp.set_srcport(53);
	
	sn.init_device(dev, 0, 500);
	sn.setfilter("icmp and (icmp[0] == 11 or icmp[0] == 3)");
	
	for (int i = 1; i < 64; i++) {
		memset(buf, 0, sizeof(buf));
		memset(buf2, 0, sizeof(buf2));
		udp.set_ttl(i);
		udp.sendpack("");
		sn.sniffpack(NULL, 0);
		
		cout<<"  "<<i<<"  "<<sn.get_src(1, buf, 100)<<" ("<<sn.get_src(0,buf2,100)<<")\n";
		if (sn.get_type() == 3)
			break;
	}
	return 0;
}
	

int tcp_trace(char *dst, char *src, char *dev, int port)
{
	TCP tcp(dst);
	IP sn("127.0.0.1", 123);
	
	char buf[100], buf2[100];
	
	tcp.set_dstport(port);
	tcp.set_src(src);
	tcp.set_srcport(1234);
	tcp.set_flags(TH_PUSH);

	sn.init_device(dev, 0, 500);
	sn.setfilter("(icmp and icmp[0] == 11) or (tcp and dst port 1234)");
	
	for (int i = 1; i < 64; i++) {
		memset(buf, 0, sizeof(buf));
		memset(buf2, 0, sizeof(buf2));
		
		tcp.set_ttl(i);
		tcp.sendpack("");
		sn.sniffpack(NULL, 0);
		
		cout<<"  "<<i<<"  "<<sn.get_src(1, buf, 100)<<" ("<<sn.get_src(0,buf2,100)<<")\n";
		if (sn.get_proto() == IPPROTO_TCP)
			break;
	}
	return 0;
}

