#include <stdio.h>
#include <usi++/tcp.h>

using namespace usipp;

int main()
{
	TCP tcp("liane");
	union tcp_options to;
	
	tcp.set_srcport(1024);
	tcp.set_dstport(515);
	
	tcp.set_flags(TH_SYN);
	to.one_word = 111;
	tcp.set_tcpopt(TCPOPT_MAXSEG, 4, to);
	tcp.sendpack("");

	tcp.reset_tcpopt();
	to.one_byte = 7;
	tcp.set_tcpopt(TCPOPT_WINDOW, 3, to);

	tcp.set_tcpopt(TCPOPT_NOP, 1, to);
	tcp.sendpack("A");
	tcp.reset_tcpopt();

	
	tcp.set_tcpopt(TCPOPT_NOP, 1, to);
	tcp.sendpack("A");

	tcp.reset_tcpopt();
	to.two_dwords[0] = 11223344;
	to.two_dwords[1] = 55667788;
	tcp.set_tcpopt(TCPOPT_TIMESTAMP, 10, to);
	tcp.sendpack("");
	return 0;
}