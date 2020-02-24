#include <iostream.h>
#include <usi++/usi++.h>

// spoof a syslog message to a FreeBSD box.

int main(int argc, char **argv)
{


	UDP udp("localhost");
        udp.set_srcport(2500);
        udp.set_dstport(1174);
	udp.set_src("192.0.0.1");
       	udp.sendpack("XXX");
        return 0;
}
