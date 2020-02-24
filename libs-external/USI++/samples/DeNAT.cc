#include <iostream.h>
#include <usi++/usi++.h>
#include <usi++/tcp.h>

int main(int argc, char **argv)
{
	TCP *dev1 = new TCP("127.0.0.1"), *tcp = new TCP("127.0.0.1");
	char buf[512], src[512], dst[512];
	
	dev1->init_device("eth0", 1, 500);
	
	while (1) {
		dev1->sniffpack(buf, sizeof(buf));
		
		if (dev1->get_flags() != TH_SYN)
			continue;
			
		cout<<"Seen "<<dev1->get_src(1,src,512)<<":"<<dev1->get_srcport()<<" -> "<<dev1->get_dst(1,dst,512)
		    <<":"<<dev1->get_dstport()<<endl;
		    
		tcp->set_dst(dev1->get_src());
		tcp->set_dstport(dev1->get_srcport());
		tcp->set_srcport(dev1->get_dstport());
		tcp->set_src(dev1->get_dst());
		tcp->set_flags(TH_SYN|TH_ACK);
		tcp->set_seq(7350);
		tcp->set_ack(dev1->get_seq()+1);
		tcp->sendpack("");
	}
	return 0;
}