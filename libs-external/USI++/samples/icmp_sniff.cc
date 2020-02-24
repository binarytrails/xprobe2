/*** Simple ICMP-monitor. GPL.
 *** 
 ***/
#include <iostream.h>
#include <string.h>
#include <usi++/usi++.h>

int main(int argc, char **argv)
{
   	ICMP icmp("127.0.0.1");
        char buf[1000] = {0}, src[1000], dst[1000];
	int i = 0;
        	
	if (argc < 2) {
		cout<<argv[0]<<" [intf]\n";
		exit(1);
	}
	icmp.init_device(argv[1], 1, 500);
	
//	icmp.setfilter("icmp");
        char smac[100], dmac[100];
	while(1){
		memset(buf,0,1000);
    		// blocks
           	cout<<icmp.sniffpack(buf, 1000)<<endl;
#ifdef PRINT_MAC		
                cout<<"["<<icmp.get_hwsrc(smac, 100)<<"->"<<icmp.get_hwdst(dmac, 100)<<"]:";
#endif
		cout<<"type:"<<(int)icmp.get_type()<<" ["<<icmp.get_src(1, src, 1000)<<" -> "
		    <<icmp.get_dst(1, dst, 1000)<<"] "<<"seq: "<<icmp.get_seq()
		    <<" ttl: "<<(int)icmp.get_ttl()<<" id: "<<icmp.get_icmpId()<<endl;
		    //<<buf<<endl;
		
        }
        return 0;
}

