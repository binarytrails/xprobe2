#include "icmp_port_unreach.h"

int icmp_port_unreach::getrandom(int limit)
{
    int rnum;
#ifdef OpenBSD
	arc4random();
	rnum = 1+arc4random()%limit;
	return rnum;
#endif
	struct timeval tp;
    struct timezone tzp;
    gettimeofday(&tp, &tzp);
    srand(tp.tv_usec);
    rnum=1+rand()%limit;
    return rnum;
}
