/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#include "usi++/TX_IP.h"
#include "usi++/usi-structs.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

namespace usipp {

int TX_IP::sendpack(void *buf, size_t len, struct sockaddr *s)
{
		
   	// if not already opened a RAW-socket, do it!
   	if (rawfd < 0) {
	       // open a socket
               if ((rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
                       die("TX_IP::sendpack::socket", PERROR, errno);
               
	       int one = 1;
	       
               // let us write IP-headers
               if (setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
                       die("TX_IP::sendpack::setsockopt", PERROR, errno);
        }
    if (tx_timeout != false) 
        if (setsockopt(rawfd, SOL_SOCKET, SO_SNDTIMEO, &tx_tv, sizeof(tx_tv)) < 0)
            die("TX_IP::sendpack::setsockopt(SO_SNDTIMEO)", PERROR, errno);
	
	int r;
	if ((r = sendto(rawfd, buf, len, 0, s, sizeof(*s))) < 0)
		die("TX_IP::sendpack::sendto", PERROR, errno);
		
	return r;	
}

int TX_IP::broadcast()
{
	int one = 1;

	if (rawfd < 0) {
	       // open a socket
               if ((rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
                       die("TX_IP::sendpack::socket", PERROR, errno);
               
               // let us write IP-headers
               if (setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
                       die("TX_IP::sendpack::setsockopt", PERROR, errno);
        }

	if (setsockopt(rawfd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0)
			die("TX_IP::broadcast::setsockopt", PERROR, errno);
	return 0;
}

int TX_IP::timeout(struct timeval tv)
{
	tx_tv = tv;
	tx_timeout = true;
	return 0;
}

bool TX_IP::timeout()
{
	return tx_timeout;
}



} // namespace
