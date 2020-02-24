/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef _TX_H_
#define _TX_H_

#include "config.h"
#include "usi++/usi-structs.h"
#include <stdio.h>

namespace usipp {

/*! \class TX
 * The transmitter lets you send packets on the net.
 * You can write your own and register them with
 * register_tx() but you must provide at least
 * sendpack(). Shipped with USI++ is TX_IP which
 * is in fact a RAW socket */ 
class TX {
public:
	TX() {}
	virtual ~TX() {}
	
	/*! Do the send. You don't call this directly. IP::sendpack() etc
	 * deliver the request to here. YOur task is only to provide a sendpack()
	 * when you write your own TX classes. */
	virtual int sendpack(void *, size_t, struct sockaddr *) = 0;

	/*! Must have capability to send broadcast packets. May be
	 * just a dummy. */
	virtual int broadcast() = 0;


	/*! set a timeout */
	virtual int timeout(struct timeval) = 0;

	/*! RX derived class must also tell user when timeout occurs */
	virtual bool timeout() = 0;
};

} // namespace usipp

#endif

