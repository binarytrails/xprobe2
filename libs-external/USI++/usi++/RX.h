/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef _RX_H_
#define _RX_H_

#include "config.h"
#include "usi++/usi-structs.h"
#include <stdio.h>

namespace usipp {

/*! \class RX
 * Receiving object
 * You can provide your own classes and register objects
 * via register_rx(). You must provide at least the 3 functions
 * below.
 */
class RX {
public:
	RX() {}
	virtual ~RX() {}

	/*! Capture a packet from the network.
	 *  At most a given len. */	
	virtual int sniffpack(void *, size_t) = 0;
		
	/*! Init a device before capturing */
	virtual int init_device(char *, int, size_t) = 0;
	
	/*! Set a filter of what must be captured */
	virtual int setfilter(char *) = 0;

	/*! set a timeout */
	virtual int timeout(struct timeval) = 0;

	/*! RX derived class must also tell user when timeout occurs */
	virtual bool timeout() = 0;

};

} // namespace usipp
#endif
