/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef _LAYER2_H_
#define _LAYER2_H_

#include "config.h"
#include "usi++/usi-structs.h"
#include "RX.h"
#include "TX.h"

#include <stdio.h>

namespace usipp {

/*! \class Layer2
 *  Describing layer 2
 */
class Layer2 {
private:
	RX *d_rx;		// for receiving
	TX *d_tx;		// for transmitting data
public:
	/*! Give us a Layer 2! Default to Raw IP sockets and
	 * pcap packet capturing. This MUST NOT be. You could also
	 * say you want to use ethertap devices etc.
	 */
	Layer2(RX *r = NULL, TX *t = NULL);
	
	/*!*/
	virtual ~Layer2();
	Layer2(const Layer2&);

	/*! Actually, capture a packet */
	virtual int sniffpack(void *, size_t);

	/*! Send a packet */
	virtual int sendpack(void *buf, size_t len, struct sockaddr *);

	/*! Initialize a device for packet capturing */
	virtual int init_device(char *dev, int promisc, size_t snaplen);

	/*! Set a filter rule */
	int setfilter(char *f);	

	/*! Set a timeout */
	int timeout(struct timeval);

	/*! return was timeout? */
	bool timeout();
	
	/*! register a new transmitter, return the old */
	TX *register_tx(TX *t) { TX *r = d_tx; d_tx = t; return r; }
	
	/*! register a new capturer, return the old */
	RX *register_rx(RX *r) { RX *ret = d_rx; d_rx = r; return ret; }

	/*! return current TX object */
	TX *tx() { return d_tx; }

	/*! return current RX object */
	RX *rx() { return d_rx; }	
	Layer2& operator=(const Layer2 &);

};

} // namespace usipp
#endif
