/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#ifndef _ARP_H_
#define _ARP_H_

#include "usi-structs.h"
#include "Layer2.h"
#include <stdio.h>

namespace usipp {

/* ARP arp.h
 * RFC826, the adress resolution protocol
 */
/*! \class ARP
 */
class ARP : public Layer2 {
private:
   	struct ether_arp arphdr;
   	
public:

	/*! Open device 'dev' for packet-capturing (ARP-packets)
	 *  ARP-objects don't need to call init_device().
	 */
   	ARP();	
   	
        virtual ~ARP();

        /*! Return the source-hardware-adress of a ARP-packet
	 */
   	char *get_sha(char *hwaddr, size_t len) const;

   	/*! Return the destination-hardware-adress.
	 */
        char *get_tha(char *hwaddr, size_t len) const;

	/*! Get source protocol-adress.
	 *  resolve to hostname (IP) when resolve == 1
	 */
        char *get_spa(int resolve, char *paddr, size_t len) const;

	/*! Get target protocol-adress.
	 *  Only IP is supportet yet!
	 */
	/*! \example arpw.cc
	 */
        char *get_tpa(int resolve, char *paddr, size_t len) const;

	/*! Return the ARP-command.
 	 */
        u_int16_t get_op() const;	

	/*! Sniff for an ARP-request/reply ...
	 * \example arpw.cc
	 */
        virtual int sniffpack();
	
	/*!*/
	virtual int init_device(char *, int, size_t);
	
	/*!*/
	virtual int setfilter(char *);
};
        
} // namespace usipp
#endif 	// _ARP_H_
 
