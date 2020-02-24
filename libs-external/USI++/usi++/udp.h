/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#ifndef _UDP_H_
#define _UDP_H_

#include "usi-structs.h"
#include "datalink.h"
#include "ip.h"

namespace usipp {

/** \class UDP
 *  All about UDP.
 */
class UDP : public IP {
private:
	struct udphdr d_udph;
	struct pseudohdr d_pseudo;
public:

	/*! Expects Host.
	 */
	UDP(const char*);
      
	/*! Destructor
	 */
	virtual ~UDP();

	/*! Copy-Constructor 
	 */
	UDP(const UDP &);

	/*! Assign-operator 
	 */
	UDP &operator=(const UDP&);

	/*! Assign-operator 
	 */
	UDP &operator=(const IP&);

	/*! Get the sourceport of UDP-datagram.
	 */
	u_int16_t get_srcport();


	/*! Get the destinationport of the UDP-datagram
	 */
	u_int16_t get_dstport();

	/*! Return length of UDP-header plus contained data.
	 */
	u_int16_t get_len();

	/*! Return the checksum of UDP-datagram.
	 */
	u_int16_t get_udpsum();

	/*! Set the sourceport in the UDP-header.
	*/
	int set_srcport(u_int16_t);

	/*! Set the destinationport in the UDP-header.
	 */
	int set_dstport(u_int16_t);

	/*! Set the length of the UDP-datagramm.
	 */
	int set_len(u_int16_t);

	/*! Set the UDP-checksum. Calling this function with s != 0
	 *  will prevent sendpack() from setting the checksum!!!
	 */
	int set_udpsum(u_int16_t);

	/*! Return complete UDP header.
	 *  Usefull for some kinds of ICMP messages 
	 */
	udphdr get_udphdr();

	/*! Send an UDP-datagramm, containing 'paylen' bytes of data.
	 */    
	virtual int sendpack(void*, size_t);
      
	/*!*/
	virtual int sendpack(char*);

	/*! Capture packets that are not for our host.
	 */ 
	virtual int sniffpack(void*, size_t);

	/*! Initialize a device ("eth0" for example) for packet-
	*  capturing. It MUST be called before sniffpack() is launched.
	*  Set 'promisc' to 1 if you want the device running in promiscous mode.
	*  Fetch at most 'snaplen' bytes per call.
	*/
	virtual int init_device(char *, int promisc, size_t snaplen);
      
};   // class UDP {}

} // namespace usipp

#endif // _UDP_H_


