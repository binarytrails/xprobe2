/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/

#ifndef _ICMP_H_
#define _ICMP_H_

#include "usi-structs.h"
#include "datalink.h"
#include "ip.h"

namespace usipp {


/*! \class ICMP icmp.h
 *  \brief the ICMP-class
 */
/*! \example icmp_sniff.cc
 */

class ICMP : public IP {
private:
   	struct icmphdr icmphdr;
public:
	/*! Expects host.
	 */
      	ICMP(const char*);
	/*! Expects destination i network byte order
	 */
		ICMP(u_int32_t);

	virtual ~ICMP();

	/*! Copy-Construktor */
	ICMP(const ICMP &);	

	/*! Assign-operator */
	ICMP &operator=(const ICMP &);

	/*! Assign-operator */
	ICMP &operator=(const IP &);

	/*! send an ICMP-packet containing 'payload' which
	 *  is 'paylen' bytes long
	 */
        virtual int sendpack(void*, size_t);

        /*! send a ICMP-packet with string 'payload' as payload.
	 */
        virtual int sendpack(char*);

		/*! send standard UNIX-like payload
	 */
		virtual int send_ping_payload();

		/*! send the ICMP timestamp request payload
	 */
		virtual int send_timestamp_payload();

		virtual int send_addrmask_payload();

        /*! handle packets, that are NOT actually for the
	 *  local adress!
	 */
        virtual int sniffpack(void*, size_t);

        /*! Initialize a device ("eth0" for example) for packet-
	 *  capturing. It MUST be called before sniffpack() is launched.
	 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
	 *  Fetch at most 'snaplen' bytes per call.
	 */
        virtual int init_device(char *, int, size_t);

        /*! Set the type-field in the actuall ICMP-packet.
	 */
        int set_type(u_int8_t);

        /*! Set ICMP-code.
 	 */
        int set_code(u_int8_t);

        /*! Set id field in the actuall ICMP-packet 
 	 */
        int set_icmpId(u_int16_t);

        /*! Set the sequecenumber of the actuall ICMP-packet.
	 */
        int set_seq(u_int16_t);
        
        int set_gateway(u_int32_t);
        
        int set_mtu(u_int16_t);

        /*! Get the type-field from the actuall ICMP-packet.
 	 */
        u_int8_t get_type();

        /*! Get ICMP-code.
 	 */
        u_int8_t get_code();

        /*! Get the id field from actuall ICMP-packet.
	 */
        u_int16_t get_icmpId();

        /*! Get the sequence-number of actuall ICMP-packet
	 */
        u_int16_t get_seq();

        iphdr get_orig();
        
        u_int32_t get_gateway();
        
        u_int16_t get_mtu();
}; // class ICMP{}



} // namespace usipp
#endif // _ICMP_H_
