/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/

#ifndef _IP_H_
#define _IP_H_

#include "usi-structs.h"
#include "datalink.h"
#include "Layer2.h"
#include <stdio.h>

namespace usipp {

/*! \class IP
 *  All about IP
 */
class IP : public Layer2 {
protected:
	struct iphdr iph;
	char ipOptions[40];
        struct sockaddr_in saddr;
	char host[1000];
        
        char *reassemble(char *, int, int *);
public:

	/*! Expects destination-adress and protocol
         */
      	IP(const char*, u_int8_t);	// IP("foo.foo", IPPROTO_TCP);

	/*! Destination-adress in network-order
         */
        IP(u_int32_t, u_int8_t);	

    /*! expects ipheader */
    IP(iphdr &iphh);    

	/*! Destructor
	 */
        virtual ~IP();

	/*! Returns headerlen/4.
         */
      	u_int8_t get_hlen() const;

	/*! returns IP-version. Should give 4 always.
         */
        u_int8_t get_vers() const;

	/*! Get Type Of Service.
         */
        u_int8_t get_tos() const;

	/*! Get total length of packet, including any data.
         *  Return len in host-order.
         */
        u_int16_t get_totlen() const;

	/*! Get id-field.
         */
        u_int16_t get_id() const;

	/*! Get fragmentation offset.
	 */
        u_int16_t get_fragoff() const;

	/*!*/
        u_int16_t get_fflags() const;

	/*! Get Time To Live field (TTL)
	 * \example trace.cc
         */
        u_int8_t get_ttl() const;

	/*! Get protocol, TCP or such.
         */
        u_int8_t get_proto() const;

	/*! Get IP-header checksum
         */
        u_int16_t get_sum() const;

    /*! Return the IP header checksum(meder)
     */
    u_int16_t calc_ipsum();

	/*! Get source-adress of packet, in network order.
         */
        u_int32_t get_src() const;

	/*! Ditto, destination-adress.
 	 */
        u_int32_t get_dst() const;

	/*! assig-operator
 	 */
	IP &operator=(const IP&);

	/*! Copy-construktor
	 */
	IP(const IP&); 

	/*! Get source-adress i human-readable-form.
         *  Resolve to an hostname, if resolv==1.
         */
        char *get_src(int resolv, char *buf, size_t buflen);

	/*! Ditto, destination-adress.
         */
	char *get_dst(int resolv, char *buf, size_t buflen);
        
	/*! Set header-len in number of 32 bit words. 5 (5*4 = 20) in normal case.
         *  Contructor does this for you, so you should not use this. 
         */
        int set_hlen(u_int8_t);

	/*! Set version-field. Normally not needed.
         */
        int set_vers(u_int8_t);

	/*!*/
        int set_tos(u_int8_t);

	/*! Set total length of packet. Not needed.
         */
        int set_totlen(u_int16_t);

	/*! Set ID-field. Also not needed.
         */
        int set_id(u_int16_t);

	/*!*/
        int set_fragoff(u_int16_t);

	/*!*/
        int set_fflags(u_int16_t);

	/*! Set time-to-live field. Not needed.
         */
        int set_ttl(u_int8_t);

	/*! Set protocol. If you use TCP {} or such, you don't need to
         *  do it yourself.
         */
        int set_proto(u_int8_t);
    
	/*!*/
        int set_sum(u_int16_t);	 // should NOT be used; just to be complete...

	/*! Set source-adress. Expects Network-ordered.
         */
        int set_src(u_int32_t);

	/*! Ditto, destination.
         */
        int set_dst(u_int32_t);

	/*! Set source-adress.
         */
        int set_src(const char *ip_or_name);
        
	/*! Ditto, destination. Not needed if the destination given
         *  in the constructor is OK.
         */
	int set_dst(const char*);

	/*! Return complete IP header.
	 * usefull for special ICMP packets
	 */
	iphdr get_iphdr() const;
	int set_iphdr(struct iphdr);

	/*! Send a Packet.
         */
	virtual int sendpack(void *payload, size_t paylen);
	
	/*!*/
	virtual int sendpack(char *pay_string);
	
	/*! Capture an packet from the net
         */
        virtual int sniffpack(void *buf, size_t len);

	/*!*/
	virtual int init_device(char *, int, size_t);

	friend bool operator== (const IP& left, const IP& right) {
		/*
		 * XXX: leave IP options comparison for later
		 */
		return (left.get_src() == right.get_src() &&
				left.get_dst() == right.get_dst()&&
				left.get_hlen() == right.get_hlen() &&
				left.get_tos() == right.get_tos() &&
				left.get_totlen() == right.get_totlen() &&
				left.get_fragoff() == right.get_fragoff() &&
				left.get_ttl() == right.get_ttl() &&
				left.get_proto() == right.get_proto() &&
				((left.get_id() != 0 && right.get_id() != 0) || (left.get_id() == 0 && right.get_id() == 0))
				);
	}
	virtual std::string to_string(void);
};


} // namespace

#endif // _IP_H_

