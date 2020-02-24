/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#ifndef _TCP_H_
#define _TCP_H_

#include "usi-structs.h"
#include "datalink.h"
#include "ip.h"
#include <cstring>

namespace usipp {

/** \class TCP
 *  All about TCP
 */
class TCP : public IP {
private:
      	struct tcphdr tcph;
      	char tcpOptions[40];
		unsigned int opt_offset;
      	struct pseudohdr pseudo;
		/*
		 * "cached" data from parsed TCP options
		 */
		mutable unsigned int timestamps[2], wscale;
public:
      	
	TCP(void);
	/*! Expects hostname or IP-adress.
         */
	TCP(const char*);

	/*! Destructor
	 */
      	virtual ~TCP();
  
	/*! Assign-operator 
	 */
	TCP &operator=(const TCP&);    

	/*! Copy-constructor 
	 */
	TCP(const TCP&);

       /*! Get sourceport of packet, in host-order.
       	*/
      	u_int16_t get_srcport() const;

       /*! Get destination-port in host-order
       	*/
      	u_int16_t get_dstport() const;

      	/*! Get sequencenumber of packet.
       	 */
      	u_int32_t  get_seq() const;

      	/*! Get acknowlegde-number of packet.
       	 */
      	u_int32_t  get_ack() const;

      	/*! Get TCP-data offset, sometimes called TCP-header-length.
       	*  Should be 20 in most cases.
       	*/
      	u_int8_t get_off() const;

       /*! Get TCP-flags. Can be either of
       	*  TH_SYN
       	*  TH_ACK
       	*  TH_FIN
       	*  TH_RST
       	*  TH_PUSH
	*  TH_URG
       	* or any combination of these (althought common combinations are SYN|ACK or
       	* similar)
       	*/
	u_int8_t get_flags() const;      
      
	/*!*/
	u_int16_t get_win() const;
      
	/*!*/
	u_int16_t get_tcpsum() const;
      	
	/*!
         */
	u_int16_t get_urg() const;

	u_int32_t get_wscale() const;
      
	/*! Set source-port 
         */
      	int set_srcport(u_int16_t);

	/*! Set destination-port
         */
      	int set_dstport(u_int16_t);

	/*!
	 */
      	int set_seq(u_int32_t);

	/*!*/
      	int set_ack(u_int32_t);

	/*!*/
      	int set_off(u_int8_t);

	/*!*/
      	int set_flags(u_int8_t);

	/*!*/
      	int set_win(u_int16_t);

	/*! Set TCP-checksum.
	 * Doing these will prevent sendpack() from doing this for you.
         * It's not recommented that you do so, coz the sum will almost
         * be weak.
         */
      	int set_tcpsum(u_int16_t);

	/*!*/
      	int set_urg(u_int16_t);
     
	/*! Return complete TCP header.
	 *  Usefull for some kinds of ICMP messages
	 */
	tcphdr get_tcphdr() const;
	int set_tcphdr(struct tcphdr);

	/* The following functions are already defined in IP {}.
	 * We need them too for TCP {}, and TCP{} calls IP::function() then.
         */
 

	/*! Capture a packet from the net.
         */
      	virtual int sniffpack(void *buf, size_t buflen);
      	
	/*! Send a packet.
         */
	virtual int sendpack(void *payload, size_t paylen);

	/*! Send a string.
         */
      	virtual int sendpack(char *pay_string);
      
      	/*! Just sets filter to TCP and calls Datalink::initdevice()
         */
	virtual int init_device(char *, int, size_t);

	/*! Set a TCP-option of kind
 	 */
	int set_tcpopt(char kind, unsigned char len, union tcp_options t);

	/*! Clear header from all options
	 */
	int reset_tcpopt();
      
	/*! Fill buffer with 20 bytes, return the length of option-field.
	 */
	int get_tcpopt(char *);
	int set_tcpopt(char *, unsigned int);

	friend bool operator== (const TCP& left, const TCP& right) {
		char left_options[40], right_options[40];
		bool options_matched=false;
		memset(left_options, 0, sizeof(left_options));
		memset(right_options, 0, sizeof(right_options));

		/* remove const'ness for a second */
		left.get_parsed_tcpopt(left_options, sizeof(left_options));
		right.get_parsed_tcpopt(right_options, sizeof(right_options));

		if( (memcmp(left_options, right_options, sizeof(left_options))) == 0) {
			options_matched = true;
		}
		return (left.get_flags() == right.get_flags() &&
				left.get_win() == right.get_win() &&
				left.get_off() == right.get_off()&&
				left.get_urg() == right.get_urg() &&
				options_matched && operator==((IP)left, (IP)right));

	}
	int get_parsed_tcpopt(char *, unsigned int) const;
	unsigned int get_tcpopt_tsv(void) { return timestamps[0]; }
	unsigned int get_tcpopt_tse(void) { return timestamps[1]; }
	std::string to_string(void);
};


} // namespace usipp

#endif // _TCP_H_

