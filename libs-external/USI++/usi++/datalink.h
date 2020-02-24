/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef _DATALINK_H_ 
#define _DATALINK_H_

#include "usi-structs.h"
#include "RX.h"
#include <stdio.h>

//#include "config.h"

namespace usipp {

/*! \class Pcap
 *  Describing a Datalink.
 */ 
class Pcap : public RX {
private:
	struct timeval d_tv;
   	time_t start;

	// Heavily used by libpcap
	int d_datalink;
	size_t d_framelen, d_snaplen;

	// pcap-descriptor
        pcap_t *d_pd;

	// netaddress and netmask
        bpf_u_int32 d_localnet, d_netmask;
       
	// The actual filter-program 
	struct bpf_program d_filter;

	// The pcap-header for every packet fetched
	struct pcap_pkthdr d_phdr;

	// filled by init_device()
	char d_dev[10];
	int d_has_promisc;

	// true when timed out
	bool d_timeout;	

protected:
	struct ether_header d_ether;
	char d_filter_string[1000];

public:

	/*! This constructor should be used to
	 *  initialize raw-datalink-objects, means not IP/TCP/ICMP etc.
	 *  We need this b/c unlike in derived classes, datalink::init_device()
	 *  cannot set a filter!
	 */
	Pcap(char *);
	
	Pcap();
	
	/*! Copy-constructor
	 */
	Pcap(const Pcap &);
	
        virtual ~Pcap();

	Pcap &operator=(const Pcap &);
	

        /*! Fill buffer with src-hardware-adress of actuall packet,
	 *  use 'datalink' to determine what HW the device is.
	 *  Now only ethernet s supportet, but it's extensinable.
	 */
        char *get_hwsrc(char *, size_t);

        /*! Fill buffer with dst-hardware-adress of actuall packet,
 	 *  use 'datalink' to determine what HW the device is.
	 *  Now only ethernet s supportet, but it's extensinable.
	 */
        char *get_hwdst(char *, size_t);

        /*! Get protocol-type of ethernet-frame
	 *  Maybe moves to ethernet-class in future?
	 */
        u_int16_t get_etype();

        /*! Return the actual datalink of the object.
	 */
        int get_datalink();

        /*! Return the actual framlen of the object.
	 *  (framelen depends on datalink)
	 */
        int get_framelen();
    
        /*! Initialize a device ("eth0" for example) for packet-
	 *  capturing. It MUST be called before sniffpack() is launched.
	 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
	 *  Fetch at most 'snaplen' bytes per call.
	 */
        virtual int init_device(char *dev, int promisc, size_t snaplen);

        /*! set a new filter for capturing
	 */
        virtual int setfilter(char *filter);

        /*! sniff a packet
         */
	virtual int sniffpack(void *, size_t);

	/*! Return HW-frame */
	void *get_frame(void *, size_t);

	/*! Get pcap_t struct to obtain fileno etc for select. */
	pcap_t *pcap() { return d_pd; }

	/*! Set a timeout. Implements RX::timeout() = 0. */
	int timeout(struct timeval);

	/*! Returns true when recv() timed out */
	bool timeout();

	/* make pcap handle nonblocking */
	bool set_nonblock();
	int get_nonblock();
	
}; // class Datalink {}


} // namespace usipp

#endif // _DATALINK_H_
