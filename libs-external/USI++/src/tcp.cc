/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights. If not,
 *** you can get it at http://www.cs.uni-potsdam.de/homepages/students/linuxer
 *** the logit-package. You will also find some other nice utillities there.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#include "usi++/usi-structs.h"
#include "usi++/tcp.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

namespace usipp {

TCP::TCP(void): IP("0.0.0.0", IPPROTO_TCP) {
	return;
}
TCP::TCP(const char *host)
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
     : IP(host, IPPROTO_TCP)
{
	srand(time(NULL));
   	memset(&tcph, 0, sizeof(tcph));
	memset(&pseudo, 0, sizeof(pseudo));
	memset(tcpOptions, 0, sizeof(tcpOptions));
	
	tcph.th_off = 5;
	opt_offset = 0;
	
	tcph.th_ack = rand();
	tcph.th_seq = rand();
}

/* Get the sourceport in human-readable form.
 */
u_int16_t TCP::get_srcport() const
{
   	return ntohs(tcph.th_sport);
}

TCP::~TCP()
{
}

TCP::TCP(const TCP &rhs)
	: IP(rhs)
{
	if (this == &rhs)
		return;
	tcph = rhs.tcph;
	memcpy(tcpOptions, rhs.tcpOptions, sizeof(tcpOptions));
	pseudo = rhs.pseudo;
}

TCP &TCP::operator=(const TCP &rhs)
{
	if (this == &rhs)
		return *this;
	IP::operator=(rhs);
	tcph = rhs.tcph;
	memcpy(tcpOptions, rhs.tcpOptions, sizeof(tcpOptions));
	pseudo = rhs.pseudo;
	return *this;
}

/* Get the destinationport in human-readable form.
 */
u_int16_t TCP::get_dstport() const
{
   	return ntohs(tcph.th_dport);
}

/* Get TCP-sequencenumber
 */
u_int32_t TCP::get_seq() const
{
   	return ntohl(tcph.th_seq);
}

/* Get the actual achnkowledge-number from the TCP-header.
 */
u_int32_t TCP::get_ack() const
{
   	return ntohl(tcph.th_ack);
}

/* Get TCP data offset.
 */
u_int8_t TCP::get_off() const
{
   	return tcph.th_off;
}

/* Set TCP-flags 
 */
u_int8_t TCP::get_flags() const
{
   	return tcph.th_flags;
}

u_int16_t TCP::get_win() const
{
   	return ntohs(tcph.th_win);
}

/* Get TCP-header checksum
 */
u_int16_t TCP::get_tcpsum() const
{
   	return tcph.th_sum;
}

u_int16_t TCP::get_urg() const
{
   	return ntohs(tcph.th_urp);
}

u_int32_t TCP::get_wscale() const
{
	return wscale;
}

/* Set TCP sourceport
 */
int TCP::set_srcport(u_int16_t sp)
{
   	tcph.th_sport = htons(sp);
        return 0;
}

/* Set TCP destination port.
 */
int TCP::set_dstport(u_int16_t dp)
{
   	tcph.th_dport = htons(dp);
        return 0;
}

/* Set the sequencenumber-filed in the TCP-header.
 */
int TCP::set_seq(u_int32_t s)
{
   	tcph.th_seq = htonl(s);
        return 0;
}

/*  Set the acknowledgenumber-filed in the TCP-header.
 *  This is only monitored by the target-kernel, if TH_ACK
 *  is set in the TCP-flags.
 */
int TCP::set_ack(u_int32_t a)
{
   	tcph.th_ack = htonl(a);
        return 0;
}

/* Set TCP data offset.
 */
int TCP::set_off(u_int8_t o)
{
   	tcph.th_off = o;
        return 0;
}

/* Set TCP-flags
 */
int TCP::set_flags(u_int8_t f)
{
   	tcph.th_flags = f;
        return 0;
}

int TCP::set_win(u_int16_t w)
{
   	tcph.th_win = htons(w);
        return 0;
}

/*  Set TCP-checksum. Calling this function with s != 0
 *  will prevent sendpack from calculating the checksum!!!
 */
int TCP::set_tcpsum(u_int16_t s)
{
   	tcph.th_sum = s;
        return 0;
}

int TCP::set_urg(u_int16_t u)
{
   	tcph.th_urp = htons(u);
        return 0;
}

/* experimental */
tcphdr TCP::get_tcphdr() const
{
	return tcph;
}

int TCP::set_tcphdr(struct tcphdr _tcph) {
	tcph = _tcph;
	return 0;
}
/*  Send a TCP-packet
 */
int TCP::sendpack(void *buf, size_t paylen)
{
	/* XXX: move to here from set_tcpopts()
	 */
	while (opt_offset % 4 && opt_offset < sizeof(tcpOptions))
		tcpOptions[opt_offset++] = TCPOPT_NOP;

	tcph.th_off = ((opt_offset+sizeof(tcph))>>2);

	unsigned int len = paylen + (tcph.th_off<<2) + sizeof(pseudo);
	char *tmp = new char[len+1+20];	// +1 for padding if necessary
	memset(tmp, 0, len+1);

   	// build a pseudoheader for IP-checksum, as
        // required per RFC 793
	pseudo.saddr = get_src();	// sourceaddress
	pseudo.daddr = get_dst();	// destinationaddress
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_TCP;
	pseudo.len = htons((tcph.th_off<<2) + paylen);
	
        // copy pseudohdr+header+data to buffer
	memcpy(tmp, &pseudo, sizeof(pseudo));
	memcpy(tmp + sizeof(pseudo), &tcph, sizeof(tcph));
	
	// options, might be 0-length
	if ((tcph.th_off<<2) > (int)sizeof(tcph))
    		memcpy(tmp + sizeof(pseudo) + sizeof(tcph), tcpOptions, (tcph.th_off<<2)-sizeof(tcph));

	// data
	memcpy(tmp + sizeof(pseudo) + (tcph.th_off<<2), buf, paylen);
	
        // calc checksum over it
	struct tcphdr *t = (struct tcphdr*)(tmp + sizeof(pseudo));
	
	if (tcph.th_sum == 0) {
		t->th_sum = in_cksum((unsigned short*)tmp, len, 1);
		tcph.th_sum = t->th_sum;
	}
	
	IP::sendpack(tmp + sizeof(pseudo), len - sizeof(pseudo));
	
	delete [] tmp;
	return 0;
}


int TCP::sendpack(char *s)
{
	return sendpack(s, strlen(s));
}


/* Sniff a TCP-packet.
 */
int TCP::sniffpack(void *buf, size_t len)
{  	
        size_t xlen = len + sizeof(tcph) + sizeof(tcpOptions);
	
	char *tmp = new char[xlen];
	int r = 0;
	
        memset(tmp, 0, xlen);
        memset(buf, 0, len);
	memset(&tcph, 0, sizeof(tcph));
	
        r = IP::sniffpack(tmp, xlen);

	if (r == 0 && Layer2::timeout()) {	// timeout
		delete[] tmp;
		return 0;
	}

	// Copy TCP-header without options	
        memcpy(&tcph, tmp, sizeof(tcph));
        
	unsigned int tcplen = tcph.th_off<<2;

	if (tcplen > sizeof(tcph)) {			
		opt_offset = tcplen - sizeof(tcph);
		if (opt_offset < sizeof(tcpOptions)) {
			memcpy(tcpOptions, tmp+sizeof(tcph), opt_offset);
		} else {
			opt_offset = 0;
		}

	}
		
	if (buf)
		memcpy(buf, tmp + tcplen, len);
        
        delete [] tmp;
       	return r - tcplen;
}
        
 
/*  Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
int TCP::init_device(char *dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);
	if (r < 0)
		die("TCP::init_device", STDERR, 1);
	r = Layer2::setfilter("tcp");
	if (r < 0)
		die("TCP::init_device::setfilter", STDERR, 1);
        return r;
}


/* Implementation of TCP-options
 */
int TCP::set_tcpopt(char kind, unsigned char len, union tcp_options to)
{
	//int mss;
	// calculate end of option-list
	/* XXX meder: we move padding and th_off calculation to
	 * sendpack() since we want to be able to construct
	 * any options, in any order.
	 * also added TCPOPT_SACK_PERMITTED
	 */
	//int opt_offset = (tcph.th_off<<2) - sizeof(tcph);

	if (opt_offset < 0 || opt_offset >= (int)sizeof(tcpOptions))
		return -1;	

	tcpOptions[opt_offset++] = kind;
	if (kind > 1)
		tcpOptions[opt_offset++] = len;
	switch (kind) {
	case TCPOPT_SACK_PERMITTED:
	case TCPOPT_EOL:
	case TCPOPT_NOP:
		break;
	case TCPOPT_MAXSEG:
		*((short*)&tcpOptions[opt_offset]) = htons(to.one_word);
		opt_offset += sizeof(short);
		break;
	case TCPOPT_WINDOW:
		tcpOptions[opt_offset++] = to.one_byte;
		break;
	case TCPOPT_TIMESTAMP:
	
		// XXX: htonl() ?
		*((int*)&tcpOptions[opt_offset]) = htonl(to.two_dwords[0]);
		opt_offset += sizeof(int);
		*((int*)&tcpOptions[opt_offset]) = htonl(to.two_dwords[1]);
		opt_offset += sizeof(int);
		break;
	// if unknown, just copy len bytes to optionbuffer
	// this could be used for generic usage
	default:
		int xl = len < sizeof(tcpOptions)-opt_offset?len:sizeof(tcpOptions)-opt_offset;
		memcpy(&tcpOptions[opt_offset], to.unknown, xl);
		opt_offset += xl;
		break;
	} // switch
	//opt_offset--;
	
	// padding for align of 4
	/*
	 * XXX: moved to sendpack()
	 * 
	while (opt_offset % 4)
		tcpOptions[opt_offset++] = TCPOPT_NOP;
	
	opt_offset += sizeof(tcph); tcph.th_off = (opt_offset>>2);
	*/
	return 0;
}

// we assume a buffer of at least 40 bytes
int TCP::get_tcpopt(char *buf)
{
	memcpy(buf, tcpOptions, 40);
	return tcph.th_off<<2;
}

int TCP::set_tcpopt(char *buf, unsigned int len) {
	opt_offset = sizeof(tcpOptions) < len ? sizeof(tcpOptions) : len;
	memset(tcpOptions, 0, sizeof(tcpOptions));
	memcpy(tcpOptions, buf, opt_offset);
	return 0;
}

int TCP::reset_tcpopt()
{
	/* XXX: changed here also
	 */
	tcph.th_off = 5;
	opt_offset = 0;
	memset(tcpOptions, 0, sizeof(tcpOptions));
	return 0;
}

//bool TCP::operator==(const TCP &left, const TCP &right) {
//	return equals_operator(left, right);
//}

/*
bool TCP::equals_operator(const TCP &left, const TCP &right);
	return (left.get_flags() == right.get_flags() &&
			left.get_win() == right.get_win() &&
			left.get_off() == right.get_off() &&
			left.get_urg() == right.get_urg());
}
*/

int TCP::get_parsed_tcpopt(char *opt_order, unsigned int buflen) const {
    unsigned int lenparsed, optlen= 0, k=0;

    // Parse TCP options, like OpenBSD does in /sys/netinet/tcp_input.c
    memset(opt_order, 0, buflen);
    for (lenparsed = 0; lenparsed < opt_offset; lenparsed += optlen) {
        if (tcpOptions[lenparsed] == TCPOPT_NOP) {
            optlen=1;
            if (k < buflen)
                opt_order[k++]='N';
            continue;
        } else if (tcpOptions[lenparsed] == TCPOPT_EOL) {
            if (opt_offset - lenparsed > 1)
                // something fucked up, we have end of list
                // but we are not done yet
                return 0;
        } else  {
            // avoid evil packets that only have
            // option w/o lenght
            if (lenparsed + 1 < opt_offset)
                optlen = tcpOptions[lenparsed+1];
            else
                // something is really fucked
                // we have option but do not have
                // its length
                return 0;
        }
        // alrighty, check for a fucked up packs
        // make sure that len reported in the pack
        // fits into our buffer
        if (optlen > opt_offset - lenparsed) {
            return 0;
        }

        // at this point have optlen bytes in tcp_options;
        // if optlen for some particular option is fucked up
        // we assign it correct value and try to parse further,
        // however neither data is parsed, nor we add option to
        // opt_order
        switch(tcpOptions[lenparsed]) {
            case TCPOPT_WINDOW:
                if (optlen != TCPOLEN_WINDOW) {
                    optlen = TCPOLEN_WINDOW;
                    continue;
                } else {
					wscale = tcpOptions[lenparsed+2];
                    if (k < buflen)
                        opt_order[k++]='W';
                }
                break;
            case TCPOPT_TIMESTAMP:
                if (optlen != TCPOLEN_TIMESTAMP) {
                    optlen = TCPOLEN_TIMESTAMP;
                    continue;
                }
                // we are guaranteed to have 8 bytes of option data at tcp_options+lenparsed
                memcpy(&timestamps[0], tcpOptions+lenparsed+2, 4);
                memcpy(&timestamps[1], tcpOptions+lenparsed+6, 4);
                timestamps[0] = ntohl(timestamps[0]);
                timestamps[1] = ntohl(timestamps[1]);

                if (k < buflen)
                    opt_order[k++]='T';
                break;
            case TCPOPT_MAXSEG:
                if (optlen != TCPOLEN_MAXSEG) {
                    optlen = TCPOLEN_MAXSEG;
                    continue;
                }
                if (k < buflen)
                    opt_order[k++] = 'M';
                break;
            case TCPOPT_SACK_PERMITTED:
                if (optlen != TCPOLEN_SACK_PERMITTED) {
                    optlen = TCPOLEN_SACK_PERMITTED;
                    continue;
                }
                if (k < buflen)
                    opt_order[k++] = 'S';
                break;
        }
    }
    return k;
}

std::string TCP::to_string(void) {
	char buf[4096], tcp_opt[40];
	string retval = IP::to_string();

	memset(buf, 0, sizeof(buf));
	memset(tcp_opt, 0, sizeof(tcp_opt));
	get_parsed_tcpopt(tcp_opt, sizeof(tcp_opt)-1);
	snprintf(buf, sizeof(buf), "+--------------------------------[ TCP ]\n| sport=%d dport=%d seq=0x%x ack=0x%x win=0x%x off=%d urg=%d flags=0x%x options=%s\n+--------------------------------\n", get_srcport(), get_dstport(), get_seq(), get_ack(), get_win(), get_off(), get_urg(), get_flags(), tcp_opt);
	retval.append(buf);
	return retval;	
}

} // namespace usipp

