/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
 
#include "usi++/usi-structs.h"
#include "usi++/datalink.h"
#include "usi++/ip.h"

#include "config.h"
#include <cstdlib>
#include <iostream>
#include <string.h>
#include <errno.h>
#include <new>
#include <vector>

namespace usipp {

/*  Create a IP-packet, with 'dst' for destination-adress.
 *  Set the protocol-filed in the IP-header to 'proto'.
 *  This is used by the derived classes (TCP etc.) to set
 *  the correct protocol (IPPROTO_TCP etc.)
 */
IP::IP(const char *dst, u_int8_t proto)
   	: Layer2()
{	
	memset(&iph, 0, sizeof(iph));
	memset(ipOptions, 0, sizeof(ipOptions));
		srand(time(NULL));
        iph.ttl = 64;
        iph.version = 4;
        iph.ihl = 5;
//        iph.id = 0;
		/* We set the IP ID
		 * since for fingerprinting we
		 * need to be able to know what
		 * was the IP ID of the packet we
		 * sent, cuz if we don't we'll get 0
		 */
		iph.id = rand();
		iph.check = 0;
        iph.protocol = proto;
		iph.tot_len = 0;

	memset(host, 0, sizeof(host));

	// ask for local hostname 
	/*
        if (gethostname(host, sizeof(host)-1) < 0) {
		perror("gethostname");
		fprintf(stderr, "using INADDR_ANY for src-IP.");		
		set_src(INADDR_ANY);
	}
	  * by meder: we dont' want to set the src host here,
	  * as it causes problem when there's no entry in /etc/hosts
	  * for the localhost.
	  * user just has to make sure he/she calls set_src();	
		else
		set_src(host);
		*/
	
	set_dst(dst);  
   	
        // what in sendpack must be set is:
        // tot_len, check, frag_off
}

/*  Same as above, but use networkbyte-ordered int32 for destination-adress.
 *  This is usefull in case you do sth. like ip.set_src(ip2.get_src())
 */
IP::IP(u_int32_t dst, u_int8_t proto)
   	: Layer2()
{
   	memset(&iph, 0, sizeof(iph));
	memset(ipOptions, 0, sizeof(ipOptions));
	
		srand(time(NULL));
        iph.ttl = 64;
        iph.version = 4;
        iph.ihl = 5;
        //iph.id = 0;
		iph.id = rand();
        iph.protocol = proto;

	memset(host, 0, sizeof(host));
	
	// ask for local hostname 
	 /*
        if (gethostname(host, sizeof(host)-1) < 0) {
		perror("gethostname");
		fprintf(stderr, "using INADDR_ANY for src-IP.");		
		set_src(INADDR_ANY);
		}
	  * by meder: we dont' want to set the src host here,
	  * as it causes problem when there's no entry in /etc/hosts
	  * for the localhost.
	  * user just has to make sure he/she calls set_src();	
		else
		set_src(host);
		*/
	
        set_dst(dst);
}


/*  Same as above
 */
IP::IP(iphdr &iphh)
   	: Layer2()
{
   	memcpy(&iph, &iphh, sizeof(iphh));
	memset(ipOptions, 0, sizeof(ipOptions));
	
}


/* Assign-operator
 */
IP& IP::operator=(const IP &rhs)
{
	if (this == &rhs)
		return *this;

	Layer2::operator=(rhs);
	
	// and just copy header and such
	memcpy(host, rhs.host, sizeof(host));
	memcpy(&iph, &rhs.iph, sizeof(iph));
	memcpy(ipOptions, rhs.ipOptions, sizeof(ipOptions));
	memcpy(&saddr, &rhs.saddr, sizeof(saddr));
	return *this;
}

/* copy-construktor
 */
IP::IP(const IP &rhs)
    : Layer2(rhs)
{
	if (this == &rhs)
		return;

	memcpy(host, rhs.host, sizeof(host));		
	memcpy(&iph, &rhs.iph, sizeof(iph));
	memcpy(ipOptions, rhs.ipOptions, sizeof(ipOptions));
	memcpy(&saddr, &rhs.saddr, sizeof(saddr));
}

IP::~IP()
{
}

/*  Get IP header-length
 */
u_int8_t IP::get_hlen() const
{
   	return iph.ihl;
}

/* Set IP-header-length.
 */
int IP::set_hlen(u_int8_t l)
{
        iph.ihl = l;
	return 0;
}

/* Get Ip-version field.
 */
u_int8_t IP::get_vers() const
{
   	return iph.version;
}

/* Set version field in IP-header.
 */
int IP::set_vers(u_int8_t v)
{
   	iph.version = v;
        return 0;
}
 
u_int8_t IP::get_tos() const
{
   	return iph.tos;
}

int IP::set_tos(u_int8_t tos)
{
   	iph.tos = tos;
        return 0;
}

/* Get total length of IP-packet.
 */
u_int16_t IP::get_totlen() const
{
   	return ntohs(iph.tot_len);
}

/* Set total length of IP-packet.
 *  If you set the total length by yourself, you will prevent the
 *  sendpack() routine to do it. This is normally _not_ needed.
 */
int IP::set_totlen(u_int16_t t)
{
	/* XXX meder: we move handling of all
	 * os the BROKEN_BSD cases into sendpack()
	 * because now for example if you do set_totlen()
	 * or set_fragoff() and then right after that 
	 * you do get_fragoff() it will return different value
	 * on BROKEN_BSD, this is because on BROKEN_BSD those
	 * values are in host byte order and get_*() return
	 * ntoh'ed values
	 * Basically we want to enforce network byte order in 
	 * those fields and then just change byte order when
	 * calling sendpack() to approriate if run on BROKEN_BSD
	 */
/*
#ifdef BROKEN_BSD
	iph.tot_len = t;
#else
	iph.tot_len = htons(t);
#endif
*/
	iph.tot_len = htons(t);
   	return 0;
}

/* Get the IP id field.
 */
u_int16_t IP::get_id() const
{
   	return ntohs(iph.id);
}

/* Set the IP id field.
 */
int IP::set_id(u_int16_t id)
{
   	iph.id = htons(id);
        return 0;
}

/* Get the IP-fragmentation offset */
u_int16_t IP::get_fragoff() const
{
   	return ntohs(iph.frag_off);
}

/* Set the IP-fragmentation offset */
int IP::set_fragoff(u_int16_t f)
{
	/* XXX meder: see comment for set_totlen */
/*
#ifdef BROKEN_BSD
	iph.frag_off = f;
#else
   	iph.frag_off = htons(f);
#endif
*/
	iph.frag_off = htons(f);
	return  0;
}

/* Get time to live.
 */
u_int8_t IP::get_ttl() const
{
   	return iph.ttl;
}

/* Set 'time to live' 
 */
int IP::set_ttl(u_int8_t ttl)
{
   	iph.ttl = ttl;
        return 0;
}

/* Obtain the actuall protocol.
 */
u_int8_t IP::get_proto() const
{
   	return iph.protocol;
}

/* Change the protocol-filed of IP header to 'p' in case
 * you need to.
 */
int IP::set_proto(u_int8_t p)
{
        iph.protocol = p;
        return 0;
}

/* Get IP-header checksum 
 */
u_int16_t IP::get_sum() const
{
	   	return iph.check;
}

/* Calculate IP-header checksum
 * calculated over ip header
 * only calcs, doesn't set anything
 */
u_int16_t IP::calc_ipsum()
{
	u_int16_t csum;
/*
#ifdef BROKEN_BSD
	iph.tot_len = htons(iph.tot_len);
	iph.frag_off = htons(iph.frag_off);
#endif
*/

	csum = in_cksum ( (unsigned short *) &iph, sizeof(iph), 0 );

/*
#ifdef BROKEN_BSD
	iph.tot_len = ntohs(iph.tot_len);
	iph.frag_off = ntohs(iph.frag_off);
#endif
*/

	return csum;
}

/* Set IP-header checksum 
 *  Should not be used as long as you don't want to
 *  insert bad checksums into the header.
 */
int IP::set_sum(u_int16_t s)
{
   	iph.check = s;
        return 0;
}

/* Get the destination-adress in networkbyteorder.
 */
u_int32_t IP::get_dst() const
{
	return iph.daddr;
}

/* Get the destination-adress in human-readable form.
 *  If resolv == 1, then resolve to a hostname if possible,
 *  otherwise give back IP (resolv == 0).
 */
char *IP::get_dst(int resolv, char *s, size_t len)
{
   	 struct in_addr in;
         struct hostent *he;         
         
         memset(s, 0, len);
         in.s_addr = iph.daddr;
         if (!resolv || (he = gethostbyaddr((char*)&in, sizeof(in), AF_INET)) == NULL)
            	strncpy(s, inet_ntoa(in), len);
         else
            	strncpy(s, he->h_name, len);
         return s;
}

/* Return the source-adress of actuall IP-packet
 * in network-byte order.
 */
u_int32_t IP::get_src() const
{
   	return iph.saddr;
}

/* Get the sourceadress in human-readable form.
 *  If 'resolv' == 1, return hostname, if 0 only IP-adress.
 */
char *IP::get_src(int resolv, char *s, size_t len)
{
   	 struct in_addr in;
         struct hostent *he;         
         
         memset(s, 0, len);
         in.s_addr = iph.saddr;
         if (!resolv || (he = gethostbyaddr((char*)&in, sizeof(in), AF_INET)) == NULL)
            	strncpy(s, inet_ntoa(in), len);
         else
            	strncpy(s, he->h_name, len);
         return s;
}

/* Set the source-adress, use networkbyteorderes adress.
 */
int IP::set_src(u_int32_t s)
{
   	iph.saddr = s;
        return 0;
}

/* Set the sourceadress, use hostname or IP.
 */
int IP::set_src(const char* host)
{
   	struct hostent *he;
        
        if ((he = gethostbyname(host)) == NULL) {
				herror("IP::set_src::gethostbyname");
                exit(errno);
        }
        memcpy(&iph.saddr, he->h_addr, he->h_length);
        return 0;
}

/* Set destination adress.
 */
int IP::set_dst(u_int32_t d)
{
	iph.daddr = d;
	return 0;
}

/*! Set destinationadress, similar to set_src()
 */
int IP::set_dst(const char* host)
{
   	struct hostent *he;
        
        if ((he = gethostbyname(host)) == NULL) {
		herror("IP::set_dst::gethostbyname");
                exit(errno);
        }
        memcpy(&iph.daddr, he->h_addr, he->h_length);
        return 0;
}

iphdr IP::get_iphdr() const
{
	return iph;
}

int IP::set_iphdr(struct iphdr _iph) {
	iph = _iph;
	return 0;
}

/* Send a packet, containing 'paylen' bytes of data.
 */
int IP::sendpack(void *payload, size_t paylen)
{	

	// get mem for packet	
	char *s = new char[paylen+sizeof(iph)+1];
	memset(s, 0, paylen+sizeof(iph)+1);
	
	
	// We give luser the chance to set wrong length's
	// if he really want's to ...
	if (get_totlen() == 0)
		set_totlen(paylen + sizeof(iph));		// how long ?

#ifdef BROKEN_BSD
	iph.tot_len = ntohs(iph.tot_len);
	iph.frag_off= ntohs(iph.frag_off);
#endif
		
	/* If checksum is 0, kernel will set it. */		
	if (iph.check != 0)
		iph.check = in_cksum((unsigned short*)&iph, sizeof(iph), 0);
	
	memcpy(s, &iph, sizeof(iph));
	memcpy(s + sizeof(iph), payload, paylen);

	sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = 0;
	saddr.sin_addr.s_addr = iph.daddr;

	Layer2::sendpack(s, paylen + sizeof(iph), (struct sockaddr*)&saddr);
	
#ifdef BROKEN_BSD
	iph.tot_len = htons(iph.tot_len);
	iph.frag_off = htons(iph.frag_off);
#endif

	delete [] s;
	return 0;
}


int IP::sendpack(char *payload)
{
	return sendpack((void*)payload, strlen(payload));
}


/*! Handle packets, that are NOT actually for the
 *  local adress!
 */
int IP::sniffpack(void *buf, size_t len)
{
	int r = 0;
	int xlen = len + sizeof(iph) + sizeof(ipOptions);
	struct usipp::iphdr *i = NULL;
        
	char *tmp = new char[xlen];
	memset(tmp, 0, xlen);
	memset(buf, 0, len);
        
	/* until we assembled fragments or we received and unfragemented packet
	 */
	while (i == NULL) {
		memset(tmp, 0, xlen);
           	if ((r = Layer2::sniffpack(tmp, xlen)) == 0 &&
		    Layer2::timeout()) {
			delete[] tmp;
			return 0;	// timeout
		}
#ifdef USI_REASSEMBLE
		i = (struct usipp::iphdr*)reassemble(tmp, len, &r);
#else
		i = (struct usipp::iphdr*)tmp;
#endif
        }
	
#ifdef USI_DEBUG
	cerr<<"IP::r="<<r<<endl;
	cerr<<"IP::ihlen="<<(i->ihl<<2)<<endl;
#endif

        unsigned int iplen = i->ihl<<2;
	// Copy header without options	
	memcpy(&iph, (char*)i, sizeof(iph));
	
	// Copy ip-options if any
	if (iplen > sizeof(iph))
		memcpy(ipOptions, tmp+sizeof(iph), iplen-sizeof(iph));	

	if (buf)
		memcpy(buf, (char*)i + iplen, len);
	
	delete [] tmp;
	return get_totlen() - iplen;
}

/*! Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
int IP::init_device(char *dev, int promisc, size_t snaplen)
{
        int r = Layer2::init_device(dev, promisc, snaplen);
	
	if (r < 0)
		die("IP::init_device", STDERR, 1);
	r = Layer2::setfilter("ip");
	
	if (r < 0)
		die("IP::init_device::setfilter", STDERR, 1);

        return r;
}

/*! Assembles IP-fragments.
 */
char *IP::reassemble(char *packet, int len, int *resultLen)
{
   	static vector<fragments*> pending;
	fragments *f = NULL;
	int ihl = 0, xlen = 0, offset = 0;
	unsigned int i = 0;

        struct usipp::iphdr *ip = (struct usipp::iphdr*)(packet);
	ihl = ip->ihl<<2;
	
	/* can't be > 60 */
	if (ihl > 60)
		ihl = 60;

        /* if fragment-offset and DF-bit not set */
        if (ntohs(ip->frag_off) != 0 && 
	   (ntohs(ip->frag_off) & IP_DF) != IP_DF) {
		
		/* for all pending fragments */
		for (i = 0; i < pending.size(); i++) {
			if (pending[i] == NULL)
				continue;
			
			/* if we already have something that belongs to
			 * _this_ fragment
                         */
			if (ntohs(ip->id) == pending[i]->id) {
				f = pending[i];
				break;
			}
		}
		
		/* otherwise its the first one */
		if (f == NULL) {
			f = new fragments;
			f->id = ntohs(ip->id);
         		f->data = new char[len + ihl];
			f->len = 0;			// # of bytes that are captured yet
			f->origLen = 0xffff;		// # of bytes IP-packet once contained
			f->userLen = 0;			// # of bytes saved
			memset(f->data, 0, len + ihl);
			memcpy(f->data, packet, ihl);
			pending.push_back(f);
		}
		
		offset = 8*(ntohs(ip->frag_off) & IP_OFFMASK);
		
		if (offset + ntohs(ip->tot_len) - ihl <= len)
			xlen = ntohs(ip->tot_len) - ihl;
		else 
			xlen = len - offset;
	
	
		/* Copy IP-data to the right offset.
		 * It may happen, that offset points out of our data-area.
		 * In this case is xlen < 0 and we ignore it.
		 */
		if (xlen > 0) {
			memcpy(f->data + offset + ihl,
		               packet + ihl,
		               xlen
		              );
			/* This is for the caller; how much was
			 * fetched AND COPIED for her.
			 */
			f->userLen += xlen;
		}
		
		/* We even count the not copied data! */
		f->len += ntohs(ip->tot_len) - ihl;
		
		
		/* OK, we received the last fragment with this id, so calculate
		 * how the original size of this packet was
		 */
		if ((ntohs(ip->frag_off) != 0 && 
		    (ntohs(ip->frag_off) & IP_MF) == 0)) {
			f->origLen = ntohs(ip->tot_len) + offset - ihl;
		}
		    
		/* In case we reached the original len -> all fragments
		 * are received and assembled.
		 * NOTE that f->len counts the # of bytes _received_, not saved!
		 * The # of saved bytes is in f->userLen.
		 */
		if (f->len == f->origLen) {
			/* should not be necessary, but */
			if (i >= 0 && i < pending.size())
				pending[i] = NULL;
			struct usipp::iphdr *ih = (struct usipp::iphdr*)(f->data);
			ih->frag_off = 0;

			ih->tot_len = htons(ihl + f->len);
			*resultLen = ihl + f->userLen;
			
			/* packet must at least be 'len+ihl' bytes big,
			 * where 'ihl' is max. 60.
			 */
			memset(packet, 0, len+ihl);
			memcpy(packet, f->data, len+ihl);
			
			delete [] f->data;
			delete f;
			return packet;
		} else  {
			*resultLen = 0;
			return NULL;
		}
		
        /* else, packet is not fragmented  */
        } else {
		*resultLen = ntohs(ip->tot_len);
		/* return IP-packet, hw-frame skipped */
		return packet;
        }
}
	
std::string IP::to_string(void) {
	char buf[4096], src_str[256], dst_str[256];
	string retval;
	
	memset(buf, 0, sizeof(buf));
	// hrm using inet_ntoa() two times in a row in one snprintf statement
	// cases it to display the same IP for both, while they are actually different
	snprintf(buf, sizeof(buf), "+--------------------------------[ IP ]\n| src=%s dst=%s hlen=%d totlen=%d tos=0x%x fragoff=0x%x ttl=%d id=%d\n+--------------------------------\n", get_src(0, src_str, sizeof(src_str)), get_dst(0, dst_str, sizeof(dst_str)), get_hlen(), get_totlen(), get_tos(), get_fragoff(), get_ttl(), get_id());	
	retval = buf;
	return retval;
}

} // namespace usipp

