/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
 
 
#ifndef _USI_STRUCTS_H_
#define _USI_STRUCTS_H_

#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
extern "C" {
#include <pcap.h>
}
#include "usi++"

#ifndef MAXHOSTLEN 
#define MAXHOSTLEN 1000
#endif


/* putting an own version of
 * iphdr, udphdr, tcphdr, icmphdr and pseudohdr
 * in usipp namespace to avoid collision with
 * kernel ones. Mostly the IP etc. structs from system to system differ
 * and are often broken.
 */
 
namespace usipp {

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/*  This is a name for the 48 bit ethernet address available on many
 *  systems.  
 */
struct ether_addr
{
   	u_int8_t ether_addr_octet[ETH_ALEN];
};

struct ether_header
{
   	u_int8_t  ether_dhost[ETH_ALEN];	// destination eth addr	
        u_int8_t  ether_shost[ETH_ALEN];	// source ether addr	
        u_int16_t ether_type;		        // packet type ID field	
};


/*
 *	These are the defined Ethernet Protocol ID's.
 */
#define ETH_P_LOOP	0x0060		// Ethernet Loopback packet	
#define ETH_P_ECHO	0x0200		// Ethernet Echo packet		
#ifndef ETH_P_PUP
#define ETH_P_PUP	0x0200		// Xerox PUP packet		
#endif
#define ETH_P_IP	0x0800		// Internet Protocol packet	
#define ETH_P_X25	0x0805		// CCITT X.25		
#define ETH_P_ARP	0x0806		// Address Resolution packet	
#define	ETH_P_BPQ	0x08FF		// G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_DEC       0x6000          // DEC Assigned proto           
#define ETH_P_DNA_DL    0x6001          // DEC DNA Dump/Load            
#define ETH_P_DNA_RC    0x6002          // DEC DNA Remote Console       
#define ETH_P_DNA_RT    0x6003          // DEC DNA Routing              
#define ETH_P_LAT       0x6004          // DEC LAT                      
#define ETH_P_DIAG      0x6005          // DEC Diagnostics              
#define ETH_P_CUST      0x6006          // DEC Customer use             
#define ETH_P_SCA       0x6007          // DEC Systems Comms Arch       
#define ETH_P_RARP      0x8035		// Reverse Addr Res packet	
#define ETH_P_ATALK	0x809B		// Appletalk DDP
#define ETH_P_AARP	0x80F3		// Appletalk AARP
#define ETH_P_IPX	0x8137		// IPX over DIX	
#define ETH_P_IPV6	0x86DD		// IPv6 over bluebook

/*
 *	Non DIX types. Won't clash for 1500 types.
 */
 
#define ETH_P_802_3	0x0001		// Dummy type for 802.3 frames 
#define ETH_P_AX25	0x0002		// Dummy protocol id for AX.25 
#define ETH_P_ALL	0x0003		// Every packet (be careful!!!) 
#define ETH_P_802_2	0x0004		// 802.2 frames 		
#define ETH_P_SNAP	0x0005		// Internal only	
#define ETH_P_DDCMP     0x0006          // DEC DDCMP: Internal only     
#define ETH_P_WAN_PPP   0x0007          // Dummy type for WAN PPP frames
#define ETH_P_PPP_MP    0x0008          // Dummy type for PPP MP frames 
#define ETH_P_LOCALTALK 0x0009		// Localtalk pseudo type 	
#define ETH_P_PPPTALK	0x0010		// Dummy type for Atalk over PPP
#define ETH_P_TR_802_2	0x0011		// 802.2 frames 		
#define ETH_P_MOBITEX	0x0015		// Mobitex (kaz@cafe.net)
#define ETH_P_CONTROL	0x0016		// Card specific control frames 
#define ETH_P_IRDA	0x0017		// Linux/IR			


/*  See RFC 826 for protocol description.  ARP packets are variable
 *  in size; the arphdr structure defines the fixed-length portion.
 *  Protocol type values are the same as those for 10 Mb/s Ethernet.
 *  It is followed by the variable-sized fields ar_sha, arp_spa,
 *  arp_tha and arp_tpa in that order, according to the lengths
 *  specified.  Field names used correspond to RFC 826.  
 */
struct arphdr {
   	u_int16_t ar_hrd;	// Format of hardware address.  
        u_int16_t ar_pro;	// Format of protocol address.  
        unsigned char ar_hln;	// Length of hardware address.  
        unsigned char ar_pln;	// Length of protocol address.  
        u_int16_t ar_op;	// ARP opcode (command).  
#if 0
    /* Ethernet looks like this : This bit is variable sized
       however...  
     */
        unsigned char __ar_sha[ETH_ALEN];	// Sender hardware address.  
        unsigned char __ar_sip[4];		// Sender IP address.  
        unsigned char __ar_tha[ETH_ALEN];	// Target hardware address.  
        unsigned char __ar_tip[4];		// Target IP address.  
#endif
};


/* ARP protocol opcodes. */
#define	ARPOP_REQUEST	1		// ARP request. 
#define	ARPOP_REPLY	2		// ARP reply.  
#define	ARPOP_RREQUEST	3		// RARP request.  
#define	ARPOP_RREPLY	4		// RARP reply.  

/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM	0		// From KA9Q: NET/ROM pseudo. 
#define ARPHRD_ETHER 	1		// Ethernet 10/100Mbps.  
#define	ARPHRD_EETHER	2		// Experimental Ethernet.  
#define	ARPHRD_AX25	3		// AX.25 Level 2.  
#define	ARPHRD_PRONET	4		// PROnet token ring.  
#define	ARPHRD_CHAOS	5		// Chaosnet.  
#define	ARPHRD_IEEE802	6		// IEEE 802.2 Ethernet/TR/TB.  
#define	ARPHRD_ARCNET	7		// ARCnet.  
#define	ARPHRD_APPLETLK	8		// APPLEtalk.  
#define ARPHRD_DLCI	15		// Frame Relay DLCI.  
#define ARPHRD_METRICOM	23		// Metricom STRIP (new IANA id).  

/* Dummy types for non ARP hardware */
#define ARPHRD_SLIP	256
#define ARPHRD_CSLIP	257
#define ARPHRD_SLIP6	258
#define ARPHRD_CSLIP6	259
#define ARPHRD_RSRVD	260		/* Notional KISS type.  */
#define ARPHRD_ADAPT	264
#define ARPHRD_ROSE	270
#define ARPHRD_X25	271		/* CCITT X.25.  */
#define ARPHRD_PPP	512
#ifndef ARPHRD_HDLC
#define ARPHRD_HDLC	513		/* (Cisco) HDLC.  */
#endif
#define ARPHRD_LAPB	516		/* LAPB.  */

#define ARPHRD_TUNNEL	768		/* IPIP tunnel.  */
#define ARPHRD_TUNNEL6	769		/* IPIP6 tunnel.  */
#define ARPHRD_FRAD	770             /* Frame Relay Access Device.  */
#define ARPHRD_SKIP	771		/* SKIP vif.  */
#define ARPHRD_LOOPBACK	772		/* Loopback device.  */
#define ARPHRD_LOCALTLK 773		/* Localtalk device.  */
#define ARPHRD_FDDI	774		/* Fiber Distributed Data Interface. */
#define ARPHRD_BIF	775             /* AP1000 BIF.  */
#define ARPHRD_SIT	776		/* sit0 device - IPv6-in-IPv4.  */
#define ARPHRD_IPDDP	777		/* IP-in-DDP tunnel.  */
#define ARPHRD_IPGRE	778		/* GRE over IP.  */
#define ARPHRD_PIMREG	779		/* PIMSM register interface.  */
#define ARPHRD_HIPPI	780		/* High Performance Parallel I'face. */
#define ARPHRD_ASH	781		/* (Nexus Electronics) Ash.  */
#define ARPHRD_ECONET	782		/* Acorn Econet.  */
#define ARPHRD_IRDA	783		/* Linux/IR.  */
#define ARPHRD_FCPP	784		/* Point to point fibrechanel.  */
#define ARPHRD_FCAL	785		/* Fibrechanel arbitrated loop.  */
#define ARPHRD_FCPL	786		/* Fibrechanel public loop.  */
#define ARPHRD_FCPFABRIC 787		/* Fibrechanel fabric.  */

/* See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct	ether_arp {
	struct	arphdr ea_hdr;		// fixed-size header 
	u_int8_t arp_sha[ETH_ALEN];	// sender hardware address 
	u_int8_t arp_spa[4];		// sender protocol address 
	u_int8_t arp_tha[ETH_ALEN];	// target hardware address 
	u_int8_t arp_tpa[4];		// target protocol address 
};
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op


/**/
struct icmphdr {
   	u_int8_t type;
        u_int8_t code;
        u_int16_t sum;

	union {
		struct {
                   	u_int16_t id;
                        u_int16_t sequence;
                } echo;
	        u_int32_t gateway;
		struct {
                   	u_int16_t unused;
                        u_int16_t mtu;
                } frag;
        } un;
};

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

#define PING_PAYLOAD_SIZE 56
#define TIMESTAMP_PAYLOAD_SIZE 12
#define ADDRMASK_PAYLOAD_SIZE 4


struct udphdr {
   	u_int16_t	source;
        u_int16_t	dest;
        u_int16_t	len;
        u_int16_t	check;
};

/*
 *  The pseudo-header is used to calculate checksums over UDP
 *  and TCP packets.
 */
struct pseudohdr {
   	u_int32_t saddr;
        u_int32_t daddr;
        u_int8_t zero;
        u_int8_t proto;
        u_int16_t len;
};


struct tcphdr
{
    	u_int16_t th_sport;		// source port 
        u_int16_t th_dport;		// destination port 
        u_int32_t th_seq;		// sequence number 
        u_int32_t th_ack;		// acknowledgement number
//#if __BYTE_ORDER == __LITTLE_ENDIAN
#ifndef WORDS_BIGENDIAN
    	u_int8_t th_x2:4;		// (unused) 
        u_int8_t th_off:4;		// data offset 
//#elif __BYTE_ORDER == __BIG_ENDIAN
#else
    	u_int8_t th_off:4;		// data offset 
        u_int8_t th_x2:4;		// (unused) 
#endif
    	u_int8_t th_flags;
#ifndef TH_FIN
#define	TH_FIN	0x01
#endif
#ifndef TH_SYN
#define	TH_SYN	0x02
#endif
#ifndef TH_RST
#define	TH_RST	0x04
#endif
#ifndef TH_PUSH
#define	TH_PUSH	0x08
#endif
#ifndef TH_ACK
#define	TH_ACK	0x10
#endif
#ifndef TH_URG
#define	TH_URG	0x20
#endif
    	u_int16_t th_win;		// window 
        u_int16_t th_sum;		// checksum 
        u_int16_t th_urp;		// urgent pointer 
};


struct iphdr
{
//#if __BYTE_ORDER == __LITTLE_ENDIAN
#ifndef WORDS_BIGENDIAN
    	u_int32_t ihl:4;
        u_int32_t version:4;
//#elif __BYTE_ORDER == __BIG_ENDIAN
#else
    	u_int32_t version:4;
        u_int32_t ihl:4;
//#else
//# error	"Please fix <bits/endian.h>"
#endif
    	u_int8_t tos;
        u_int16_t tot_len;
        u_int16_t id;
        u_int16_t frag_off;
#ifndef IP_RF
#define IP_RF 0x8000
#endif
#ifndef IP_DF 
#define IP_DF 0x4000
#endif
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif
        u_int8_t ttl;
        u_int8_t protocol;
        u_int16_t check;
        u_int32_t saddr;
        u_int32_t daddr;
    /* The options start here. */
};


/* describes a fragment for re-assembling routines
 */
struct fragments {
	int id;		// the IP id-filed
	int len;	// how much data received yet?
	int origLen;	// and how much has it to be?
	int userLen;	// and how much did we saved?
	char *data;     // the packet itself
};

// from netinet/tcp.h
#define	TCPOPT_EOL		0
#define	TCPOPT_NOP		1
#define	TCPOPT_MAXSEG		2
#define TCPOLEN_MAXSEG		4
#define TCPOPT_WINDOW		3
#define TCPOLEN_WINDOW		3
#define TCPOPT_SACK_PERMITTED	4		/* Experimental */
#define TCPOLEN_SACK_PERMITTED	2
#define TCPOPT_SACK		5		/* Experimental */
#define TCPOPT_TIMESTAMP	8
#define TCPOLEN_TIMESTAMP	10
#define TCPOLEN_TSTAMP_APPA	(TCPOLEN_TIMESTAMP+2) /* appendix A */


/*
 */
union tcp_options {
			   // nothing for kind 0 and 1
	char one_byte;	   // kind: 3
	u_int16_t one_word;    // kind: 2
	u_int32_t two_dwords[2]; // kind: 8 (timestamp)
	char unknown[20];  // default
};


} // namespace usipp

#endif	// _USI_STRUCTS_H_ 
