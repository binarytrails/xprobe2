#include <xprobe.h>
#include "util.h"
#include "icmp_port_unreach.h"
#include "parse_keyword.h"
#include "interface.h"

extern Interface *ui;

int icmp_port_unreach::parse_keyword(int os_id, const char *keyword, const char *value){
	
	Fingerprint newfingerprint;
	int iii=0;

    xprobe_debug(XPROBE_DEBUG_SIGNATURES, "[%s] Parsing for %i : %s  = %s\n",
                                                       get_name(), os_id,  keyword, value);
	for (iii=0; keyarr[iii] != NULL; iii++) {
		if ((strncmp (keyarr[iii], keyword, strlen (keyarr[iii]))) == 0) {
			if ( (iter = os2finger.find (os_id)) == os2finger.end() ) {
				os2finger.insert (pair<int, Fingerprint>(os_id, newfingerprint));
				/* so that we could start adding things righ away */
				iter = os2finger.find (os_id);
			}
			switch(iii) {
				case ICMP_UNREACH_TTL:
            		if ( value[0] == '<' || value[0] == '>' )
                		value += 1;
					iter->second.put_p_unreach_ttl(value);
					break;
				case ICMP_UNREACH_ECHOED_SIZE:
					iter->second.put_echoed_size(value);
					break;
				case ICMP_UNREACH_ECHOED_UPSUM:
					iter->second.put_echoed_udpsum(value);
					break;
				case ICMP_UNREACH_ECHOED_IPSUM:
					iter->second.put_echoed_ipsum(value);
					break;
				case ICMP_UNREACH_ECHOED_IPID:
					iter->second.put_echoed_ipid(value);
					break;
				case ICMP_UNREACH_ECHOED_TOTLEN:
					iter->second.put_echoed_totlen(value);
					break;
				case ICMP_UNREACH_ECHOED_3BIT:
					iter->second.put_echoed_3bit(value);
					break;
				case ICMP_UNREACH_PRECEDENCE:
					iter->second.put_icmp_prec_bits(value);
					break;
				case ICMP_UNREACH_DF: 
					iter->second.put_icmp_df(value);
					break;
				case ICMP_UNREACH_IPID:
					iter->second.put_icmp_ipid(value);
					break;
				case ICMP_UNREACH_REPLY:
					iter->second.put_reply(value);
					break;
			}
			return OK;
		}
	}
return OK;
}
