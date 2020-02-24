#ifndef PARSE_KEYWORD_H
#define PARSE_KEYWORD_H
char *keyarr[] = {
"icmp_unreach_reply_ttl",
"icmp_unreach_echoed_dtsize",
"icmp_unreach_echoed_udp_cksum",
"icmp_unreach_echoed_ip_cksum",
"icmp_unreach_echoed_ip_id",
"icmp_unreach_echoed_total_len",
"icmp_unreach_echoed_3bit_flags",
"icmp_unreach_precedence_bits",
"icmp_unreach_df_bit",
"icmp_unreach_ip_id",
"icmp_unreach_reply",
NULL};

#define ICMP_UNREACH_TTL 0
#define ICMP_UNREACH_ECHOED_SIZE 1
#define ICMP_UNREACH_ECHOED_UPSUM 2
#define ICMP_UNREACH_ECHOED_IPSUM 3
#define ICMP_UNREACH_ECHOED_IPID 4
#define ICMP_UNREACH_ECHOED_TOTLEN 5
#define ICMP_UNREACH_ECHOED_3BIT 6
#define ICMP_UNREACH_PRECEDENCE 7
#define ICMP_UNREACH_DF 8
#define ICMP_UNREACH_IPID 9
#define ICMP_UNREACH_REPLY 10
#endif
