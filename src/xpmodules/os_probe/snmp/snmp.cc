/*
 * **
 * ** Copyright (C) 2005 Meder Kydyraliev <meder@o0o.nu>
 * ** Copyright (C) 2001-2005  Fyodor Yarochkin <fygrave@tigerteam.net>,
 * **                                           Ofir Arkin <ofir@sys-security.com>
 * **
 * ** This program is free software; you can redistribute it and/or modify
 * ** it under the terms of the GNU General Public License as published by
 * ** the Free Software Foundation; either version 2 of the License, or
 * ** (at your option) any later version.
 * **
 * **
 * ** This program is distributed in the hope that it will be useful,
 * ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 * ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * ** GNU General Public License for more details.
 * **
 * ** You should have received a copy of the GNU General Public License
 * ** along with this program; if not, write to the Free Software
 * ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * */

#include "snmp.h"
#include "interface.h"

extern Interface *ui;

int SNMP::parse(unsigned char *buf, unsigned int buflen) {
		unsigned char *ptr=buf;
		unsigned long len, intval=0;
		string str;

		while (buflen > 0) {

			buflen--;
			switch(*ptr) {
				case 0x30: // SEQ
					ptr = get_len(&len, ptr+1, &buflen);
					if (len_is_invalid(buflen, len)) return FAIL;
					break;

				case 0x02:	//integer
					intval = 0;
					ptr = get_len(&len, ptr+1, &buflen);
					if (len_is_invalid(buflen, len)) return FAIL;
					buflen -= len;
					while (len-- > 0) {
						intval = (intval << 8) | *ptr++;
					}
					insert_int(intval);
					//ptr += len;
					break;

				case 0x04:	// string
					ptr = get_len(&len, ptr+1, &buflen);
					if (len_is_invalid(buflen, len)) return FAIL;
					buflen -= len;
					str.erase();
					str.append((const char *)ptr, len);
					insert_string(str);
					ptr += len;
					break;

				case 0x06: 	// OID
					ptr = get_len(&len, ptr+1, &buflen);
					if (len_is_invalid(buflen, len)) return FAIL;
					buflen -= len;
					ptr += len;
					break;
				case 0xa2:	// GETResponse PDU
					ptr = get_len(&len, ptr+1, &buflen);
					if (len_is_invalid(buflen, len)) return FAIL;
					break;
				default:
					ui->error("SNMP::parse(): Unknown SNMP ASN.1 type %d\n", *ptr);
					return FAIL;
			}
		}
		
		return OK;
}

void SNMP::insert_string(string _val) {
	SNMPval val(_val);
	insert_value(ASN_STRING, val);
}

void SNMP::insert_int(unsigned long _val) {
	SNMPval val(_val);
	insert_value(ASN_INTEGER, val);
}

void SNMP::insert_value(unsigned char type, SNMPval val) {
	map<unsigned char, vector<SNMPval> >::iterator iter = SNMPvalues.find(type);
	vector<SNMPval> vec;
	if (iter == SNMPvalues.end()) {
		vec.push_back(val);
		SNMPvalues.insert(pair<unsigned char, vector<SNMPval> >(type, vec));
	} else {
		iter->second.push_back(val);
	}
}

void SNMP::get_strings(vector<string> &retval) {
	map<unsigned char, vector<SNMPval> >::iterator iter = SNMPvalues.find(ASN_STRING);
	if (iter == SNMPvalues.end()) return;
	for (unsigned int i=0; i < iter->second.size(); i++) {
		retval.push_back(iter->second[i].str);
	}
}

void SNMP::get_integers(vector<unsigned long> &retval) {
	map<unsigned char, vector<SNMPval> >::iterator iter = SNMPvalues.find(ASN_INTEGER);
	if (iter == SNMPvalues.end()) return;
	for (unsigned int i=0; i < iter->second.size(); i++) {
		retval.push_back(iter->second[i].integer);
	}
}

unsigned char *SNMP::get_len(unsigned long *len, unsigned char *pack, unsigned int *buflen) {
    	unsigned char length= *pack;
		if (*buflen < 2) {
			exit(1);
			return NULL;
		}
	    if (length & 0x80) {
	        length &= ~0x80;
	        if (length == 0 || length > sizeof(long)) {
	            return NULL;
	        }
	        pack++;
			(*buflen)--;
	        *len=0;
	        while (*buflen > 0 && length--) {
	            *len <<= 8;
	            *len |= *pack++;
				(*buflen)--;
	        }
	        if ((long) *len < 0) {
	            return NULL;
	        }
	        return pack;
	    } else {
			(*buflen)--;
	        *len = (unsigned long) length;
	        return pack+1;
	    }
}
	
bool SNMP::len_is_invalid(unsigned int buflen, unsigned long vallen) {
		if (vallen > buflen) {
			ui->error("SNMP::len_is_invalid(): Val length %lu is greater than buf %d\n", vallen, buflen);
			return true;
		}
		return false;
}
