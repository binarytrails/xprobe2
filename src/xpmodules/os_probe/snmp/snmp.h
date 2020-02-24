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

#ifndef XPROBE_SNMP_H
#define XPROBE_SNMP_H

#include "snmp_mod.h"

#define ASN_STRING 		0x04
#define ASN_INTEGER		0x02
#define ASN_SEQ			0x30
#define ASN_OID			0x06
#define ASN_GETPDU		0xa2

class SNMP {

	private:
		class SNMPval {
			public:
				SNMPval(string _s) { str = _s; }
				SNMPval(unsigned long _i) { integer = _i; } 
				string str;
				unsigned long integer;
		};
		map<unsigned char, vector<SNMPval> > SNMPvalues;
		unsigned char *get_len(unsigned long *, unsigned char *, unsigned int *);
		bool len_is_invalid(unsigned int, unsigned long);
		void insert_string(string);
		void insert_int(unsigned long);
		void insert_value(unsigned char, SNMPval);
		
	
	public:
		int parse(unsigned char *, unsigned int);
		void get_strings(vector<string> &);
		void get_integers(vector<unsigned long> &);
};

#endif /* XPROBE_SNMP_H */
