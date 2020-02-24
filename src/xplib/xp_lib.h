/*
 * **
 * ** Copyright (C) 2001-2005 Fyodor Yarochkin <fygrave@tigerteam.net>,
 * **                    Ofir Arkin       <ofir@sys-security.com>
 * **                    Meder Kydyraliev <meder@o0o.nu>
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

#ifndef _XP_LIB_H
#define _XP_LIB_H

#include "xplib.h"

using namespace std;

class xp_lib {

	public:
		static int tokenize(const char *, char, vector<string> *);
		static int tokenize(const char *, char, vector<int> *);
		static string int_to_string(int);
		static int OpenTCPSession( struct in_addr dst_IP, unsigned short dst_port );
		static int RecvTimeout( int sock, unsigned char *bufr, int bsize, int timeout );
		static bool equal(const char *, const char *);
		static bool equal(string, string);
		static int OpenUDPSocket(struct sockaddr_in *to, struct sockaddr_in *bind_sin=NULL);
};

#endif
