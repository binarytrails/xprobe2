/*
** Copyright (C) 2001, 2002 Meder Kydyraliev <meder@areopag.net>
**
** Copyright (C) 2001 Fyodor Yarochkin <fygrave@tigerteam.net>,
**                    Ofir Arkin       <ofir@sys-security.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "xplib.h"

/* copies len bytes of standart unix ICMP echo request payload */

int xp_get_ping_payload(char *dest, int len) {

	struct timeval tv;
	struct Timestamp timestmp;
	int tocopy, iii;

	if (len > 0 && dest != NULL) {
		if ((gettimeofday(&tv, NULL)) < 0) {
			perror ("xp_get_ping_payload: gettimeofday()");
			return FAIL;
		}
		timestmp.sec = htonl(tv.tv_sec);
		timestmp.usec = htonl(tv.tv_usec);
		tocopy = (unsigned int)len > sizeof (timestmp) ? sizeof(timestmp): len;
		memcpy (dest, &timestmp, tocopy);
		dest += tocopy;
		tocopy = len - tocopy;
		iii = sizeof (timestmp);
		while (tocopy > 0) {
			*dest++ = iii;
			tocopy--;
			iii++;
		}
	}
    return OK;
}
