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
struct in_addr xp_get_src_addr(struct in_addr dst) {
	struct sockaddr_in src, remote;
	int sockfd;
	socklen_t socklen;

	remote.sin_family = AF_INET;
	remote.sin_port = htons(1234);
	remote.sin_addr.s_addr = dst.s_addr;
	src.sin_addr.s_addr = 0xffffffff;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("xp_get_src_addr():socket");
		/* couldn't allocate socket, something is really fucked */
		exit(1);
	}
	if ((connect(sockfd, (struct sockaddr *) &remote, sizeof(remote))) < 0) {
		perror("xp_get_src_addr():connect");
		/* invalid ip address ? */
		exit(1);
	}
	socklen = sizeof(src);
	if ((getsockname(sockfd, (struct sockaddr *) &src, &socklen)) < 0) {
		perror("xp_get_src_addr(): getsockname");
		exit(1);
	}	

	//KPC 1-17-05 - Close socket connection to address handle leak
	if (close(sockfd) < 0) {
		perror("xp_get_src_addr(): close");
		exit(1);
	}

	return src.sin_addr;
}
