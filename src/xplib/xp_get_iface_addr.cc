/* $Id: xp_get_iface_addr.cc,v 1.2 2003/04/22 20:00:06 fygrave Exp $ */
/*
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

/* nifty idea stolen from 'skin'.. better than my own roting sockets
 * magic! ;-) */
 
 
#include "xp_get_iface_addr.h"

struct in_addr xp_get_iface_addr(char *iname) {
    struct ifreq ifr;
    int sd;
    struct in_addr retval;
    struct sockaddr_in *sinaddr;

    if (!iname) {
        retval.s_addr = 0xffffffff; /* error */
        return retval;
    }

    if((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset((void *)&ifr, 0, sizeof(struct ifreq));

    strncpy(ifr.ifr_name, iname, sizeof(ifr.ifr_name));

    if (ioctl(sd, SIOCGIFADDR,(char *)&ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sd);
        exit(1); /* interface doesn't exist or your kernel is flacky */
    }
    close(sd);
    sinaddr = (struct sockaddr_in *) &ifr.ifr_addr;
    memcpy((void *)&retval, (void *)&(sinaddr->sin_addr.s_addr),
             sizeof(retval));
    return retval;
 
}


