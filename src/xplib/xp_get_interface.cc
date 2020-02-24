/* $Id: xp_get_interface.cc,v 1.4 2003/04/22 20:00:27 fygrave Exp $ */
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
 
 
#include "xp_get_interface.h"

char *xp_get_interface(struct in_addr addr) {
    struct sockaddr_in ifraddr, remote;
    socklen_t iflen;
    int sd;
    struct ifconf ifc;
    struct ifreq  *ifr, ifrtemp;
    char buf[sizeof(struct ifreq)*MAXIFNUM];
    static char ifrname[IF_NAMESIZE + 1];
    char *retval = NULL;

    remote.sin_family = AF_INET;
    remote.sin_port = htons(1234);
    remote.sin_addr.s_addr = addr.s_addr;

#ifdef __linux__
/* TMP fix. linux is a bitch */
    if (addr.s_addr == inet_addr("127.0.0.1")) {
        snprintf(ifrname, IF_NAMESIZE, "lo");
        return ifrname;
    }
#endif
    bzero((void *)&ifraddr, sizeof(ifraddr));

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return NULL;
    }

    if (connect(sd, (struct sockaddr *) &remote, sizeof(remote)) < 0) {
        perror("connect");
        close(sd);
        return NULL;
    }

    iflen = sizeof(ifraddr);
    if (getsockname(sd, (struct sockaddr *) & ifraddr, &iflen) < 0) {
        perror("getsockname");
        close(sd);
        return NULL;
    }

    bzero((void *)buf, sizeof(buf));
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t) buf;
    if (ioctl(sd, SIOCGIFCONF, (char *)&ifc) < 0) {
        perror("ioctl(SIOCGIFCONF)");
        close(sd);
        return NULL;
    }
    for(ifr = (struct ifreq *)buf;
        (char *)ifr &&
        *(char *)ifr &&
        (char *)ifr < (buf + ifc.ifc_len);
#ifndef HAVE_SOCKADDR_SA_LEN        
        ifr++
#endif        
        ) {

        bcopy((void *)ifr, (void *)&ifrtemp, sizeof(struct ifreq));
#ifdef HAVE_SOCKADDR_SA_LEN        
        ifr = (struct ifreq *)((char *)ifr + ifr->ifr_addr.sa_len + \
                                sizeof(ifr->ifr_name));
#endif        
        if (ioctl(sd, SIOCGIFFLAGS, (char *)&ifrtemp) < 0) {
			if (errno == ENXIO)
				continue;
            perror("ioctl(SIOCGIFFLAGS)");
            close(sd);
            return NULL;
            /* XXX: report me if fails here */
        }

       if (!(ifrtemp.ifr_flags & IFF_UP)) continue;
       
       if (((struct sockaddr_in *)&ifrtemp.ifr_addr)->sin_addr.s_addr 
                                               != ifraddr.sin_addr.s_addr)
           continue;
       
       bcopy((void *)(&ifrtemp)->ifr_name, (void *)ifrname, IF_NAMESIZE); 
       retval = ifrname;
       break;
    }
    close(sd);
    if (retval == NULL)
        fprintf(stderr, "No interface leading to %s was found\n",
        inet_ntoa(addr));
    return retval;
}
