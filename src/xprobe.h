/* $Id: xprobe.h,v 1.7 2005/02/13 18:41:31 mederchik Exp $ */
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

#ifndef XPROBE_H
#define XPROBE_H

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
 
#include <time.h>
#define IP_VERSION 4
 
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
 
#include <sys/param.h>

#ifndef bzero
#ifdef NOBZERO
#define bzero(x,y) memset((void *)x,(int)0,(size_t) y)
#define bcopy(x,y,z) memcpy((void *)y, (const void *)x, (size_t) z)
#endif /* NOBZERO */
#endif /* bzero*/

#include <stdarg.h>
#include <errno.h>

#ifdef __linux__
#ifdef HAVE_GLIB_H
#include <glib.h>
#endif
#endif
 
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <time.h>
#include <sys/time.h>
#ifdef __linux__ 
#define __FAVOR_BSD
#endif
/* fix the OsX bug */
#ifndef _BSD_SOCKLEN_T_
#define _BSD_SOCKLEN_T_ unsigned int
#endif
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifndef __linux__
//#include <netinet/ip_var.h>
#else /* __linux__ */
#include <sys/time.h>
#endif /* __linux__ */
#include <netinet/ip_icmp.h>
// #include <netinet/tcp.h>
#ifndef  IFNAMSIZ
#include <net/if.h>
#endif
#if !defined(__OpenBSD__) && !defined(__NetBSD__) && !defined(SOLARIS) &&  !defined(__sgi)
#include <net/ethernet.h>
#endif
 
#ifdef SOLARIS
#include <sys/sockio.h>
#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif
#endif
 
#include <netinet/if_ether.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>
// #include <math.h> /* conflicts with <string>
#include <signal.h>
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#ifdef __cplusplus
extern "C" {
#include <pcap.h>
}
#else
#include <pcap.h>
#endif

/* some types correction */
#if defined(__FreeBSD__) || defined(__linux__)
#define TIMEZONE_T struct timezone
#else
#define TIMEZONE_T unsigned long
#endif
#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

/* macroses */
/* linux and OpenBSD want ip offset in network order, others: in host
 * order
 */

#if defined(__linux__) || defined(__OpenBSD__)    
#define IPOFF_FIX(off)      htons((unsigned short)(off))
#else
#define IPOFF_FIX(off)      (off)
#endif

#define IFRLEN(ifrptr)  (ifrptr->ifr_addr.sa_len + sizeof(ifrptr->ifr_name))

#include "defines.h"
#include "xprobe_timeval.h"
// STL includes
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#endif /* XPROBE_H */
