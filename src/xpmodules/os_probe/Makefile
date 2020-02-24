# $Id: Makefile.in,v 1.5 2005/07/21 11:42:32 mederchik Exp $
#
# Copyright (C) 2001 Fyodor Yarochkin <fygrave@tigerteam.net>,
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.


CC=gcc
CXX=g++
INSTALL=/bin/install -c
INSTALL_PROGRAM=${INSTALL}
INSTALL_DATA=${INSTALL} -m 644
RANLIB=ranlib
DESTDIR=
prefix=/usr
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
mandir=/usr/share/man
PACKAGE=xprobe2
VERSION=0.3
CPPFLAGS=-D_FORTIFY_SOURCE=2 -Wall -W -Wcast-align -Wcast-qual -Wshadow
CFLAGS=-march=x86-64 -mtune=generic -O2 -pipe -fno-plt -D_FORTIFY_SOURCE=2 -Wall -W -Wcast-align -Wcast-qual -Wshadow -I../ -I../xplib/
LDFLAGS=-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now -ldl -rdynamic
SOLDFLAGS=@SOLDFLAGS@
LIBS=-lpcap 
DYNFLAGS=-fPIC -shared
RANLIB=ranlib
INCLUDES=@INCLUDES@

all: os_probe.a

os_probe.a: icmp_port_unreach_mod icmp_echo_id_mod icmp_timestamp_mod \
icmp_inforeq_mod icmp_addrmask_mod tcp_handshake_mod tcp_rst_mod smb_mod snmp_mod
	ar cr os_probe.a `LC_ALL=C ls icmp_port_unreach/*.o icmp_echo_id/*.o icmp_timestamp/*.o \
    icmp_inforeq/*.o icmp_addrmask/*.o tcp_handshake/*.o tcp_rst/*.o smb/*.o snmp/*.o`
	$(RANLIB) os_probe.a

	
icmp_port_unreach_mod:
	cd icmp_port_unreach; ${MAKE}    

icmp_echo_id_mod:
	cd icmp_echo_id; ${MAKE}    


icmp_timestamp_mod:
	cd icmp_timestamp; ${MAKE}    


icmp_inforeq_mod:
	cd icmp_inforeq; ${MAKE}    

icmp_addrmask_mod:
	cd icmp_addrmask; ${MAKE}    

tcp_handshake_mod:
	cd tcp_handshake; ${MAKE}

tcp_rst_mod:
	cd tcp_rst; ${MAKE}

smb_mod:
	cd smb; ${MAKE}

snmp_mod:
	cd snmp; ${MAKE}

clean:
	rm -f core *.o *.so
	rm -f os_probe.a
	cd icmp_port_unreach; ${MAKE} clean    
	cd icmp_echo_id; ${MAKE} clean    
	cd icmp_timestamp; ${MAKE} clean    
	cd icmp_addrmask; ${MAKE} clean    
	cd icmp_inforeq; ${MAKE} clean    
	cd tcp_handshake; ${MAKE} clean    
	cd tcp_rst; ${MAKE} clean
	cd smb; ${MAKE} clean 
	cd snmp; ${MAKE} clean 

distclean: clean
	rm -f Makefile
	cd icmp_port_unreach; ${MAKE} distclean
	cd icmp_echo_id; ${MAKE} distclean    
	cd icmp_timestamp; ${MAKE} distclean    
	cd icmp_addrmask; ${MAKE} distclean    
	cd icmp_inforeq; ${MAKE} distclean    
	cd tcp_handshake; ${MAKE} distclean
	cd tcp_rst; ${MAKE} distclean
	cd smb; ${MAKE} distclean
	cd snmp; ${MAKE} distclean
