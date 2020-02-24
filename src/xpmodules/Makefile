# $Id: Makefile.in,v 1.1 2002/08/08 11:41:42 fygrave Exp $
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

INCLUDES=@INCLUDES@

all: modules

modules: alive os
    
alive:
	cd alive_probe; ${MAKE}    

os:
	cd os_probe; ${MAKE}    

.c.o: $(INCLUDES)
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f core
	cd alive_probe; ${MAKE} clean    
	cd os_probe; ${MAKE} clean    
distclean: clean
	rm -f Makefile
	cd alive_probe; ${MAKE} distclean
	cd os_probe; ${MAKE} distclean
