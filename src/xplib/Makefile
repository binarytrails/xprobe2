# $Id: Makefile.in,v 1.7 2005/01/12 07:04:57 mederchik Exp $
#
# Copyright (C) 2001 Fyodor Yarochkin <fygrave@tigerteam.net>,
#                    Ofir Arkin       <ofir@sys-security.com>
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
DESTDIR=
prefix=/usr
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
mandir=/usr/share/man
PACKAGE=xprobe2
VERSION=0.3
CPPFLAGS=-D_FORTIFY_SOURCE=2 -Wall -W -Wcast-align -Wcast-qual -Wshadow
CXXFLAGS=$(CPPFLAGS) -march=x86-64 -mtune=generic -O2 -pipe -fno-plt -I ../
CFLAGS=$(CPPFLAGS) -march=x86-64 -mtune=generic -O2 -pipe -fno-plt -I ../
LDFLAGS=-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now -ldl -rdynamic
LIBS=-lpcap 
INSTALL=/bin/install -c
RANLIB=ranlib
OBJS=xp_get_interface.o xp_get_iface_addr.o xp_get_random_data.o \
	xp_get_ping_payload.o xp_get_src_addr.o xp_sha1.o xp_lib.o


all: libxplib.a

libxplib.a: $(OBJS)
	ar cr libxplib.a `LC_ALL=C ls *.o`
	$(RANLIB) libxplib.a

 .c.o: $(INCLUDES)
	$(CC) -c $(CFLAGS) $<

.cc.o: $(INCLUDES)
	$(CXX) -c $(CFLAGS) $<

clean:
	rm -f libxplib.a core *.o

distclean: clean
	rm -f Makefile
