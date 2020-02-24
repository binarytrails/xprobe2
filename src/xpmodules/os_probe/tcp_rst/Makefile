# $Id: Makefile.in,v 1.1 2005/02/08 19:39:05 mederchik Exp $
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
CFLAGS=-march=x86-64 -mtune=generic -O2 -pipe -fno-plt -D_FORTIFY_SOURCE=2 -Wall -W -Wcast-align -Wcast-qual -Wshadow -I../ -I../../ -I ../../../ -I../../../xplib -I ../../../../libs-external/USI++
LDFLAGS=-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now -ldl -rdynamic -L../../xplib
SOLDFLAGS=@SOLDFLAGS@
LIBS=-lpcap  -lxplib
DYNFLAGS=-fPIC -shared
XPLIB=../../xplib/libxplib.a
INCLUDES= 
RANLIB=ranlib


all: tcp_rst.o

tcp_rst.o: tcp_rst.cc
	${CXX} ${CFLAGS} -c tcp_rst.cc

    
.c.o: $(INCLUDES)
	$(CC) -c $(CFLAGS) $<

    
.cc.o: $(INCLUDES)
	$(CXX) -c $(CFLAGS) $<

clean:
	rm -f core *.o *.so
distclean: clean
	rm -f Makefile
