
# $Id: Makefile.in,v 1.2 2003/04/22 19:59:58 fygrave Exp $
#
# Copyright (C) 2001 Fyodor Yarochkin <fygrave@tigerteam.net>,
#                    Ofir Arkin       <ofir@sys-security.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
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
srcdir=.
PACKAGE=xprobe2
VERSION=0.3
CPPFLAGS=-D_FORTIFY_SOURCE=2 -Wall -W -Wcast-align -Wcast-qual -Wshadow
CXXFLAGS=$(CPPFLAGS) -march=x86-64 -mtune=generic -O2 -pipe -fno-plt
CFLAGS=$(CPPFLAGS) -march=x86-64 -mtune=generic -O2 -pipe -fno-plt -I ./ -I ../libs-external/USI++/src/
LDFLAGS=-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now -ldl -rdynamic 
LIBS=-lpcap 
INCLUDES=cmd_opts.h config_set.h interface.h interface_con.h log.h os_matrix.h scan_engine.h target.h targets_list.h xprobe.h xprobe_module.h xprobe_module_hdlr.h xprobe_module_param.h xprobe_timeval.h  defines.h config.h
SOURCES=cmd_opts.cc config_set.cc interface.cc interface_con.cc log.cc os_matrix.cc scan_engine.cc target.cc targets_list.cc xprobe.cc xprobe_module_hdlr.cc xprobe_module_param.cc 
OBJS=${SOURCES:.cc=.o}
XPLIBS= xplib/libxplib.a ../libs-external/USI++/src/libusi++.a
MODOBJS=xpmodules/alive_probe/alive_probe.a \
	xpmodules/os_probe/os_probe.a $(XPLIBS)

all: lib xprobe2

xprobe2: $(OBJS) modules
	$(CXX) $(CFLAGS) $(OBJS) $(MODOBJS) -o $@ $(LDFLAGS) $(LIBS)
	strip $@    

modules:
	cd xpmodules; ${MAKE}    
lib:
	cd xplib; ${MAKE}    

.c.o: $(INCLUDES)
	$(CC) -c $(CFLAGS) $<

.cc.o: $(INCLUDES)
	$(CXX) -c $(CFLAGS) $<

clean:
	rm -f xprobe2 xprobe2.core core *.o
	cd xpmodules; ${MAKE} clean
	cd xplib; ${MAKE} clean

distclean: clean
	rm -f config.h defines.h Makefile
	cd xpmodules; ${MAKE} distclean
	cd xplib; ${MAKE} distclean
