
# $Id: Makefile.in,v 1.4 2003/04/22 19:59:54 fygrave Exp $
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

FILES=AUTHORS Makefile.in README acconfig.h cfg-scripts configure \
configure.in docs
SOURCES=cmd_opts.cc config_set.cc interface.cc interface_con.cc log.cc os_matrix.cc scan_engine.cc target.cc targets_list.cc xprobe.cc xprobe_module_hdlr.cc xprobe_module_param.cc 
HEADERS=cmd_opts.h config_set.h interface.h interface_con.h log.h os_matrix.h scan_engine.h target.h targets_list.h xprobe.h xprobe_module.h xprobe_module_hdlr.h xprobe_module_param.h xprobe_timeval.h 
SRCFILES= Makefile.in config.h.in defines.h.in cmd_opts.cc config_set.cc interface.cc interface_con.cc log.cc os_matrix.cc scan_engine.cc target.cc targets_list.cc xprobe.cc xprobe_module_hdlr.cc xprobe_module_param.cc  cmd_opts.h config_set.h interface.h interface_con.h log.h os_matrix.h scan_engine.h target.h targets_list.h xprobe.h xprobe_module.h xprobe_module_hdlr.h xprobe_module_param.h xprobe_timeval.h  \
xptests
INSTALL=/bin/install -c
INSTALL_PROGRAM=${INSTALL}
INSTALL_DATA=${INSTALL} -m 644
prefix=/usr
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
mandir=/usr/share/man
sysconfdir=/etc
CFGDIR=/etc/xprobe2
PACKAGE=xprobe2
VERSION=0.3
TARDIR=$(PACKAGE)-$(VERSION)
TARFILE=$(TARDIR).tar
TGZFILE=$(TARFILE).gz
SIGFILE=$(TGZFILE).asc
SIG=md5sum -b


all: 
	cd libs-external/USI++/src; ${MAKE}
	cd src; ${MAKE}


clean:
	cd libs-external/USI++/src; ${MAKE} clean
	cd src; ${MAKE} clean
distclean: clean
	rm -f config.cache config.log config.status Makefile
	cd libs-external/USI++/src; ${MAKE} distclean
	cd src; ${MAKE} distclean
install: src/xprobe2
	$(INSTALL_PROGRAM) -d $(DESTDIR)/$(bindir)
	$(INSTALL_PROGRAM) -d $(DESTDIR)/$(mandir)/man1
	$(INSTALL_PROGRAM) -d $(DESTDIR)/$(sysconfdir)/xprobe2
	$(INSTALL_PROGRAM) -m 0755 src/xprobe2 $(DESTDIR)/$(bindir)
	$(INSTALL_PROGRAM) -m 0444 etc/xprobe2.conf $(DESTDIR)/$(sysconfdir)/xprobe2
	$(INSTALL_DATA) docs/xprobe2.1 $(DESTDIR)/$(mandir)/man1

configure: configure.in
	autoheader
	autoconf    

tarball: configure
	mkdir ../$(TARDIR)
	mkdir ../$(TARDIR)/src
	cp -R $(FILES) ../$(TARDIR)/
	cd src;cp -R $(SRCFILES) ../../$(TARDIR)/src
	cd ../; tar cfz $(TGZFILE) $(TARDIR)/
	cd ../;$(SIG) $(TGZFILE) > $(SIGFILE)
	rm -rf ../$(TARDIR)

arc: configure distclean
	rm -rf ../$(TARDIR)
	cp -R ../$(PACKAGE) ../$(TARDIR)
	cd ..; tar cvfz $(TGZFILE) $(TARDIR)
	cd ../;$(SIG) $(TGZFILE) > $(SIGFILE)
	rm -rf ../$(TARDIR)
