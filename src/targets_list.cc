/* $Id: targets_list.cc,v 1.2 2003/04/22 20:00:02 fygrave Exp $ */
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


#include "xprobe.h"
#include "targets_list.h"
#include "interface.h"

extern Interface *ui;

int Targets_List::init(char *target_ascii) {

    ui->msg("[+] Target is %s\n", target_ascii);
    if (target_net.init(target_ascii) == FAIL) return FAIL;

    return OK;
}

void Targets_List::reset(void) {
    
    target_net.reset();
}

Target *Targets_List::getnext() {
    unsigned long na = getnext_ip();
    if (na == 0xffffffff || na == 0) return NULL;

    Target *tg = new Target(na);
    targets.insert(pair <int, Target *>(target_counter++, tg));
    return tg;
}

unsigned long Targets_List::getnext_ip(void) {
    return target_net.getnext();
}

Targets_List::Targets_List(void) {
    target_counter = 0;
}
