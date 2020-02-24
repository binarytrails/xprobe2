/* $Id: targets_list.h,v 1.3 2003/04/22 20:00:02 fygrave Exp $ */
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

#ifndef TARGETS_LIST_H
#define TARGETS_LIST_H

#include "xprobe.h"
#include "target.h"
#include <list>

using namespace std;

class Targets_List {
    private:
        map<int, Target *> targets;
        map<int, Target *>::iterator targets_iterator;
        Target_Net target_net;            
        int target_counter;
    public:
        int init(char *target_ascii);
        void reset(void);
        Target *getnext(void);
        unsigned long getnext_ip(void);
        Targets_List(void);
};

#endif /* TARGETS_LIST_H */
