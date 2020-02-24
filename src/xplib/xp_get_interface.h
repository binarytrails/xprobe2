/* $Id: xp_get_interface.h,v 1.2 2003/04/22 20:00:30 fygrave Exp $ */
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
 
 
#ifndef XP_GET_INTERFACE_H
#define XP_GET_INETRFACE_H
#include "xplib.h"

char *xp_get_interface(struct in_addr);

#endif /* XP_GET_INTERFACE_H */
