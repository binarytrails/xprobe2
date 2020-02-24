/* $Id: xplib.h,v 1.7 2005/01/12 07:04:58 mederchik Exp $ */
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

#ifndef XPLIB_H
#define XPLIB_H
#ifndef _XPROBE_MODULE
#include "xprobe.h"
#else
#include <stdarg.h>
#include "../defines.h"
#endif

#include "xp_get_interface.h"
#include "xp_get_iface_addr.h"
#include "xp_get_random_data.h"
#include "xp_get_ping_payload.h"
#include "xp_get_src_addr.h"
#include "xp_sha1.h"
#include "xp_lib.h"

#endif /* XPLIB_H */
