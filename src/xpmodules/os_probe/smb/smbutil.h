/*
 * **
 * ** Copyright (C) 2001-2005 Meder Kydyraliev <meder@o0o.nu>
 * **
 * ** Copyright (C) 2001-2005  Fyodor Yarochkin <fygrave@tigerteam.net>,
 * **                                  Ofir Arkin       <ofir@sys-security.com>
 * **
 * ** This program is free software; you can redistribute it and/or modify
 * ** it under the terms of the GNU General Public License as published by
 * ** the Free Software Foundation; either version 2 of the License, or
 * ** (at your option) any later version.
 * **
 * **
 * ** This program is distributed in the hope that it will be useful,
 * ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 * ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * ** GNU General Public License for more details.
 * **
 * ** You should have received a copy of the GNU General Public License
 * ** along with this program; if not, write to the Free Software
 * ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * */
/*
 *
 * ATTENTION:
 * Code below is modified version of the examples presented in the
 * 'Implementing CIFS' online book which is available at:
 * http://ubiqx.org/cifs/
 *
 * Copyright (C) 1999-2003 by Christopher R. Hertel
 *
 * Date of changes: 20/06/2005
 */


#ifndef XPROBE_SMBUTIL_H
#define XPROBE_SMBUTIL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>

using namespace std;

class SMBUtil {
	private:
	public:	
		static unsigned char *L1_Encode(unsigned char *dst, const unsigned char *name, const unsigned char pad, const unsigned char sfx );
		static int L2_Encode(unsigned char *dst, const unsigned char *name, const unsigned char pad, const unsigned char sfx, const unsigned char *scope );
		static unsigned short smb_GetShort( unsigned char *src, int offset );
		static void smb_SetShort( unsigned char *dst, int offset, unsigned short val );
		static unsigned long smb_GetLong( unsigned char *src, int offset );
		static void smb_SetLong( unsigned char *dst, int offset, unsigned long val);	
		
};

#endif /* XPROBE_SMBUTIL_H */
