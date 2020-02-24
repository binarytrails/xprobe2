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


#include "smbutil.h"

unsigned char *SMBUtil::L1_Encode(unsigned char *dst, const unsigned char *name, const unsigned char pad, const unsigned char sfx ) {

	int i = 0;
	int j = 0;
	int k = 0;
	
	while( ('\0' != name[i]) && (i < 15) ) {
		k = toupper( name[i++] );
		dst[j++] = 'A' + ((k & 0xF0) >> 4);
		dst[j++] = 'A' +  (k & 0x0F);
	}

	i = 'A' + ((pad & 0xF0) >> 4);
	k = 'A' +  (pad & 0x0F);
	while( j < 30 ) {
		dst[j++] = i;
		dst[j++] = k;
	}
	dst[30] = 'A' + ((sfx & 0xF0) >> 4);
	dst[31] = 'A' +  (sfx & 0x0F);
	dst[32] = '\0';
	return( dst );

}

int SMBUtil::L2_Encode(unsigned char *dst, const unsigned char *name, const unsigned char pad, const unsigned char sfx, const unsigned char *scope ) {

	int lenpos;
	int i;
	int j;
	
	if( NULL == L1_Encode( &dst[1], name, pad, sfx ) )
		return( -1 );
	dst[0] = 0x20;
	lenpos = 33;
	
	if( '\0' != *scope ) {
		do {
			for( i = 0, j = (lenpos + 1);('.' != scope[i]) && ('\0' != scope[i]); i++, j++)
				dst[j] = toupper( scope[i] );
	
			dst[lenpos] = (unsigned char)i;
			lenpos     += i + 1;
			scope      += i;
		} while( '.' == *(scope++) );
		dst[lenpos] = '\0';
    }
	return( lenpos + 1 );
}


unsigned short SMBUtil::smb_GetShort( unsigned char *src, int offset ) {
	/* ---------------------------------------------------- **
	* Read a short integer converting to host byte order
	* from a byte array in SMB byte order.
	* ---------------------------------------------------- **
	*/
	unsigned short tmp;
	
	/* Low order byte is first in the buffer. */
	tmp  = (unsigned short)(src[offset]);
	
	/* High order byte is next in the buffer. */
	tmp |= ( (unsigned short)(src[offset+1]) << 8 );
	
	return( tmp );
}

void SMBUtil::smb_SetShort( unsigned char *dst, int offset, unsigned short val ) {
	/* ---------------------------------------------------- **
	* Write a short integer in host byte order to the
	* buffer in SMB byte order.
	* ---------------------------------------------------- **
	*/
	/* Low order byte first. */
	dst[offset]   = (unsigned char)(val & 0xFF);
	
	/* High order byte next. */
	dst[offset+1] = (unsigned char)((val >> 8) & 0xFF);
}

unsigned long SMBUtil::smb_GetLong( unsigned char *src, int offset ) {
	/* ---------------------------------------------------- **
	* Read a long integer converting to host byte order
	* from a byte array in SMB byte order.
	* ---------------------------------------------------- **
	*/
	unsigned long tmp;
	
	tmp  = (unsigned long)(src[offset]);
	tmp |= ( (unsigned long)(src[offset+1]) << 8 );
	tmp |= ( (unsigned long)(src[offset+2]) << 16 );
	tmp |= ( (unsigned long)(src[offset+3]) << 24 );
	return( tmp );
}  

void SMBUtil::smb_SetLong( unsigned char *dst, int offset, unsigned long val ) {
	/* ---------------------------------------------------- **
	* Write a long integer in host byte order to the
	* buffer in SMB byte order.
	* ---------------------------------------------------- **
	*/
	
	dst[offset]   = (unsigned char)(val & 0xFF);
	dst[offset+1] = (unsigned char)((val >> 8) & 0xFF);
	dst[offset+2] = (unsigned char)((val >> 16) & 0xFF);
	dst[offset+3] = (unsigned char)((val >> 24) & 0xFF);
}

