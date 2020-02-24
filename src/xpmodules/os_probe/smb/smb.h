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


#ifndef XPROBE_SMB_H
#define XPROBE_SMB_H

#include "xprobe.h"
#include "xprobe_module.h"
#include "xprobe_module_param.h"
#include "xplib.h"
#include "smbutil.h"

using namespace std;

class SMB {
	public:
		const static int SESS_MSG = 0x00;
		const static int SESS_REQ = 0x81;
		const static int SESS_POS_RESP = 0x82;
		const static int SESS_NEG_RESP = 0x83;
		const static int SESS_RETARGET = 0x84;
		const static int SESS_KEEPALIVE = 0x85;
		const static int NBT_NOT_LISTENING = 0x80;
		const static int NBT_NAME_NOT_PRESENT = 0x82;
		const static int NBT_SERVER_SERVICE = 0x20;
		const static int NBT_WORKSTATION_SERVICE = 0x00;
		
		const static int SMB_HDR_SIZE = 32;
		const static int SMB_OFFSET_CMD = 4;
		const static int SMB_OFFSET_NTSTATUS = 5;
		const static int SMB_OFFSET_ECLASS = 5;
		const static int SMB_OFFSET_ECODE = 7;
		const static int SMB_OFFSET_FLAGS = 9;
		const static int SMB_OFFSET_FLAGS2 = 10;
		const static int SMB_OFFSET_EXTRA = 12;
		const static int SMB_OFFSET_TID = 24;
		const static int SMB_OFFSET_PID = 26;
		const static int SMB_OFFSET_UID = 28;
		const static int SMB_OFFSET_MID = 30;
		const static int SMB_OFFSET_WC = 32;
		const static int SMB_OFFSET_COM = 33;
		const static int SMB_OFFSET_XRESERVED = 34;
		const static int SMB_OFFSET_OFFSET = 35;
		const static int SMB_OFFSET_MAXBUF = 37;
		const static int SMB_OFFSET_MPXCNT = 39;
		const static int SMB_OFFSET_VCNUM = 41;
		const static int SMB_OFFSET_SESSKEY = 43;
		const static int SMB_OFFSET_CIPASSLEN = 47;
		const static int SMB_OFFSET_CSPASSLEN = 49;
		const static int SMB_OFFSET_RESERVED = 51;
		const static int SMB_OFFSET_CAPABILITIES = 55;
		/*
		 * FLAGS
		 */
		const static int SMB_FLAGS_CANONICAL_PATHNAMES = 0x10;
		const static int SMB_FLAGS_CASELESS_PATHNAMES = 0x08;
		/*
		 * FLAGS2
		 */
		const static int SMB_FLAGS2_KNOWS_LONG_NAMES = 0x0001;
		
		/*
		 * SMB Commands
		 */
		const static int SMB_COM_NEGOTIATE = 0x72;
		const static int SMB_COM_SESS_SETUP_ANDX = 0x73;
		
	private:	
		int MakeSessReq(unsigned char *bufr, unsigned char *Called, unsigned char *Calling);
		int RequestNBTSession(int sock, unsigned char *Called, unsigned char *Calling);

		int smb_hdrInit( unsigned char *bufr, int bsize );
		int nbt_SessionHeader( unsigned char *bufr, unsigned long size );		
		static void smb_hdrSetCmd( unsigned char *bufr, char cmd ) { bufr[SMB_OFFSET_CMD] = cmd; }
		static void smb_hdrSetFlags( unsigned char *bufr, char flags ) { bufr[SMB_OFFSET_FLAGS] = flags; }
		static void smb_hdrSetFlags2( unsigned char *bufr, char flags2 ) { 
			SMBUtil::smb_SetShort( bufr, SMB_OFFSET_FLAGS2, flags2 );
		}
		int NBT_Session(struct in_addr dst_addr, unsigned short dst_port);
		int smb_NegProtRequest( unsigned char  *bufr, int bsize, int namec, const unsigned char **namev );
		int smb_SessSetupRequest(unsigned char *buf, unsigned int bsize);
		int NBT_Node_Status_Query(struct in_addr);
		string nativeos, lanman, domain, calledname;
		unsigned char mac[6];
		
	public:
		SMB() { calledname="*SMBSERVER"; bzero(mac, sizeof(mac)); } 
		int session_setup_and_x(struct in_addr target, unsigned short port = 139);
		string get_nativeos(void) { return nativeos; }
		string get_lanman(void) { return lanman; }
		string get_domain(void) { return domain; }
		string get_calledname(void) { return calledname; }
		string get_mac(void);
};
#endif /* XPROBE_SMB_H */
