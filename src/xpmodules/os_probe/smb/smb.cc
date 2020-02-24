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

#include "interface.h"
#include "smb.h"
#include <sstream>

using namespace std;

extern Interface *ui;

int SMB::MakeSessReq( unsigned char *bufr, unsigned char *Called, unsigned char *Calling ) {
	/* ---------------------------------------------------- **
	* Create an NBT SESSION REQUEST message.
	* ---------------------------------------------------- **
	*/
	
	/* Write the header.
	*/
	bufr[0] = SESS_REQ;
	bufr[1] = 0;
	bufr[2] = 0;
	bufr[3] = 68;         /* 2x34 bytes in length. */
	
	/* Copy the Called and Calling names into the buffer.
	*/
	(void)memcpy( &bufr[4],  Called,  34 );
	(void)memcpy( &bufr[38], Calling, 34 );
	
	/* Return the total message length.
	*/
	return( 72 );
}


int SMB::RequestNBTSession( int sock, unsigned char *Called, unsigned char *Calling ) {
	/* ---------------------------------------------------- **
	* Send an NBT SESSION REQUEST over the TCP connection,
	* then wait for a reply.
	* ---------------------------------------------------- **
	*/
	unsigned char bufr[128];
	int   result;
	
	/* Create the NBT Session Request message.
	*/
	result = MakeSessReq( bufr, Called, Calling );
	
	/* Send the NBT Session Request message.
	*/
	result = send( sock, bufr, result, 0 );
	if( result < 0 ) {
		ui->error( "Error sending Session Request message: %s\n", strerror( errno ) );
		return FAIL;
	}

	/* Now wait for and handle the reply (2 seconds).
	*/
	result = xp_lib::RecvTimeout( sock, bufr, sizeof(bufr), 1);
	if( result < 4 ) {
		ui->error("RequestNBTSession(): got only %d bytes\n", result);
    	return FAIL;
	}

	switch( *bufr ) {
		case SESS_POS_RESP:
			/* We got what we wanted. */
			xprobe_mdebug(XPROBE_DEBUG_MODULES, "-- SMB::RequestNBTSession(): Received POSITIVE session response\n");
			return OK;
		case SESS_NEG_RESP:
			/* 
			 * check if we got called name not present or 
			 * not listening on called name errors
			 */
			if (result < 5) {
				ui->error("RequestNBTSession(): truncated SESS_NEG_RESPONSE (%d bytes)\n", result);
				return FAIL;
			}
			if(bufr[4] == NBT_NOT_LISTENING || bufr[4] == NBT_NAME_NOT_PRESENT)
				return RETRY;
			else
				return FAIL;
		case SESS_RETARGET:
			/* We've been retargeted. */
			return FAIL;
		default:
			/* Not a response we expected. */
			return FAIL;
			break;
	}
	return FAIL;
}

int SMB::NBT_Session( struct in_addr dst_addr, unsigned short dst_port) {
	/* ---------------------------------------------------- **
	 * Program mainline.
	 * Parse the command-line input and open the connection
	 * to the server.
	 * ---------------------------------------------------- **
	 */
	unsigned char Called[34];
	unsigned char Calling[34];
	int sock=-1, retval;
	
	/* 
	 * Open the session.
	 */
	sock = xp_lib::OpenTCPSession( dst_addr, dst_port );
	
	if (sock == FAIL)
		return FAIL;
	
	/* 
	 * Comment out the next call for raw TCP.
	 */
	if (dst_port == 139) {
		(void)SMBUtil::L2_Encode( Called, (const unsigned char *)calledname.c_str(), 0x20, 0x20, (const unsigned char *)"" );

		/* 
		 * Create a (bogus) Calling Name.
		 */
		(void)SMBUtil::L2_Encode( Calling, (const unsigned char *)"SMBCLIENT", 0x20, 0x00, (const unsigned char *)"" );

		retval = RequestNBTSession( sock, Called, Calling );
		if (retval != OK) {
			xprobe_debug(XPROBE_DEBUG_MODULES, "SMB::NBT_Session(): retval: %d\n", retval);
			close(sock);
			return retval;
		}
	}
	/* ** Do real work here. ** */
	return(sock);
}

int SMB::smb_hdrInit( unsigned char *bufr, int bsize ) {
	/* ---------------------------------------------------- **
	 * Initialize an empty header structure.
	 * Returns -1 on error, the SMB header size on success.
	 * ---------------------------------------------------- **
	 */
	int i;
	const char *smb_hdrSMBString = "\xFFSMB";
	
	if( bsize < SMB_HDR_SIZE )
		return( FAIL );

	for( i = 0; i < 4; i++ )
		bufr[i] = smb_hdrSMBString[i];
	for( i = 4; i < SMB_HDR_SIZE; i++ )
		bufr[i] = '\0';

	return( SMB_HDR_SIZE );
}

int SMB::nbt_SessionHeader( unsigned char *bufr, unsigned long size ) {
	/* ---------------------------------------------------- **
	 * This function writes the NBT Session Service header.
	 * Note that we use NBT byte order, not SMB.
	 * ---------------------------------------------------- **
	 */
	if( size > 0x0001FFFF || size < 4 ) /* That's the NBT maximum. */
		return( FAIL );
	bufr[0] = 0;
	bufr[1] = (size >> 16) & 0xFF;
	bufr[2] = (size >>  8) & 0xFF;
	bufr[3] = size & 0xFF;
	return( (int)size );
}


int SMB::smb_NegProtRequest( unsigned char  *bufr, int bsize, int namec, const unsigned char **namev ) {
	/* ---------------------------------------------------- **
	* Build a Negotiate Protocol Request message.
	* ---------------------------------------------------- **
	*/
	unsigned char *smb_bufr;
	int    i;
	int    length;
	int    offset;
	unsigned short bytecount;
	unsigned char  flags;
	unsigned short flags2;

	/*
	 * Set aside four bytes for the session header.
	 */
	bsize    = bsize - 4;
	smb_bufr = bufr + 4;

	/* Make sure we have enough room for the header,
	* the WORDCOUNT field, and the BYTECOUNT field.
	* That's the absolute minimum (with no dialects).
	*/
	if( bsize < (SMB_HDR_SIZE + 3) )
		return(FAIL);

	/* Initialize the SMB header.
	 * This zero-fills all header fields except for
	 * the Protocol field ("\ffSMB").
	 * We have already tested the buffer size so
	 * we can void the return value.
	 */
	(void)smb_hdrInit( smb_bufr, bsize );
	
	/* Hard-coded flags values...
	 */
	flags  = SMB_FLAGS_CANONICAL_PATHNAMES;
	flags |= SMB_FLAGS_CASELESS_PATHNAMES;
	flags2 = SMB_FLAGS2_KNOWS_LONG_NAMES;
	
	/* Fill in the header.
	 */
	smb_hdrSetCmd(smb_bufr, SMB_COM_NEGOTIATE );
	smb_hdrSetFlags(smb_bufr, flags );
	smb_hdrSetFlags2(smb_bufr, flags2 );
	
	/* Fill in the (empty) parameter block.
	 */
	smb_bufr[SMB_HDR_SIZE] = 0;
	
	/* Copy the dialect names into the message.
	 * Set offset to indicate the start of the
	 * BYTES field, skipping BYTECOUNT.  We will
	 * fill in BYTECOUNT later.
	 */
	offset = SMB_HDR_SIZE + 3;
	for( bytecount = i = 0; i < namec; i++ ) {
		length = strlen((const char *)namev[i]) + 1;       /* includes nul  */
		if( bsize < (offset + 1 + length) )  /* includes 0x02 */
			return( FAIL );
		smb_bufr[offset++] = '\x02';
		(void)memcpy( &smb_bufr[offset], namev[i], length );
		offset += length;
		bytecount += length + 1;
	}

	/* The offset is now the total size of the SMB message.
	 */
	if( nbt_SessionHeader( bufr, (unsigned long)offset ) < offset )
		return(FAIL);

	/* The BYTECOUNT field starts one byte beyond the end
	 * of the header (one byte for the WORDCOUNT field).
	 */
	SMBUtil::smb_SetShort( smb_bufr, (SMB_HDR_SIZE + 1), bytecount );

	/* Return the total size of the packet.
	 */
	return( offset + 4 );
}

int SMB::smb_SessSetupRequest(unsigned char *buf, unsigned int bsize) {
	char smb_data[]="\x1b\x00\x00\x00\x00\x00\x00\x55\x00\x6e\x00\x69\x00\x78\x00\x00\x00\x53\x00\x61\x00\x6d\x00\x62\x00\x61\x00\x00\x00";
	char wordcount = 26; // size of our SMB parameters
	
	unsigned char *smb_bufr;
	unsigned char  flags;
	unsigned short flags2;
	unsigned long smblen;

	bsize    = bsize - 4;
	smb_bufr = buf + 4;

	if (bsize < SMB_HDR_SIZE+wordcount+sizeof(smb_data)+1)
		return FAIL;
	(void)smb_hdrInit(smb_bufr, bsize );
	/* Hard-coded flags values...
	 */
	flags  = SMB_FLAGS_CANONICAL_PATHNAMES;
	flags |= SMB_FLAGS_CASELESS_PATHNAMES;
	flags2 = SMB_FLAGS2_KNOWS_LONG_NAMES;
	smb_hdrSetCmd(smb_bufr, SMB_COM_SESS_SETUP_ANDX);
	smb_hdrSetFlags(smb_bufr, flags );
	smb_hdrSetFlags2(smb_bufr, flags2 );

    smb_bufr[SMB_OFFSET_WC]=wordcount/2;  /* 12 or 13 words */
	smb_bufr[SMB_OFFSET_COM]=0xff;
	smb_bufr[SMB_OFFSET_XRESERVED]=0;
	SMBUtil::smb_SetShort(smb_bufr, SMB_OFFSET_OFFSET,0);
	SMBUtil::smb_SetShort(smb_bufr,SMB_OFFSET_MAXBUF,65535);
	SMBUtil::smb_SetShort(smb_bufr, SMB_OFFSET_MPXCNT, 2);
	SMBUtil::smb_SetShort(smb_bufr,SMB_OFFSET_VCNUM, getpid());
	SMBUtil::smb_SetLong(smb_bufr,SMB_OFFSET_SESSKEY, 0);
	SMBUtil::smb_SetShort(smb_bufr,SMB_OFFSET_CIPASSLEN, 0);
	SMBUtil::smb_SetShort(smb_bufr,SMB_OFFSET_CSPASSLEN, 0);
	SMBUtil::smb_SetLong(smb_bufr,SMB_OFFSET_RESERVED, 0);
	SMBUtil::smb_SetLong(smb_bufr, SMB_OFFSET_CAPABILITIES, 0x0000005c);

	memcpy(smb_bufr+SMB_HDR_SIZE+wordcount+1, smb_data, sizeof(smb_data));
	smblen = SMB_HDR_SIZE+wordcount+sizeof(smb_data);
	if(nbt_SessionHeader( buf, smblen) == FAIL )
		return( FAIL );
	return smblen+4;	// session header is 4 bytes
}

int SMB::session_setup_and_x(struct in_addr target, unsigned short port) {
	const unsigned char *dialects[] = {
		(const unsigned char *)"PC NETWORK PROGRAM 1.0",
		(const unsigned char *)"MICROSOFT NETWORKS 1.03",
		(const unsigned char *)"MICROSOFT NETWORKS 3.0",
		(const unsigned char *)"LANMAN1.0",
		(const unsigned char *)"LM1.2X002",
		(const unsigned char *)"DOS LANMAN2.1",
		(const unsigned char *)"Samba",
		(const unsigned char *)"NT LANMAN 1.0",
		(const unsigned char *)"NT LM 0.12"
	};
	unsigned char buf[2048], *nativeosptr=NULL;
	unsigned char wordcount=0, bytecount=0, k;
	int sock, size;
	string tmp;
	vector<string> tokens;
	
	bzero(buf, sizeof(buf));

	// lets try to get the name using node status query
	NBT_Node_Status_Query(target);

	sock = NBT_Session(target, port);
	
	if (sock == FAIL) {
		ui->error("SMB::session_setup_and_x: NBT_Session() failed!\n");
		return FAIL;
	} else if (sock == RETRY) {
		/*
		 * default name we are calling remote box "*SMBSERVER" failed
		 * we now send NBT Node Status Query which should provide us
		 * with the name we need
		 */
		ui->error("SMB::session_setup_and_x: Remote target didn't accept called name %s\n", calledname.c_str());
		return FAIL;
	}
		
	size = smb_NegProtRequest(buf,sizeof(buf), 9, dialects);
	if (size == FAIL) {
		ui->error("SMB::session_setup_and_x: smb_NegProtRequest(): failed!\n");
		return FAIL;
	}
		
	if ((size = send(sock, buf, size, 0)) < 1) {
		ui->error("SMB::session_setup_and_x: send(): failed!\n");
		return FAIL;
	}
	
	/*
	 * to make sure remote box replies
	 */
	size = xp_lib::RecvTimeout( sock, buf, sizeof(buf), 1);

	if (size < 1) {
		ui->error("--SMB::session_setup_and_x: failed to read NegProt response\n");
		return FAIL;
	}
	xprobe_debug(XPROBE_DEBUG_MODULES, "--SMB::session_setup_and_x: Received NEG PROTO response %d bytes\n", size );
	bzero(buf, sizeof(buf));
	size = smb_SessSetupRequest(buf, sizeof(buf));
	
	if ((size=send(sock, buf, size, 0)) < 1) {
		return FAIL;
	}
	
	size = xp_lib::RecvTimeout( sock, buf, sizeof(buf), 1);
	
	if (size < SMB_HDR_SIZE+3+4) {
		close(sock);
		return FAIL;
	}
	wordcount = buf[SMB_HDR_SIZE+4];

	/* 
	 * Argh...ugly checks!
	 *
	 * 4 bytes NBT header
	 * 32 bytes SMB header
	 * 1 bytes word count
	 * word count * 2 bytes SMB params
	 * 1 byte byte count
	 */
	if ((4 + SMB_HDR_SIZE + 1 + (wordcount*2) + 1) > size) {
		ui->error("--SMB::session_setup_and_x: [wordcount] invalid Sess Setup And X reply (reported length is less than received). Received=%d Reported=%d\n", size, (4 + SMB_HDR_SIZE + 1 + (wordcount*2) + 1));
		close(sock);
		return FAIL;
	}
	bytecount = buf[SMB_HDR_SIZE+4+(wordcount*2)+1];

	/*
	 * Argh...ugly checks!
	 */
	if ((4 + SMB_HDR_SIZE + 1 + (wordcount*2) + 1 + bytecount) > size) {
		ui->error("--SMB::session_setup_and_x: [bytecount] invalid Sess Setup And X reply (reported length is less than received). Received=%d Reported=%d\n", size, (4 + SMB_HDR_SIZE + 1 + (wordcount*2) + 1));
		close(sock);
		return FAIL;
	}

	if (bytecount > 0) {
		nativeosptr = &buf[SMB::SMB_HDR_SIZE+4+(wordcount*2)+2];
		for (k=0; k < bytecount; k++) {
			if (nativeosptr[k] == '\0') {
				tmp.append("|");
			} else {
				tmp+=nativeosptr[k];
			}
		}
		xp_lib::tokenize(tmp.c_str(), '|', &tokens);
		if (tokens.size() == 4) {
			nativeos = tokens[1];
			lanman = tokens[2];
			domain = tokens[3];
		} else {
			ui->error("--SMB::session_setup_and_x: Invalid number of tokens: %d (nativeos, ...)\n",
							tokens.size());
			close(sock);
			return FAIL;
		}
	}
	close(sock);
	return OK;
}

int SMB::NBT_Node_Status_Query(struct in_addr dst_addr) {
	// NBT node status request packet
	unsigned char nbtrequest[]="\x81\x9e" // transaction id, modified below
					"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
					"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
					"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
					"\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01";
	unsigned char buf[2048];
	unsigned short transid = rand();
	int sock, size, offset, i, k;
	char num_of_names;
	struct sockaddr_in sin, to;

	// make sure we don't try *SMBSERVER once again

	/* set the transaction id and later check its value
	 * to make sure the reply has not been spoofed
	 */
	SMBUtil::smb_SetShort(nbtrequest, 0, transid);
	xprobe_debug(XPROBE_DEBUG_MODULES, "--Transaction ID: %d\n", transid);

	/*
	 * for bind
	 */
	bzero(&sin, sizeof(sin));
	bzero(&to, sizeof(to));
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(137);
	to.sin_addr = dst_addr;
	to.sin_port = htons(137);
	to.sin_family = AF_INET;

	sock = xp_lib::OpenUDPSocket(&to, &sin);	
	if (sock == FAIL) {
		ui->error("SMB::NBT_Node_Status_Query: xp_lib::OpenUDPSocket failed! (%s)\n", strerror(errno));
		return FAIL;
	}

	/*
	 * for sendto
	 */
	sin.sin_addr = dst_addr;
	size = send(sock, nbtrequest, sizeof(nbtrequest)-1, 0);
	if (size < 1) {
		ui->error("SMB::NBT_Node_Status_Query: sendto() failed!\n");
		close(sock);
		return FAIL;
	}

	xprobe_debug(XPROBE_DEBUG_MODULES, "--SMB::NBT_Node_Status_Query: Sent %d bytes\n", size);

	bzero(buf, sizeof(buf));

	size = xp_lib::RecvTimeout( sock, buf, sizeof(buf)-1, 2);

	if (size < 1) {
		ui->error("SMB::NBT_Node_Status_Query: xp_lib::RecvTimeout() failed!\n");
		close(sock);
		return FAIL;
	}

	xprobe_debug(XPROBE_DEBUG_MODULES, "--SMB::NBT_Node_Status_Query: Received %d bytes\n", size);

	/*
	 * first sanity check,
	 * make sure we have enough to reference the 13th byte
	 */
	if (size < 13) {
		ui->error("SMB::NBT_Node_Status_Query: corrupted/truncated reply\n");
		close(sock);
		return FAIL;
	}
	offset =	2 + 12						/* Length of the header */
				+ strlen((const char *) &buf[12] ) + 1	/* NBT Name length      */
				+ 2 + 2 + 4;				/* Type, Class, & TTL   */
	  
	/*
	 * check transaction ID
	 */
	if (transid != SMBUtil::smb_GetShort(buf, 0)) {
		ui->error("SMB::NBT_Node_Status_Query: invalid transaction ID (spoofed?)\n");
		close(sock);
		return FAIL;
	}
	/*
	 * second sanity check,
	 * make sure offset we have calculated is valid
	 */
	if (size <= offset+2) {
		ui->error("SMB::NBT_Node_Status_Query: invalid offset (corrupted packet or someone's playing games w/ us?)\n");
		close(sock);
		return FAIL;
	}

	num_of_names = buf[offset++];

	/*
	 * third sanity check,
	 * make sure we have received all names claimed + MAC + other header params
	 */
	if (size < (num_of_names * 18)+offset+6+36) {
		ui->error("SMB::NBT_Node_Status_Query: invalid number of names(corrupted packet or someone's playing games w/ us?)\n");
		close(sock);
		return FAIL;
	}

	for( i = 0; i < num_of_names; i++, offset += 18 ) {
		if (buf[offset+15] == NBT_SERVER_SERVICE) {
			calledname.erase();
			for (k=0; k < 15; k++) {
				if (isprint(buf[offset+k])) {
					calledname+=buf[offset+k];
				} else {
					/* nonprintable char in name, something's wrong */
					ui->error("SMB::NBT_Node_Status_Query: nonprintable char in name\n");
					close(sock);
					return FAIL;
				}
			}	
		}
	}

	mac[0] = buf[offset];
	mac[1] = buf[offset+1];
	mac[2] = buf[offset+2];
	mac[3] = buf[offset+3];
	mac[4] = buf[offset+4];
	mac[5] = buf[offset+5];

	close(sock);
	return OK;
}

string SMB::get_mac(void) {
	char buf[128];
	string retval;
	
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	retval = buf;
	return retval;
}
