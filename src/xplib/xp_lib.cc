/*
 * **
 * ** Copyright (C) 2001-2005 Fyodor Yarochkin <fygrave@tigerteam.net>,
 * **                    Ofir Arkin       <ofir@sys-security.com>
 * **                    Meder Kydyraliev <meder@o0o.nu>
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
#include "xp_lib.h"

int xp_lib::tokenize(const char *input, char delimiter, vector<string> *tokens) {

	string str(input);
	string::size_type pos, lastpos;

	if (tokens == NULL)
		return FAIL;
	pos = str.find_first_of(delimiter);
	lastpos = str.find_first_not_of(delimiter, 0);

	/* tokenizer */
	while (pos != string::npos && lastpos != string::npos) {
		tokens->push_back(str.substr(lastpos, pos - lastpos));
		lastpos = str.find_first_not_of(delimiter, pos);
		pos = str.find_first_of(delimiter, lastpos);
	}
	if (pos == string::npos && lastpos != string::npos) {
		// handle the last token
		tokens->push_back(str.substr(lastpos, str.size()-lastpos+1));
	}
	return OK;
}

int xp_lib::tokenize(const char *input, char delimiter, vector<int> *tokens) {
	vector <string> str_vector;
	unsigned int ix;
	
	if (tokens != NULL && tokenize(input, delimiter, &str_vector) == OK) {
		for (ix = 0; ix < str_vector.size(); ix++) {
			tokens->push_back(atoi(str_vector[ix].c_str()));
		}
		return OK;
	}
	return FAIL;
}

string xp_lib::int_to_string(int toconvert) {
	char buf[512];
	string retval;
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d", toconvert);
	retval = buf;
	return retval;
}

bool xp_lib::equal(const char *str1, const char *str2) {
	return (strncasecmp(str1, str2, strlen(str1)) == 0);
}

bool xp_lib::equal(string str1, string str2) {
	return equal(str1.c_str(), str2.c_str());
}

int xp_lib::OpenUDPSocket(struct sockaddr_in *to, struct sockaddr_in *bind_sin) {

	int sock;
	
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return FAIL;
	}
	if (bind_sin != NULL)
		if (bind(sock, (struct sockaddr *)bind_sin, sizeof(struct sockaddr_in)) == -1) {
			return FAIL;
		}

	if (to != NULL)
		if (connect(sock, (struct sockaddr *) to, sizeof(struct sockaddr_in)) == -1) {
			return FAIL;
		}

	return sock;
}

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

int xp_lib::OpenTCPSession( struct in_addr dst_IP, unsigned short dst_port ) {
  /* ---------------------------------------------------- **
   * Open a TCP session with the specified server.
   * Return the connected socket.
   * ---------------------------------------------------- **
   */
	int                sock;
	int                result;
	struct sockaddr_in sock_addr;
	
	/* Create the socket.
	 */
	sock = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );
	if( sock < 0 ) {
		printf( "Failed to create socket(); %s.\n", strerror( errno ) );
		return(FAIL);
	}

	/* Connect the socket to the server at the other end.
	 */
	sock_addr.sin_addr   = dst_IP;
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port   = htons( dst_port );
	result = connect( sock, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_in) );
	if( result < 0 ) {
		printf( "Failed to create socket(); %s.\n", strerror( errno ) );
		return(FAIL);
	}

	return( sock );
}
int xp_lib::RecvTimeout( int sock, unsigned char *bufr, int bsize, int timeout ) {
  /* ---------------------------------------------------- **
   * Attempt to receive a TCP packet within a specified
   * period of time.
   * ---------------------------------------------------- **
   */  
	int result;
	fd_set rset;
	struct timeval tv;
	
	FD_ZERO(&rset);
	FD_SET(sock, &rset);
	tv.tv_usec=0;
	tv.tv_sec=timeout;
	result = select(sock+1, &rset, NULL, NULL, &tv);
	
	/* A result less than zero is an error.
	 */
	if( result < 0 ) {
		printf( "select() error: %s\n", strerror( errno ) );
		return(FAIL);
	}

	/* A result of zero is a timeout.
	 */
	if( result == 0 )
		return( 0 );

	/* A result greater than zero means a message arrived,
	 * so we attempt to read the message.
	 */
	result = recv( sock, bufr, bsize, 0 );
	if( result < 0 ) {
		printf( "Recv() error: %s\n", strerror( errno ) );
		return(FAIL);
	}

	/* Return the number of bytes received.
	 * (Zero or more.)
	 */
	return( result );
} 

