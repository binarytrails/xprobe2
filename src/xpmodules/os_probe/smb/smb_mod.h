/*
 * **
 * ** Copyright (C) 2005 Meder Kydyraliev <meder@o0o.nu>
 * ** Copyright (C) 2001-2005  Fyodor Yarochkin <fygrave@tigerteam.net>,
 * ** 						Ofir Arkin <ofir@sys-security.com>
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

#ifndef TCP_SMB_MOD_H
#define TCP_SMB_MOD_H

#include "xprobe.h"
#include "xprobe_module.h"
#include "xprobe_module_param.h"
#include "smb.h"


class SMB_Mod: public Xprobe_Module {
	private:
		class SMBFingerprint {
			public:
				string nativeos, lanman;
		};
		map<int, SMBFingerprint *> smb_fingerprints;
	public:
		SMB_Mod(void);
		~SMB_Mod(void);
		int init(void);
		int parse_keyword(int, const char *, const char *);
		int exec(Target *, OS_Matrix *);
		int fini(void);
};

#endif /* TCP_SMB_MOD_H */
