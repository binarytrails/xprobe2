/*
** Copyright (C) 2001, 2002 Meder Kydyraliev <meder@areopag.net>
**
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

#include "xp_get_random_data.h"

#define RAND_DEV	"/dev/urandom"

int xp_get_random_data(char *buf, int size) {
        struct stat fst;
        FILE *fd;
        int retval = FAIL;

        if (buf != NULL && stat(RAND_DEV, &fst) == 0) {
                if (fst.st_rdev & S_IFCHR) {
                        if ((fd = fopen (RAND_DEV, "r")) == NULL){
                                perror("xp_get_random_data():fdopen");
                                return FAIL;
                        }
                        if ((buf=fgets(buf, size, fd)) == NULL)
                                return FAIL;
                        if ( (fclose (fd)) != 0) {
                                perror("xp_get_random_data():fclose");
                                return FAIL;
                        }
                        retval = OK;
                }
        }
        return retval;
}
