
/* $Id: os_matrix.h,v 1.6 2005/06/26 11:29:50 mederchik Exp $ */
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

#ifndef OS_MATRIX_H
#define OS_MATRIX_H

#include "xprobe.h"
/*
#include <string>
#include <map>
#include <vector>
#include <algorithm>
*/

using namespace std;

#define XPROBE_MATCH_NO             0
#define XPROBE_MATCH_PROBABLY_NO    1
#define XPROBE_MATCH_PROBABLY_YES   2
#define XPROBE_MATCH_YES            3

class OS_Name {
    private:
        map <int, string> osid_name;
        int id_count;
    public:
        OS_Name(void);
        const string osid2str(int);
        const char *osid2char(int id) {
             string s = osid2str(id);
             return (s.c_str());
        }
        int add_os(string &os_name);
        int find_os(string &os_name);
        void list_oses(void);
        int get_osnum(void) { return id_count; }
};
               

class OS_Vector {

    private:
        int os_id;
        /* we may need this later: map<int, int> mod_score; */
        int total;
		int numofkwds;

    public:
        OS_Vector(int);
        void add_result(int, int);
        int get_total(void) { return total; }
        int get_os_id(void) { return os_id; }
		int get_number_of_keywords(void) { return numofkwds; }
        friend bool os_vector_compare(const OS_Vector &, const OS_Vector &);
};


class OS_Matrix {
    private:
        vector <OS_Vector> osid_vec;
        int xp_loaded_mods;
        int find_os_id(int);
    
    public:
        OS_Matrix(int);
        virtual ~OS_Matrix(void);
        void add_result(int, int, int, int times = 1);
        /* returns top num scored OS id */
        int get_top(int);
        /* returns given os_id score */
        int get_score(int);
        /* returns maximum possible score --> max score by number of
         * tests */
        int get_max_score(int);
        /* returns given os_id score in percent */
        int get_prcnt_score(int);
};

#endif /* INTERFACE_H */
            
