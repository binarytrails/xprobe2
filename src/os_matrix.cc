/* $Id: os_matrix.cc,v 1.8 2005/07/18 11:08:24 mederchik Exp $ */
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

#include "xprobe.h"
#include "os_matrix.h"
#include "interface.h"
#include "xprobe_module_hdlr.h"

extern Interface *ui;

/*
 * OS_Name object.
 *****************
 */

OS_Name::OS_Name(void) {

    id_count = 0;

}

/*
 * OS_Name::add_os()
 *******************
 * returns FAIL is the OS already exist. os_id otherwise.
 */
 

int OS_Name::add_os(string &os_name) {

    if (find_os(os_name) != FAIL) return FAIL; /* exist */
    
    osid_name.insert(pair<int, string>(id_count, os_name));
    return (id_count++);
}


/*
 * OS_Name::find_os()
 *******************
 * returns FAIL is the OS does not exist. os_id otherwise.
 */
 

int OS_Name::find_os(string &os_name) {
    map <int, string>::iterator osid_i;

    for (osid_i = osid_name.begin();
         osid_i != osid_name.end(); osid_i++) {
        if ((*osid_i).second == os_name) return ((*osid_i).first); /* exist */
    }
    return FAIL; /* does not exist */
}


/*
 * OS_Name::list_oses()
 *******************
 * for debugging _ONLY_
 */
 

void OS_Name::list_oses(void) {
    map <int, string>::iterator osid_i;

    xprobe_mdebug(XPROBE_DEBUG_OSMATRIX,"Following systems are recognizable\n");
    for (osid_i = osid_name.begin();
         osid_i != osid_name.end(); osid_i++) {
        xprobe_debug(XPROBE_DEBUG_OSMATRIX,"Id: %i\tOS: %s\n",(*osid_i).first, (*osid_i).second.c_str());
    }
}


/*
 * OS_Name::list_oses()
 *******************
 * for debugging _ONLY_
 */
 


const string OS_Name::osid2str(int id) {
    map <int, string>::iterator osid_i = osid_name.find(id);
    if (osid_i != osid_name.end()) return ((*osid_i).second);
    return ("BUG, PLEASE REPORT! :-)");
}
    
/*
 * OS_Vector stuff:
 */        
OS_Vector::OS_Vector(int new_os_id) {
    os_id = new_os_id;
    total = 0;
	numofkwds=0;
}

void OS_Vector::add_result(int test_id, int score) {
    xprobe_debug(XPROBE_DEBUG_OSMATRIX, "added: test_id: %i score: %i\n",
     test_id, score);
    total += score;
	numofkwds++;
}

bool os_vector_compare(const OS_Vector &a, const OS_Vector &b) {

    if (a.total > b.total) return true;
    return false;
}



OS_Matrix::OS_Matrix(int mods) {

    xprobe_mdebug(XPROBE_DEBUG_INIT, "OS matrix initialized\n");
    xp_loaded_mods =mods;

}

OS_Matrix::~OS_Matrix(void) {

    xprobe_mdebug(XPROBE_DEBUG_INIT, "OS matrix deinitialized\n");

}


int OS_Matrix::find_os_id(int os_id) {
    unsigned int i;

    for (i = 0; i< osid_vec.size(); i++)
        if (os_id == osid_vec[i].get_os_id()) return i;
    return -1;
}
        
void OS_Matrix::add_result(int test_id, int os_id, int score, int times) {
    int i;

    xprobe_debug(XPROBE_DEBUG_OSMATRIX, "test_id: %i os_id: %i score: %i\n", test_id, os_id, score); 

    if (find_os_id(os_id) == -1) /* if doesn't exist. we insert it
                                      * first */
        osid_vec.push_back(OS_Vector(os_id));

    i = find_os_id(os_id);
	while (times-- > 0) {			
	    osid_vec[i].add_result(test_id, score);
	}
}

int OS_Matrix::get_score(int os_id) {

    if (find_os_id(os_id) == -1) return FAIL;

    return (osid_vec[find_os_id(os_id)].get_total());
}

int OS_Matrix::get_max_score(int os_id) {
	int i = find_os_id(os_id);
	
    //return (xp_loaded_mods * XPROBE_MATCH_YES);
	return (osid_vec[i].get_number_of_keywords() * XPROBE_MATCH_YES);

}

int OS_Matrix::get_prcnt_score(int os_id) {

    if (get_score(os_id) < 0) return 0;	
    return get_score(os_id) * 100/get_max_score(os_id);

}

int OS_Matrix::get_top(int num) { 

    sort(osid_vec.begin(), osid_vec.end(), os_vector_compare);

    if ((unsigned int)num < osid_vec.size())
        return osid_vec[num].get_os_id();

    return 0; /* out of range */
} 

