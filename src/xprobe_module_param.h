/* $Id: xprobe_module_param.h,v 1.10 2005/02/08 20:00:36 mederchik Exp $ */
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

/*
 * Changes:
 *				-	Feb 12 14:34:04 2003 meder - added type XPROBE_MODULE_PARAM_ZNZORIG,
 *					that required addition of an extra argument to the add_param() and 
 *					check_param() methods;
 */
#ifndef XPROBE_MODULE_PARAM_H
#define XPROBE_MODULE_PARAM_H

#include "xprobe.h"
#include "usi++/usi++.h"
#include "target.h"
#include "os_matrix.h"
#include <string>

using namespace std;

#define XPROBE_MODULE_PARAM_BOOL		1      /* y/n */
#define XPROBE_MODULE_PARAM_ZNZ			2      /* zero, not zero -- !0, 0 */
#define XPROBE_MODULE_PARAM_INT			3      /* int - 1234 */
#define XPROBE_MODULE_PARAM_RANGE		4      /* range - <1, >2, 20-40 */
#define XPROBE_MODULE_PARAM_ZNZORIG		5		/* zero, not zero, original value(SENT) */
#define XPROBE_MODULE_PARAM_ZNZVAL		6		/* zero, value, not zero */
#define XPROBE_MODULE_PARAM_INTLIST		7		/* list of integers (1,2,3,4,...) */
#define XPROBE_MODULE_PARAM_STRATEGY	8		/* (R)andom, (I)ncremental, 0 */

#define XPROBE_MODULE_PARAM_FUZZY_DELTA     31


#define XMP_STRATEGY_RANDOM				2
#define XMP_STRATEGY_INCREMENTAL		1
#define XMP_STRATEGY_ZERO				0
#define XMP_STRATEGY_THRESHOLD			256	

typedef struct xprobe_module_param_val {
    int high;
    int low;
	vector <int> val_list;
} xprobe_module_param_t;



class Xprobe_Module_Param {
    private:
        int id;
        int type;
        map <int, xprobe_module_param_t> osid_sig;
        int sig_insert(int os_id, xprobe_module_param_t p);
    public:
        Xprobe_Module_Param(int t) { type = t; }
        virtual ~Xprobe_Module_Param(void) { return; }
//        virtual int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) =0;    
        int parse_param(int os_id, const char *param);
        int add_param(int param, int orig, OS_Matrix *os);
        void set_id(int i) { id = i; }
        int get_id(void) { return id; }
		int gen_match(int cnt, OS_Matrix *os);
};

class Xprobe_Module_Param_TCP: public Xprobe_Module_Param {
	public:
		Xprobe_Module_Param_TCP(int t): Xprobe_Module_Param(t) { return; }
		virtual ~Xprobe_Module_Param_TCP(void) { return; }
		virtual int check_param(TCP *ip_pkt, TCP *orig_pkt, OS_Matrix *os) =0;
};
class Xprobe_Module_Param_ICMP: public Xprobe_Module_Param {
	public:
		Xprobe_Module_Param_ICMP(int t): Xprobe_Module_Param(t) {return; }
		virtual ~Xprobe_Module_Param_ICMP(void) { return; }
		virtual int check_param(ICMP *ip_pkt, ICMP *orig_pkt, OS_Matrix *os) =0;
};


#endif /* XPROBE_MODULE_PARAM */
