/* $Id: xprobe_module_param.cc,v 1.12 2005/07/18 11:08:24 mederchik Exp $ */
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
#include "xprobe_module_param.h"
#include "interface.h"
#include "xplib/xplib.h"

extern Interface *ui;

int Xprobe_Module_Param::sig_insert(int os_id, xprobe_module_param_t p) {
                if (osid_sig.find(os_id) != osid_sig.end()) 
                    return FAIL;
            osid_sig.insert(pair <int, xprobe_module_param_t>(os_id, p));
            return OK;

        }

int Xprobe_Module_Param::add_param(int param, int orig, OS_Matrix *os) {
    map <int, xprobe_module_param_t>::iterator sig_i;
	unsigned int ix;
	long id_diff;
	vector <int> *vec_ptr;

    for (sig_i = osid_sig.begin(); sig_i != osid_sig.end(); sig_i++) {
    
            switch (type) {

                case XPROBE_MODULE_PARAM_BOOL:
                case XPROBE_MODULE_PARAM_ZNZ:
                    if ((param == 0 && (*sig_i).second.low == 0) ||
                         param != 0 && (*sig_i).second.low == 1) {
                        os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_YES);
                    } else {
                        os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_NO);
                    }
                    break;
				case XPROBE_MODULE_PARAM_ZNZORIG:
					if ((param == 0 && sig_i->second.low == 0) ||
						(param != orig && param != 0 && sig_i->second.low == 1) ||
						(param == orig && sig_i->second.low == -1)) {
                        os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_YES);
					} else {
                        os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_NO);
					}
					break;

				case XPROBE_MODULE_PARAM_ZNZVAL:
					if ((param == sig_i->second.low) ||
						(param != 0 && sig_i->second.low == -1)) {
						os->add_result(get_id(), sig_i->first, XPROBE_MATCH_YES);
					} else {
						os->add_result(get_id(), sig_i->first, XPROBE_MATCH_NO);
					}
					break;

                case XPROBE_MODULE_PARAM_RANGE:
                    if ((*sig_i).second.low == 0 &&
                            (*sig_i).second.high >= XPROBE_MODULE_PARAM_FUZZY_DELTA) { // * no lower mark
                        if ((*sig_i).second.high - XPROBE_MODULE_PARAM_FUZZY_DELTA <= param &&
                                param <= (*sig_i).second.high) {
                            os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_YES);
						} else {
                            os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_NO);
						}
                        break;
                    } else {
                        
                        if ((*sig_i).second.low < param && param <= (*sig_i).second.high)
                            os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_YES);
                        else    
                            os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_NO);
                        break;
                    }

                case XPROBE_MODULE_PARAM_INT:
                    if ((*sig_i).second.low < param && param < (*sig_i).second.high)
                        os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_YES);
                    else    
                        os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_NO);
					break;
	
				case XPROBE_MODULE_PARAM_INTLIST:
					vec_ptr = &((*sig_i).second.val_list);
					for (ix = 0; ix < vec_ptr->size(); ix++) {						
						if (param == (*vec_ptr)[ix]) {
							os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_YES);
							break;
						}
					}
					if (param != (*vec_ptr)[ix]) // no match was found
						os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_NO);
					break;

				case XPROBE_MODULE_PARAM_STRATEGY:
					id_diff = param - orig;
					if ((id_diff > XMP_STRATEGY_THRESHOLD || id_diff < 0)  && (*sig_i).second.low == XMP_STRATEGY_RANDOM)
						os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_YES);
					else if (id_diff > 0 && id_diff <= XMP_STRATEGY_THRESHOLD && (*sig_i).second.low == XMP_STRATEGY_INCREMENTAL)
						os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_YES);
					else if (id_diff == 0 && (*sig_i).second.low == XMP_STRATEGY_ZERO) 
						os->add_result(get_id(), (*sig_i).first, XPROBE_MATCH_YES);
					break;
               default:
               /* oops */
					ui->msg("Something fucked in add_param\n");
               return FAIL;
            } /* switch */
    } /* for */
    return OK;
                
}

/* Lamye-arse parser.. will do it better later ;-) XXX */
int Xprobe_Module_Param::parse_param(int os_id, const char *param) {
    xprobe_module_param_t p;

    switch(type) {
        case XPROBE_MODULE_PARAM_BOOL:
        case XPROBE_MODULE_PARAM_ZNZ:
		case XPROBE_MODULE_PARAM_ZNZORIG:
            switch (param[0]) {
                case '0':
                    p.low = 0;
                    sig_insert(os_id, p);
                   return OK;
                case '!':
                    p.low = 1;
                    sig_insert(os_id, p);
                    return OK;
                case 'y':
                    p.low = 1;
                    sig_insert(os_id, p);
                    return OK;
                case 'n':
                    p.low = 0;
                    sig_insert(os_id, p);
                    return OK;        
				case 'S':
				case 's':
					if (type == XPROBE_MODULE_PARAM_ZNZORIG && !(strncasecmp(param, "SENT", 4))) {
						p.low = -1;
						sig_insert(os_id, p);
						return OK;
					}
                default:
                    ui->msg("xprobe_param module:  unknown value %s\n", param);
            }
            return FAIL;
            /* unreach */
            break;

		case XPROBE_MODULE_PARAM_ZNZVAL:
			if (param[0] == '!') {
				p.low = -1;
			} else if (param[0] >= '0' && param[0] <= '9') {
				errno = 0;
				p.low = strtol(param, NULL, 0);
				if (errno == ERANGE) {
					ui->msg("xprobe_param: bad value %s\n", param);
					return FAIL;
				}
			}
			sig_insert(os_id, p);
			return OK;
			break;

        case XPROBE_MODULE_PARAM_INT:
        case XPROBE_MODULE_PARAM_RANGE:
            if (param[0] == '<') {
                p.low = 0; p.high = atoi(param+1);
            } else if (param[0] == '>') {
                p.low = atoi(param+1); p.high = 256;
            } else  {
                p.low = atoi(param) - 1; p.high = atoi(param) + 1;
            }
			sig_insert(os_id, p);
            return OK;
            break;
		case XPROBE_MODULE_PARAM_INTLIST:
			if (xp_lib::tokenize(param, ',', &p.val_list) == FAIL) {
				ui->error("xp_lib::tokenize() failed!\n");
				return FAIL;
			}
			sig_insert(os_id, p);
			return OK;
			break;
		case XPROBE_MODULE_PARAM_STRATEGY:
			switch(param[0]) {
				case 'R':
					p.low = XMP_STRATEGY_RANDOM;
					break;
				case 'I':
					p.low = XMP_STRATEGY_INCREMENTAL;
					break;
				case '0':
					p.low = XMP_STRATEGY_ZERO;
					break;
				default:
					ui->msg("xprobe_param module:  unknown value %s\n", param);
					return FAIL;
			}
			sig_insert(os_id, p);
			return OK;
			break;
        default:
            ui->msg("Xprobe_Module_Param::parse_param(): oops.. something fucked up!\n");
    }
    return FAIL;
}

int Xprobe_Module_Param::gen_match(int cnt, OS_Matrix *os) {
	map <int, xprobe_module_param_t>::iterator sig_i;
	int i;

	if (cnt < 0)
		return OK;
	for (sig_i = osid_sig.begin(); sig_i != osid_sig.end(); sig_i++) 
		for (i=0; i < cnt; i++)
			os->add_result(get_id(), sig_i->first, XPROBE_MATCH_YES);
	return OK;
}
