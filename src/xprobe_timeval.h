/* $Id: xprobe_timeval.h,v 1.2 2003/08/20 05:30:16 mederchik Exp $ */
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

#ifndef XPROBE_TIMEVAL_H
#define XPROBE_TIMEVAL_H

#include "xprobe.h"

namespace Xprobe {
#define USECS2SEC   1000000
    class Timeval: public timeval {
        public:
            Timeval();
            Timeval(long sec_, long usec_);
            Timeval(double t_);
            Timeval(const struct timeval& t_);
            Timeval(const Timeval& t_);
            operator double () const;
            void sec(long s_) { tv_sec = s_; }
            long sec(void) const { return tv_sec; }
            void usec(long us_) { tv_usec = us_; }
            long usec(void) const { return tv_usec; }
            long millisec(void) const;
            long microsec(void) const;
            Timeval& operator= (const Timeval& tv_);
            Timeval& operator+= (const Timeval& rh_);
            Timeval& operator-= (const Timeval& rh_);
            //Timeval& operator++ (void);
            //Timeval& operator-- (void);
            friend Timeval operator+ (const Timeval& lh_, const Timeval& rh_);
            friend Timeval operator- (const Timeval& lh_, const Timeval& rh_);
            bool operator< (const Timeval& rh_) const;
            bool operator== (const Timeval& rh_) const;
            friend bool operator> (const Timeval& lh_, const Timeval& rh_);
            friend bool operator!= (const Timeval& lh_, const Timeval& rh_);
            friend bool operator<= (const Timeval& lh_, const Timeval& rh_);
            friend bool operator>= (const Timeval& lh_, const Timeval& rh_);
            static Timeval gettimeofday();
        protected:    
            void init(long, long);
        private:            
            void align(void);
           /* no members */
    };

    inline void Timeval::init (long sec_, long usec_) {
        tv_sec = sec_;
        tv_usec = usec_;
        align();
    }

    inline Timeval::Timeval (void) {
        init(0, 0);
    }

    inline Timeval::Timeval(long sec_, long usec_) {
        init(sec_, usec_);
    }

    inline Timeval::Timeval(double t_) {
        long l = (long)t_;
        tv_sec = l;
        tv_usec = (long)((t_ - double(l)) * 1000000.0);
        align();
    }

    inline Timeval::Timeval(const struct timeval& t_) {
        init(t_.tv_sec, t_.tv_usec);
    }

    inline Timeval::Timeval(const Timeval& t_) {
        init(t_.tv_sec, t_.tv_usec);
    }


    inline Timeval Timeval::gettimeofday() {
        struct timeval tv;
        ::gettimeofday(&tv, 0);
        return tv;
    }

    inline Timeval::operator double() const {
        return (tv_sec + tv_usec / 1000000.0);
    }

    // return total in milliseconds
    inline long Timeval::millisec() const{
        return sec()*1000 + (usec() % 1000000) / 1000;
    }

    // return total in microseconds
    inline long Timeval::microsec() const{
        return sec()*1000000 + usec();
    }

    /* logic */

    inline Timeval& Timeval::operator= (const Timeval& tv_) {
        init(tv_.tv_sec, tv_.tv_usec);
        return *this;
    }

    inline Timeval operator+ (const Timeval& lh_, const Timeval& rh_) {
        Timeval tmp(lh_);
        tmp += rh_;
        tmp.align();
        return tmp;
    }

    inline Timeval operator- (const Timeval& lh_, const Timeval& rh_) {
        Timeval tmp(lh_);
        tmp -= rh_;
        tmp.align();
        return tmp;
    }

    inline Timeval& Timeval::operator+= (const Timeval& rh_) {
        tv_sec += rh_.tv_sec;
        tv_usec += rh_.tv_usec;
        align();
		return *this;
    }

    inline Timeval& Timeval::operator-= (const Timeval& rh_) {
        tv_sec -= rh_.tv_sec;
        tv_usec -= rh_.tv_usec;
        align();
		return *this;
    }

    inline void Timeval::align(void) {

        if (tv_usec >= USECS2SEC) {
            do {
                tv_sec++;
                tv_usec -= USECS2SEC;
            } while (tv_usec >= USECS2SEC);
        } else if (tv_usec <= -USECS2SEC) {
            do {
                tv_sec--;
                tv_usec += USECS2SEC;
            } while (tv_usec <= -USECS2SEC);
        }

        if (tv_sec > 0 && tv_usec < 0) {
            tv_sec--;
            tv_usec += USECS2SEC;
        } else if (tv_sec < 0 && tv_usec > 0) {
            tv_sec++;
            tv_usec -= USECS2SEC;
        }

    }
                    
    inline bool Timeval::operator< (const Timeval& rh_) const {

        return (tv_sec < rh_.tv_sec || (tv_sec == rh_.tv_sec && tv_usec < rh_.tv_usec)) ;
    }

    inline bool Timeval::operator== (const Timeval & rh_) const {
        return !(*this < rh_ || rh_ < *this);
    }

    inline bool operator> (const Timeval& lh_, const Timeval& rh_) {
        return rh_ < lh_;
    }

    inline bool operator!= (const Timeval& lh_, const Timeval& rh_) {
        return !( rh_ == lh_ );
    }
    
    inline bool operator<= (const Timeval& lh_, const Timeval& rh_) {
        return !( rh_ < lh_ );
    }
    
    inline bool operator>= (const Timeval& lh_, const Timeval& rh_) {
        return !( lh_ < rh_ );
    }


}; /* namespace */
#endif
