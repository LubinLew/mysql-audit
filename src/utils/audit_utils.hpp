/*  Copyright (C) 2024 LubinLew
    SPDX short identifier: MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the “Software”), to deal in 
the Software without restriction, including without limitation the rights to use, 
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
OTHER DEALINGS IN THE SOFTWARE. */


#ifndef __AUDIT_UTILS_HPP__
#define __AUDIT_UTILS_HPP__
/*****************************************************************************/

#include <time.h>
#include <stdint.h>

#include "audit_types.hpp"

/*****************************************************************************/

uint32_t audit_util_date_compress(time_t& t);
time_t   audit_util_date_decompress(uint32_t date);

audit_str_t audit_util_time_diff_from_now(struct timespec& start);
audit_str_t audit_util_time_get(struct timespec& start);
audit_str_t audit_util_time_get_now(void);

/*****************************************************************************/
#endif /* __AUDIT_UTILS_HPP__ */

