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


#include "redis_debug.hpp"
#include "redis_internal.hpp"



void redis_debug_start_session(redis_sess_t& sess)
{
    TEST_AUDIT_DEBUG_LEVEL_INFO

    std::cout << std::dec << sess.id << "[[ SESSION START ]] {" << sess.tuple.saddr << ":" << sess.tuple.sport << " -> " << sess.tuple.daddr << ":" << sess.tuple.dport << "}" << std::endl;
}


void redis_debug_end_session(redis_sess_t& sess)
{
    TEST_AUDIT_DEBUG_LEVEL_INFO

    std::cout << std::dec << sess.id << "[[ SESSION END   ]] {" << sess.tuple.saddr << ":" << sess.tuple.sport << " -> " << sess.tuple.daddr << ":" << sess.tuple.dport << "}" << std::endl;
}


void redis_debug_exit_session(redis_sess_t& sess)
{
    TEST_AUDIT_DEBUG_LEVEL_WARN

    std::cout << std::dec << sess.id << "[[ SESSION EXIT  ]] {" << sess.tuple.saddr << ":" << sess.tuple.sport << " -> " << sess.tuple.daddr << ":" << sess.tuple.dport << "}" << std::endl;
}

