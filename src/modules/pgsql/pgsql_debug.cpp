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


#include "pgsql_debug.hpp"





void pgsql_debug_msg(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    pgsql_msg_detail_t* info = sess.current_msg_info;

    if (info) {
        const char* dir = (sess.direction == PGSQL_DATA_DIR_C2S ? "C->S" : "S->C");
        audit_debug_dbg("MSG:[%s]\033[1;31m[%s]\033[0m[length:%u]", dir, info->description, msg.length);
    }
}


void pgsql_debug_msg_error(pgsql_sess_t& sess, pgsql_msg_err_t& err)
{
    audit_debug_dbg("ERROR\nseverity: %s\ncode: %s\nmessage: %s\n",
        err.severity.c_str(),
        err.code.c_str(),
        err.message.c_str()
     );
}




