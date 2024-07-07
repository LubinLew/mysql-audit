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


#include <tins/tcp_ip/stream.h>

#include <audit_data.hpp>

#include "pgsql_internal.hpp"
#include "pgsql_audit.hpp"
#include "pgsql_debug.hpp"

using Tins::TCPIP::Stream;


static audit_ret_t pgsql_client_msg_ssl_request(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    return RET_OK;
}


static audit_ret_t pgsql_client_msg_startup(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    uint8_t* start = msg.body;
    uint8_t* end   = start + msg.length;

    sess.startup_msg.major_version = audit_data_get_uint16_be(&start, end);
    sess.startup_msg.minor_version = audit_data_get_uint16_be(&start, end);

    audit_str_map_t& map = sess.startup_msg.paris;
    while (start < end - 1) {/* last char is nul */
        auto key = audit_data_get_string(&start, end);
        auto val = audit_data_get_string(&start, end);
        map.insert({key, val});
    }

    auto search = map.find("user");
    if (search != map.end()) {
        sess.user = search->second;
        map.erase(search);
    }

    search = map.find("database");
    if (search != map.end()) {
        sess.database = search->second;
        map.erase(search);
    }

    return RET_OK;
}

static audit_ret_t pgsql_client_msg_simple_query(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    uint8_t* start = msg.body;
    uint8_t* end   = start + msg.length;

    timespec_get(&sess.cmd_start_time, TIME_UTC);

    sess.statement = audit_data_get_string(&start, end);
    audit_debug_dbg("%s", sess.statement.c_str());

    sess.is_simple_query = true;
    sess.statistics_command_client = msg.length + 4;
    return RET_OK;
}


static audit_ret_t pgsql_client_msg_termination(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    return RET_OK;
}


audit_ret_t pgsql_client_msg_proc(Stream& stream, pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    audit_ret_t ret = RET_OK;

    sess.statistics_session_client += (msg.length + 4);

    switch (sess.msg_type) {
    case PGSQL_MSG_TYPE_SSL_REQUEST:
        ret = pgsql_client_msg_ssl_request(sess, msg);
        break;
    case PGSQL_MSG_TYPE_STARTUP:
        ret = pgsql_client_msg_startup(sess, msg);
        break;
    case PGSQL_MSG_TYPE_AUTH_MSG:     /* Authentication message */
        break;
    case PGSQL_MSG_TYPE_SIMPLE_QUERY: /* Simple query */
        ret = pgsql_client_msg_simple_query(sess, msg);
        break;
    case PGSQL_MSG_TYPE_PARSE:        /* Parse */
        break;
    case PGSQL_MSG_TYPE_BIND:         /* Bind */
        break;
    case PGSQL_MSG_TYPE_EXEC:         /* Execute */
        break;
    case PGSQL_MSG_TYPE_DESC:         /* Describe */
        break;
    case PGSQL_MSG_TYPE_CLOSE:        /* Close */
        break;
    case PGSQL_MSG_TYPE_FLUSH:        /* Flush */
        break;
    case PGSQL_MSG_TYPE_SYNC:         /* Sync */
        break;
    case PGSQL_MSG_TYPE_FUNC:         /* Function call */
        break;
    case PGSQL_MSG_TYPE_FE_COPY_DATA: /* Copy data */
        break;
    case PGSQL_MSG_TYPE_COPY_COMP:    /* Copy completion */
        break;
    case PGSQL_MSG_TYPE_COPY_FAIL:    /* Copy failure */
        break;
    case PGSQL_MSG_TYPE_TERM:         /* Termination */
        ret = pgsql_client_msg_termination(sess, msg);
        break;
    default:
        break;
    }

    return ret;
}

