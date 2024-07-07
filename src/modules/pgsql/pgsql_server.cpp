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

/*****************************************************************************/

using Tins::TCPIP::Stream;

bool pgsql_create_tls_session(pgsql_sess_t& sess);

/*****************************************************************************/

static audit_ret_t pgsql_server_msg_ssl_response(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    uint8_t* start = msg.body;
    uint8_t* end   = start + msg.length;

    if (msg.length != 1) {
        audit_debug_err("msg_length(%u) is not 1", msg.length);
        return RET_ES;
    }

    uint8_t response = audit_data_get_uint8(&start, end);
    if (response == 'S') {
        auto ok = pgsql_create_tls_session(sess);
        if (!ok) {
            return RET_ES;
        }
    } else if (response == 'N') {
        sess.is_ssl = false;
    } else {
        audit_debug_err("unknown SSLRespose data %d", response);
        return RET_ES;
    }

    audit_debug_dbg("SSLRespose %c", response);

    return RET_OK;
}


static audit_ret_t pgsql_server_msg_ready_for_query(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    sess.is_simple_query = false;
    sess.statistics_command_client = 0;
    sess.statistics_command_server = 0;

    if unlikely(sess.phase == PGSQL_PHASE_STA) {
        pgsql_audit_log(sess, true, nullptr); /* starup success audit log */
        sess.phase = PGSQL_PHASE_CMD;
    }

    return RET_OK;
}

static audit_ret_t pgsql_server_msg_parameter_status(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    uint8_t* start = msg.body;
    uint8_t* end   = start + msg.length;

    auto key = audit_data_get_string(&start, end);
    auto val = audit_data_get_string(&start, end);

    if unlikely(key == "server_version") {
        sess.server_version = val;
    } else {
        sess.parameter_status.insert({key, val});
    }

    return RET_OK;
}

static audit_ret_t pgsql_server_msg_command_completion(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    if (sess.is_simple_query) { /* audit log */
        pgsql_audit_log(sess, true, nullptr);

    }

    sess.is_simple_query = false;

    return RET_OK;
}


static audit_ret_t pgsql_server_msg_backend_key_data(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    uint8_t* start = msg.body;
    uint8_t* end   = start + msg.length;

    pgsql_msg_be_key_data_t& key = sess.be_key_data;
    key.pid = audit_data_get_uint32_be(&start, end);
    key.key = audit_data_get_uint32_be(&start, end);

    return RET_OK;
}


static audit_ret_t pgsql_server_msg_auth_request(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    static const char* _tbl[] = {
        "Success",
        "Kerberos V4",
        "Kerberos V5",
        "Plaintext password",
        "crypt()ed password",
        "MD5 password",
        "SCM credentials",
        "GSSAPI",
        "GSSAPI/SSPI continue",
        "SSPI",
        "SASL",
        "SASL continue",
        "SASL complete",
    };

    uint8_t* start = msg.body;
    uint8_t* end   = start + msg.length;

    uint32_t auth_type = audit_data_get_uint32_be(&start, end);
    if (auth_type == PGSQL_AUTH_TYPE_SUCCESS) {
        sess.is_login_success = true;
    }

    if (auth_type < PGSQL_AUTH_TYPE_INVALID) {
        audit_debug_dbg("auth-req: %s", _tbl[auth_type]);
    } else {
        audit_debug_err("Invalid auth type: %u", auth_type);
    }

    return RET_OK;
}


static audit_ret_t pgsql_server_msg_error(pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    uint8_t* start = msg.body;
    uint8_t* end   = start + msg.length;

    pgsql_msg_err_t err {};

    while (start < end - 1) {
        uint8_t type = audit_data_get_uint8(&start, end);
        auto val = audit_data_get_string(&start, end);

        switch (type) {
        case 'S':
            err.severity = val;
            break;
        case 'C':
            err.code = val;
            break;
        case 'M':
            err.message = val;
            break;
        case 'D': //detail
            break;
        case 'H': //hint
            break;
        case 'P': //position
            break;
        case 'p': //internal_position
            break;
        case 'q': //internal_query
            break;
        case 'W': //where
            break;
        case 's': //schema_name
            break;
        case 't': //table_name
            break;
        case 'c': //column_name
            break;
        case 'd': //type_name
            break;
        case 'n': //constraint_name
            break;
        case 'F': //file
         break;
        case 'L': //line
            break;
        case 'R': //routine
            break;
        default:
            break;
        }
    }

    pgsql_audit_log(sess, false, &err);

    pgsql_debug_msg_error(sess, err);

    return RET_OK;
}


audit_ret_t pgsql_server_msg_proc(Stream& stream, pgsql_sess_t& sess, pgsql_msg_t& msg)
{
    audit_ret_t ret = RET_OK;

    sess.statistics_command_server += (msg.length + 4);
    sess.statistics_session_server += (msg.length + 4);

    switch (sess.msg_type) {
    case PGSQL_MSG_TYPE_SSL_RESPONSE:
        ret = pgsql_server_msg_ssl_response(sess, msg);
        break;
    case PGSQL_MSG_TYPE_AUTH_REQ:       /* Authentication Request */
        ret = pgsql_server_msg_auth_request(sess, msg);
        break;
    case PGSQL_MSG_TYPE_BE_KEY_DATA:    /* Backend key data */
        ret = pgsql_server_msg_backend_key_data(sess, msg);
        break;
    case PGSQL_MSG_TYPE_PARAM_STATUS:   /* Parameter status */
        ret = pgsql_server_msg_parameter_status(sess, msg);
        break;
    case PGSQL_MSG_TYPE_PARSE_COMP:     /* Parse completion */
        break;
    case PGSQL_MSG_TYPE_BIND_COMP:      /* Bind completion */
        break;
    case PGSQL_MSG_TYPE_CLOSE_COMP:     /* Close completion */
        break;
    case PGSQL_MSG_TYPE_CMD_COMP:       /* Command completion */
        ret = pgsql_server_msg_command_completion(sess, msg);
        break;
    case PGSQL_MSG_TYPE_PARAM_DSEC:     /* Parameter description */
        break;
    case PGSQL_MSG_TYPE_ROW_DESC:       /* Row description */
        break;
    case PGSQL_MSG_TYPE_DATA_ROW:       /* Data row */
        break;
    case PGSQL_MSG_TYPE_EMPTY_QUERY:    /* Empty query */
        break;
    case PGSQL_MSG_TYPE_NO_DATA:        /* No data */
        break;
    case PGSQL_MSG_TYPE_ERROR:          /* Error */
        ret = pgsql_server_msg_error(sess, msg);
        break;
    case PGSQL_MSG_TYPE_NOTICE:         /* Notice */
        break;
    case PGSQL_MSG_TYPE_PORTAL_SUSP:    /* Portal suspended */
        break;
    case PGSQL_MSG_TYPE_READY_QUERY:    /* Ready for query */
        ret = pgsql_server_msg_ready_for_query(sess, msg);
        break;
    case PGSQL_MSG_TYPE_NOTIFY:         /* Notification */
        break;
    case PGSQL_MSG_TYPE_FUNC_RESP:      /* Function call response */
        break;
    case PGSQL_MSG_TYPE_COPY_IN_RESP:   /* CopyIn response */
        break;
    case PGSQL_MSG_TYPE_COPY_OUT_RESP:  /* CopyOut response */
        break;
    case PGSQL_MSG_TYPE_BE_COPY_DATA:   /* Copy data */
        break;
    case PGSQL_MSG_TYPE_BE_COPY_COMP:   /* Copy completion */
        break;
    case PGSQL_MSG_TYPE_BE_NEGO_VER:    /* Negotiate protocol version */
        break;
    default:
        break;
    }


    return ret;
}

