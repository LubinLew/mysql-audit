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


#include <stdint.h>
#include <iostream>     // std::cout
#include <algorithm>    // std::max

#include "mysql_utils.hpp"
#include "mysql_debug.hpp"
#include "mysql_audit.hpp"

#include <tins/tcp_ip/stream.h>

/*****************************************************************************/

using Tins::TCPIP::Stream;

bool mysql_dissect_check_capabilities(mysql_sess_t& sess, uint32_t flag);

/*****************************************************************************/


/* https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html
 * 
 * the offical doc says:
 * - OK: header = 0 and length of packet > 7
 * - EOF: header = 0xfe and length of packet < 9
 *
 * But Most OK_Packet length is 7 (MySQL 8.0)
 */
static bool mysql_dissect_is_valid_ok_length(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint32_t length = packet->payload_length;

    if (length >= 7) {
        return true;
    }

    return false;
}


static bool mysql_dissect_is_valid_eof_length(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint32_t length = packet->payload_length;

    if (length < 9) {
        return true;
    }

    return false;
}


/* https://dev.mysql.com/doc/refman/8.0/en/error-message-elements.html#error-code-ranges
 * 1,000  to 1,999: Server error codes reserved for messages sent to clients.
 * 2,000  to 2,999: Client error codes reserved for use by the client library.
 * 3,000  to 4,999: Server error codes reserved for messages sent to clients.
 * 5,000  to 5,999: Error codes reserved for use by X Plugin for messages sent to clients.
 * 10,000 to 49,999: Server error codes reserved for messages to be written to the error log (not sent to clients).
 * 50,000 to 51,999: Error codes reserved for use by third parties.
 *
 * https://mariadb.com/kb/en/mariadb-error-codes/
 * 1000 to 1982
 * 3000 to 3060
 * 4000 to 4182
 */
static bool mysql_dissect_is_vaild_errcode(mysql_sess_t& sess, uint16_t errcode)
{
    if (sess.variant == MYSQL_VARIANT_MARIADB) {
        if ((errcode > 999) && (errcode < 1983)) {
            return true;
        } else if ((errcode > 2999) && (errcode < 3061)) {
            return true;
        } else if ((errcode > 3999) && (errcode < 4183)) {
            return true;
        }

        return false;
    }

    /* other ? */
    if ((errcode > 999) && (errcode < 6000)) {
        return true;
    } else if ((errcode > 9999) && (errcode < 52000)) {
        return true;
    }

    return false;
}


/* Server Version 
 * 
 * MySQL:
 * - 8.0.28
 *
 * Percona:
 * - 8.0.32-24
 *
 * MariaDB:
 * - 5.5.68: 5.5.68-MariaDB
 * - 10.9.2: 5.5.5-10.9.2-MariaDB
 * - 10.11.3(docker): 5.5.5-10.11.3-MariaDB-1:10.11.3+maria~ubu2204
 */
static mysql_variant_t mysql_dissect_variant(audit_str_t& version)
{
    if (version.find("-MariaDB") != std::string::npos) {
        return MYSQL_VARIANT_MARIADB;
    } else if (version.find("-") != std::string::npos) {
        return MYSQL_VARIANT_PERCONA;
    }

    /* MySQL */
    return MYSQL_VARIANT_MYSQL;
}


static audit_ret_t mysql_dissect_ok_packet(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    bool is_next_query_exist = false;

    mysql_ok_packet_t ok = {};

    ok.header = audit_data_get_uint8(&start, end);
    ok.affected_rows = mysql_util_get_encode_uint(&start, end);
    sess.affected_rows = ok.affected_rows;
    ok.last_insert_id = mysql_util_get_encode_uint(&start, end);
    if (mysql_dissect_check_capabilities(sess, CLIENT_PROTOCOL_41)) {
        ok.status_flags = audit_data_get_uint16(&start, end);
        ok.warnings = audit_data_get_uint16(&start, end);
    } else if (mysql_dissect_check_capabilities(sess, CLIENT_TRANSACTIONS)) {
        ok.status_flags = audit_data_get_uint16(&start, end);
    }

    if (audit_data_get_remain_length(&start, end) > 0) {
        if (mysql_dissect_check_capabilities(sess, CLIENT_SESSION_TRACK)) {
            ok.info = mysql_util_get_encode_string(&start, end);
            if (ok.status_flags & SERVER_SESSION_STATE_CHANGED) {
                audit_data_get_eof_bytes(&start, end, ok.session_state_info);
            }
        } else {
            ok.info = audit_data_get_eof_string(&start, end);
        }
    }

    if (ok.status_flags & SERVER_MORE_RESULTS_EXISTS) {
        is_next_query_exist = true;
    }

    if (is_next_query_exist) {
        sess.state = MYSQL_STATE_CMD_QUERY_RESPONSE;
        mysql_debug_response_ok(sess, ok);
        return RET_OK;
    }

    sess.state = MYSQL_STATE_CMD_END;
    sess.packet_type = MYSQL_PACK_TYPE_RESP_OK;
    mysql_debug_response_ok(sess, ok);
    mysql_audit_log(sess, true, (uint8_t*)&ok);

    if (sess.phase == MYSQL_SESS_PHASE_HANDSHAKE) {
        sess.phase = MYSQL_SESS_PHASE_CMD;
        if (sess.compress_type != MYSQL_COMPRESS_NONE) { /* handshake phase no compress */
            sess.is_compressed = true;
            sess.packet_header_size = 7;
        }
    }

    /* COM_INIT_DB success, so we need to change the default database
     * and should be after the log
     */
    if (sess.command == COM_INIT_DB) {
        sess.database = sess.initdb;
    } else if (sess.command == COM_CHANGE_USER) {
        sess.user = sess.chg_user;
    }

    return RET_OK;
}


static audit_ret_t mysql_dissect_err_packet(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_err_packet_t err = {};

    err.header = audit_data_get_uint8(&start, end);
    err.error_code = audit_data_get_uint16(&start, end);
    if (!mysql_dissect_is_vaild_errcode(sess, err.error_code)) {
        return RET_NG;
    }

    if (mysql_dissect_check_capabilities(sess, CLIENT_PROTOCOL_41)) {
        err.sql_state_marker = audit_data_get_fixed_string(&start, end, 1);
        err.sql_state = audit_data_get_fixed_string(&start, end, 5);
    }

    err.error_message = audit_data_get_eof_string(&start, end);

    sess.state = MYSQL_STATE_CMD_END;
    sess.packet_type = MYSQL_PACK_TYPE_RESP_ERR;

    mysql_debug_response_err(sess, err);
    mysql_audit_log(sess, false, (uint8_t*)&err);

    return RET_OK;
}


static audit_ret_t mysql_dissect_eof_packet(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;
    bool     is_next_query_exist = false; /* Multi-Statement */

    mysql_eof_packet_t eof = {};

    eof.header = audit_data_get_uint8(&start, end);
    if (mysql_dissect_check_capabilities(sess, CLIENT_PROTOCOL_41)) {
        eof.warnings = audit_data_get_uint16(&start, end);
        eof.status_flags = audit_data_get_uint16(&start, end);
        if (eof.status_flags & SERVER_MORE_RESULTS_EXISTS) {
            is_next_query_exist = true;
        }
    }

    if (is_next_query_exist) {/* Multi-Statement */
        sess.state = MYSQL_STATE_CMD_QUERY_RESPONSE;
        mysql_debug_response_eof(sess, eof);
        return RET_OK;
    }

    sess.state = MYSQL_STATE_CMD_END;
    sess.packet_type = MYSQL_PACK_TYPE_RESP_EOF;
    mysql_debug_response_eof(sess, eof);
    mysql_audit_log(sess, true, (uint8_t*)&eof);

    if (sess.phase == MYSQL_SESS_PHASE_HANDSHAKE) {
        sess.phase = MYSQL_SESS_PHASE_CMD;
        if (sess.compress_type != MYSQL_COMPRESS_NONE) { /* handshake phase no compress */
            sess.is_compressed = true;
            sess.packet_header_size = 7;
        }
    }

    /* COM_INIT_DB success, so we need to change the default database */
    if (sess.command == COM_INIT_DB) {
        sess.database = sess.initdb;
    } else if (sess.command == COM_CHANGE_USER) {
        sess.user = sess.chg_user;
    }

    return RET_OK;
}


static audit_ret_t mysql_dissect_generic_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    audit_ret_t ret = RET_NG;

    uint8_t header = audit_data_get_uint8(&start, end);

    switch (header) {
    case MYSQL_RESP_TYPE_OK: /* OK Packet */
        if (mysql_dissect_is_valid_ok_length(sess, packet)) {
            ret = mysql_dissect_ok_packet(sess, packet);
        }
        break;

    case MYSQL_RESP_TYPE_EOF: /* EOF packet */
        if (mysql_dissect_is_valid_eof_length(sess, packet)) {
            ret = mysql_dissect_eof_packet(sess, packet);
        } else { /* OK_Packet can use 0x00 or 0xFE, found in mysql 5.7.42 */
            if (mysql_dissect_is_valid_ok_length(sess, packet)) {
                ret = mysql_dissect_ok_packet(sess, packet);
            }
        }
        break;

    case MYSQL_RESP_TYPE_ERR: /* ERR packet */
        ret = mysql_dissect_err_packet(sess, packet);
        break;

    default:
        break;
    }

    return ret;
}


static audit_ret_t mysql_dissect_column_cout_packet(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_column_count_t count = {};

    if (mysql_dissect_check_capabilities(sess, CLIENT_OPTIONAL_RESULTSET_METADATA) && \
        (sess.command != COM_STMT_EXECUTE)) {
        count.metadata_follows = audit_data_get_uint8(&start, end);
    }
    count.column_count = mysql_util_get_encode_uint(&start, end);

    /* management init */
    auto& col = sess.col_manager;
    col.col_total_count = count.column_count;
    col.col_recv_count = 0;

    sess.state = MYSQL_STATE_COLUMN_DEFINITION;
    sess.packet_type = MYSQL_PACK_TYPE_COLUMN_COUNT;

    mysql_debug_column_count_packet(sess, count);

    return RET_OK;
}


//Protocol::ColumnDefinition41
static audit_ret_t mysql_dissect_column_definition_packet(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;
    auto&    col    = sess.col_manager;

    mysql_column_def41_t column = {};

    column.catalog   = mysql_util_get_encode_string(&start, end);
    column.schema    = mysql_util_get_encode_string(&start, end);
    column.table     = mysql_util_get_encode_string(&start, end);
    column.org_table = mysql_util_get_encode_string(&start, end);
    column.name      = mysql_util_get_encode_string(&start, end);
    column.org_name  = mysql_util_get_encode_string(&start, end);

    column.fixed_length  = mysql_util_get_encode_uint(&start, end);
    column.character_set = audit_data_get_uint16(&start, end);
    column.column_length = audit_data_get_uint32(&start, end);
    column.type          = audit_data_get_uint8(&start, end);
    column.flags         = audit_data_get_uint16(&start, end);
    column.decimals      = audit_data_get_uint8(&start, end);

    ++col.col_recv_count;
    switch (sess.command) {
    case COM_QUERY:
    case COM_PROCESS_INFO:
    case COM_STMT_BULK_EXECUTE:
        if (col.col_recv_count == col.col_total_count) {
            /* management data init */
            auto& row = sess.row_manager;
            row.is_first_row = true;
            row.row_count = 0;
            /* change state */
            sess.state = MYSQL_STATE_TEXT_RESULTSET_ROW_PACKET;
        }
        break;

    case COM_FIELD_LIST: /* command field list, no column_count */
        /* Next Packet is ColumnDefinition or EOF_Packet */
        break;

    case COM_STMT_PREPARE:
        if (col.col_recv_count == col.col_total_count) {
            // log it, because EOF_packet maybe not coming
            mysql_audit_log(sess, true, nullptr);
            sess.state = MYSQL_STATE_GENGRIC_RESPONSE; // Maybe a EOF_packet will coming
        }
        break;

    case COM_STMT_EXECUTE:
        if (col.col_recv_count == col.col_total_count) {
            /* management data init */
            auto& row = sess.row_manager;
            row.is_first_row = true;
            row.row_count = 0;
            sess.state = MYSQL_STATE_BINARY_RESULTSET_ROW_PACKET; 
        }
        break;

    default:
        break;
    }

    sess.packet_type = MYSQL_PACK_TYPE_COLUMN_DEFINITION;
    mysql_debug_column_definition_packet(sess, column);

    return RET_OK;
}


static audit_ret_t mysql_dissect_text_resultset_row_packet(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_text_resultset_row_packet_t row = {};

    while (start < end) {
        auto text = mysql_util_get_encode_string(&start, end);
        row.texts.push_back(text);
    }

    //we never know how many row packet will come
    sess.state = MYSQL_STATE_TEXT_RESULTSET_ROW_PACKET;
    sess.packet_type = MYSQL_PACK_TYPE_TEXT_RESULTSET_ROW;
    mysql_debug_text_resultset_row_packet(sess, row);

    return RET_OK;
}


static audit_ret_t mysql_dissect_text_resultset_row_packet_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;
    uint8_t header  = audit_data_get_uint8(&start, end);

    audit_ret_t ret = RET_OK;

    mysql_row_mgr_t& mgr = sess.row_manager;

    //maybe a EOF_Packet After the Column Def.
    if (mgr.is_first_row) {
        mgr.is_first_row = false;
        if (!mysql_dissect_check_capabilities(sess, CLIENT_DEPRECATE_EOF)) {
            if (MYSQL_RESP_TYPE_EOF == header) {
                sess.command_is_logd = true;
                auto ret = mysql_dissect_eof_packet(sess, packet);
                sess.command_is_logd = false;
                sess.state = MYSQL_STATE_TEXT_RESULTSET_ROW_PACKET;
                return ret;
            }
        }
    }

    ++mgr.row_count;

    ret = mysql_dissect_generic_response(sess, packet);
    if (ret != RET_OK) {
        ret = mysql_dissect_text_resultset_row_packet(sess, packet);
    }

    return ret;
}


static audit_ret_t mysql_dissect_binary_resultset_row_packet(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_binary_resultset_row_packet_t row = {};

    row.packet_header = audit_data_get_uint8(&start, end);
    if (row.packet_header != 0x00) {
        return RET_NG;
    }

    size_t null_bitmap_length = (sess.col_manager.col_total_count + 7 + 2) / 8;
    audit_data_get_bytes(&start, end, row.null_bitmap, null_bitmap_length);
    audit_data_get_eof_bytes(&start, end, row.values);

    sess.state = MYSQL_STATE_BINARY_RESULTSET_ROW_PACKET;
    sess.packet_type = MYSQL_PACK_TYPE_BINARY_RESULTSET_ROW;
    mysql_debug_binary_resultset_row_packet(sess, row);

    return RET_OK;
}


static audit_ret_t mysql_dissect_binary_resultset_row_packet_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;
    uint8_t header  = audit_data_get_uint8(&start, end);

    audit_ret_t ret = RET_NG;

    mysql_row_mgr_t& mgr = sess.row_manager;
    //maybe a EOF_Packet After the Column Def.
    if (mgr.is_first_row) {
     mgr.is_first_row = false;
        if (!mysql_dissect_check_capabilities(sess, CLIENT_DEPRECATE_EOF)) {
            if (MYSQL_RESP_TYPE_EOF == header) {
                sess.command_is_logd = true;
                ret = mysql_dissect_eof_packet(sess, packet);
                sess.command_is_logd = false;
                sess.state = MYSQL_STATE_BINARY_RESULTSET_ROW_PACKET;
                return ret;
            }
        }
    }

    ret = mysql_dissect_generic_response(sess, packet);
    if (ret != RET_OK) {
        ret = mysql_dissect_binary_resultset_row_packet(sess, packet);
    }

    return ret;
}


static audit_ret_t mysql_dissect_handshake_request(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;
    mysql_handshake_request_t& req = sess.handshake_request;

    req.server_protocol = audit_data_get_uint8(&start, end);

    /* Maybe a ERR_Packet 
     * The CLIENT is not allowed to connect to SERVER
     */
    if (req.server_protocol == MYSQL_RESP_TYPE_ERR) {
        return mysql_dissect_err_packet(sess, packet);
    }

    if (req.server_protocol != 10) {
        if (req.server_protocol == 9) {
            audit_debug_err("Not Supported HANDSHAKE Version 9");
        } else {
            audit_debug_err("Unknown HANDSHAKE Version:%d", req.server_protocol);
        }

        return RET_ES;
    }

    req.server_version  = audit_data_get_string(&start, end);
    sess.variant = mysql_dissect_variant(req.server_version);

    req.connection_id = audit_data_get_uint32(&start, end);
    audit_data_get_bytes(&start, end, req.auth_plugin_data1, 8);
    audit_data_skip_bytes(&start, end, 1); //filter
    req.capability_lower = audit_data_get_uint16(&start, end);
    req.server_character_set = audit_data_get_uint8(&start, end);
    req.server_status_flags = audit_data_get_uint16(&start, end);
    req.capability_upper = audit_data_get_uint16(&start, end);
    req.server_capabilities = audit_data_make_word(req.capability_upper, req.capability_lower);
    req.auth_plugin_data_len = audit_data_get_uint8(&start, end);
    audit_data_skip_bytes(&start, end, 10); // reserved 10 bytes
    if (req.auth_plugin_data_len) {
        size_t length = std::max(13, req.auth_plugin_data_len - 8);
        audit_data_get_bytes(&start, end, req.auth_plugin_data2, length);
        req.auth_plugin_name = audit_data_get_string(&start, end);
    }

    sess.id += std::to_string(req.connection_id);
    sess.state = MYSQL_STATE_HANDSHAKE_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_HANDSHAKE_REQUEST;

    mysql_debug_handshake_request(sess);

    return RET_OK;
}


static audit_ret_t mysql_dissect_auth_more_data(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_auth_more_data_t data = {};
    data.header  = audit_data_get_uint8(&start, end);

    if (MYSQL_RESP_TYPE_OK == data.header) {
        return mysql_dissect_ok_packet(sess, packet);
    } else if (MYSQL_RESP_TYPE_ERR == data.header) {
        return mysql_dissect_err_packet(sess, packet);
    } else if (data.header != 0x01) {
        return RET_NG;
    }

    audit_data_get_eof_bytes(&start, end, data.data);

    sess.packet_type = MYSQL_PACK_TYPE_AUTH_MORE_DATA;
    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    
    mysql_debug_auth_more_data(sess, data);

    return RET_OK;
}


static audit_ret_t mysql_dissect_auth_switch_request(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_auth_switch_request_t auth = {};

    auth.status_flag = audit_data_get_uint8(&start, end);

    /* This is not a AuthSwitchRequest Packet */
    if (auth.status_flag != MYSQL_RESP_TYPE_EOF) { /* 0xFE, just same with MYSQL_RESP_HEADER_EOF */
        if (MYSQL_RESP_TYPE_ERR == auth.status_flag) { /* Is it a ERR_Packet ? */
            return mysql_dissect_err_packet(sess, packet);
        } else if (MYSQL_RESP_TYPE_OK == auth.status_flag) { /* Is it a OK_Packet ? No need to auth-switch */
            return mysql_dissect_ok_packet(sess, packet);
        } else if (0x01 == auth.status_flag) {/* 0x01, Protocol::AuthMoreData*/
            return mysql_dissect_auth_more_data(sess, packet);
        } else {
            audit_debug_err("Unknown Packet NOT <AuthSwithRequest>");
            sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
            return RET_NG;
        }
    } else {
        auth.plugin_name = audit_data_get_string(&start, end);
        audit_data_get_eof_bytes(&start, end, auth.plugin_data);
        sess.state = MYSQL_STATE_AUTH_SWITCH_RESPONSE;
    }

    sess.packet_type = MYSQL_PACK_TYPE_AUTH_SWICH_REQUEST;

    mysql_debug_auth_switch_request(sess, auth);

    return RET_OK;
}


static audit_ret_t mysql_dissect_local_infile_request(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_infile_request_t req = {};
    audit_data_skip_bytes(&start, end, 1); //skip packet type(0xFB)
    req.filename = audit_data_get_eof_string(&start, end);

    sess.state = MYSQL_STATE_LOCAL_INFILE_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_LOCAL_INFILE_REQUEST;

    mysql_debug_local_inflie_request(sess, req);

    return RET_OK;
}


/* COM_QUERY Response
 *
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response.html
 *
 * Returns:
 * - ERR_Packet
 * - OK_Packet/EOF_Packet
 * - LOCAL INFILE Request
 * - Text Resultset
 *    | column count
 *    | n * Column Definition
 *    | EOF_Packet (not capabilities & CLIENT_DEPRECATE_EOF)
 *    | m * Text Resultset Row
 *    | OK_Packet/EOF_Packet/ERR_Packet
 */
static audit_ret_t mysql_dissect_cmd_query_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;
    audit_ret_t ret = RET_OK;

    uint8_t header = audit_data_get_uint8(&start, end);

    if (MYSQL_RESP_TYPE_ERR == header) {
        ret = mysql_dissect_err_packet(sess, packet);
    } else if ((MYSQL_RESP_TYPE_EOF == header) && \
        mysql_dissect_is_valid_eof_length(sess, packet)) {
        ret = mysql_dissect_eof_packet(sess, packet);
    } else if ((MYSQL_RESP_TYPE_OK == header) &&  \
        mysql_dissect_is_valid_ok_length(sess, packet)) {
        ret = mysql_dissect_ok_packet(sess, packet);
    } else if (MYSQL_RESP_TYPE_LI == header) { /* LOCAL INFILE Request */
        ret = mysql_dissect_local_infile_request(sess, packet);
    } else { /* Text Resultset */
        ret = mysql_dissect_column_cout_packet(sess, packet);
    }

    return ret;
}


/* COM_FIELD_LIST Response
 *
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_field_list.html#sect_protocol_com_field_list_response
 *
 * The response to COM_FIELD_LIST can be one of:
 * - ERR_Packet
 * - zero or more Column Definition
 * - a closing EOF_Packet
 */
static audit_ret_t mysql_dissect_cmd_field_list_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    audit_ret_t ret = RET_OK;

    ret = mysql_dissect_generic_response(sess, packet);
    if (ret != RET_OK) {/* not a VALID respose packet */
        ret = mysql_dissect_column_definition_packet(sess, packet);
    }

    return ret;
}


/*
Returns:
 - Text Resultset
 - ERR_Packet
*/
static audit_ret_t mysql_dissect_cmd_process_info_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    uint8_t header = audit_data_get_uint8(&start, end);
    if (MYSQL_RESP_TYPE_ERR == header) {
        return mysql_dissect_err_packet(sess, packet);
    }

    return mysql_dissect_column_cout_packet(sess, packet);
}


static audit_ret_t mysql_dissect_cmd_statistics_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_cmd_statistics_t statistics = {};

    statistics.statistics = audit_data_get_eof_string(&start, end);

    sess.state = MYSQL_STATE_GENGRIC_RQUEST;

    mysql_debug_cmd_statistics_response(sess, statistics);

    /* no OK/EOF/ERR packet follows, so we need log it manually */
    mysql_audit_log(sess, true, nullptr);

    return RET_OK;
}


static audit_ret_t msyql_dissect_smst_prepare_ok(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_cmd_stmt_prepare_ok_t ok = {};

    ok.status = audit_data_get_uint8(&start, end);
    ok.statement_id = audit_data_get_uint32(&start, end);
    ok.num_columns = audit_data_get_uint16(&start, end);
    ok.num_params = audit_data_get_uint16(&start, end);
    audit_data_skip_bytes(&start, end, 1);

    size_t remain = audit_data_get_remain_length(&start, end);
    if (remain >= 2) {
        ok.warning_count = audit_data_get_uint16(&start, end);
    }
    if (remain >= 3) {
        ok.metadata_follows = audit_data_get_uint8(&start, end);
    }

    sess.col_manager.col_total_count = ok.num_params;
    sess.col_manager.col_recv_count  = 0;

    if (ok.num_params == 0) {
        sess.state = MYSQL_STATE_GENGRIC_RESPONSE; /* Maybe a EOF_Packet will coming */
    } else {//next num_params COLUMN packet
        sess.state = MYSQL_STATE_COLUMN_DEFINITION;
    }

    sess.packet_type = MYSQL_PACK_TYPE_CMD_STMT_PREPARE_OK;
    mysql_debug_cmd_smst_prepare_response(sess, ok);

    return RET_OK;
}


// COM_STMT_PREPARE_OK on success, ERR_Packet otherwise
static audit_ret_t mysql_dissect_stmt_prepare_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    uint8_t header = audit_data_get_uint8(&start, end);
    if (MYSQL_RESP_TYPE_OK == header) {
        return msyql_dissect_smst_prepare_ok(sess, packet);
    } else if (MYSQL_RESP_TYPE_ERR == header) {
        return mysql_dissect_err_packet(sess, packet);
    }

    /* should not go here */
    return RET_NG;
}


/*
a OK_Packet
a ERR_Packet
Binary Protocol Resultset
*/
static audit_ret_t mysql_dissect_stmt_exetute_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    uint8_t header = audit_data_get_uint8(&start, end);
    if (MYSQL_RESP_TYPE_OK == header) {
        return mysql_dissect_ok_packet(sess, packet);
    } else if (MYSQL_RESP_TYPE_ERR == header) {
        return mysql_dissect_err_packet(sess, packet);
    }

    /* Binary Protocol Resultset */
    return mysql_dissect_column_cout_packet(sess, packet);
}


static audit_ret_t mysql_dissect_stmt_fetch_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    uint8_t header = audit_data_get_uint8(&start, end);
   
    if (MYSQL_RESP_TYPE_ERR == header) {
        return mysql_dissect_err_packet(sess, packet);
    }

    /* Multi-Resultset */
    return mysql_dissect_binary_resultset_row_packet_response(sess, packet);
}


/* Returns
 * - Binlog Network Stream on success
 * - ERR_Packet on error
 */
static audit_ret_t mysql_dissect_cmd_binlog_dump_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    uint8_t header = audit_data_get_uint8(&start, end);
   if (MYSQL_RESP_TYPE_ERR == header) {
        return mysql_dissect_err_packet(sess, packet);
    }

   //TODO: Binlog Network Stream

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_end(mysql_sess_t& sess, mysql_packet_t* packet)
{
    audit_debug_err("SERVER send data after command successfully, STATE ERROR");

    if (mysql_dissect_generic_response(sess, packet) == RET_OK) {
	return RET_OK;
    }

    return RET_NG;
}


audit_ret_t server_one_packet_proc(Stream& stream, mysql_sess_t& sess, mysql_packet_t* packet)
{
    audit_ret_t ret = RET_OK;

    sess.statistics_session_server += packet->payload_length;
    sess.statistics_command_server += packet->payload_length;

    switch (sess.state) {
    case MYSQL_STATE_HANDSHAKE_REQUEST:
        ret = mysql_dissect_handshake_request(sess, packet); /* change to HANDSHAKE_RESPONSE state */
        break;

    /* This case should be handled by client-side, 
     * But if client CLOSE the tcp session, this case will occur.
     */
    case MYSQL_STATE_HANDSHAKE_RESPONSE: 
        ret = mysql_dissect_err_packet(sess, packet);
        break;

    case MYSQL_STATE_AUTH_SWITCH_REQUEST:
        ret = mysql_dissect_auth_switch_request(sess, packet); /* change to AUTH_SWITCH_RESPONSE state */
        break;

    case MYSQL_STATE_AUTH_MOREDATA:
        ret = mysql_dissect_auth_more_data(sess, packet);
        break;

    /* This case should be handled by client-side, 
     * But if client CLOSE the tcp session, this case will occur.
     */
    case MYSQL_STATE_AUTH_SWITCH_RESPONSE:
        ret = mysql_dissect_err_packet(sess, packet);
        break;

    case MYSQL_STATE_TEXT_RESULTSET_ROW_PACKET:
        ret = mysql_dissect_text_resultset_row_packet_response(sess, packet);
        break;

    case MYSQL_STATE_BINARY_RESULTSET_ROW_PACKET:
        ret = mysql_dissect_binary_resultset_row_packet_response(sess, packet);
        break;

    case MYSQL_STATE_COLUMN_DEFINITION:
        ret = mysql_dissect_column_definition_packet(sess, packet);
        break;

    case MYSQL_STATE_CMD_QUERY_RESPONSE:
        ret = mysql_dissect_cmd_query_response(sess, packet);
        break;

    case MYSQL_STATE_CMD_SMST_PREPARE_RESPONSE:
        ret = mysql_dissect_stmt_prepare_response(sess, packet);
        break;

    case MYSQL_STATE_CMD_SMST_EXECUTE_RESPONSE:
        ret = mysql_dissect_stmt_exetute_response(sess, packet);
        break;

    case MYSQL_STATE_CMD_SMST_FETCH_RESPONSE:
        ret = mysql_dissect_stmt_fetch_response(sess, packet);
        break;

    case MYSQL_STATE_CMD_FIELDLIST_RESPONSE:
        ret = mysql_dissect_cmd_field_list_response(sess, packet);
        break;

    case MYSQL_STATE_CMD_PROCESS_INFO_RESPONSE:
        ret = mysql_dissect_cmd_process_info_response(sess, packet);
        break;

    case MYSQL_STATE_GENGRIC_RESPONSE:
        ret = mysql_dissect_generic_response(sess, packet);
        break;

    case MYSQL_STATE_CMD_STATISTICS_RESPONSE:
        ret = mysql_dissect_cmd_statistics_response(sess, packet);
        break;

    case MYSQL_STATE_CMD_BINLOG_DUMP_RESPONSE:
        ret = mysql_dissect_cmd_binlog_dump_response(sess, packet);
        break;

    case MYSQL_STATE_CMD_END:
        ret = mysql_dissect_cmd_end(sess, packet);
        break;

    case MYSQL_STATE_CLOSED: /* The Packet After COM_QUIT, must be ERR_Packet */
        ret = mysql_dissect_err_packet(sess, packet);
        break;

    default:
        ret = mysql_dissect_err_packet(sess, packet);
        break;
    }

    if (ret != RET_OK) {
        audit_debug_err("Unknown Server Packet Or Malformad Packet");
 //       mysql_debug_packet(packet);
    }

    return ret;
}

/*****************************************************************************/

