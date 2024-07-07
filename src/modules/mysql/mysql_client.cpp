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
#include "mysql_info.hpp"
#include "mysql_statement.hpp"
#include "mysql_audit.hpp"

#include <tins/tcp_ip/stream.h>

/*****************************************************************************/

using Tins::TCPIP::Stream;

bool mysql_create_tls_session(mysql_sess_t& sess);
mysql_compress_type_t mysql_dissect_get_compress_kind(mysql_sess_t& sess);
bool mysql_dissect_check_capabilities(mysql_sess_t& sess, uint32_t flag);

/*****************************************************************************/

/*
 * - HandshakeResponse
 * - SSLRequest
 */
static audit_ret_t mysql_dissect_handshake_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;
    mysql_handshake_respone_t& resp = sess.handshake_respone;

    resp.client_capabilities = audit_data_get_uint32(&start, end);
    sess.capabilities = resp.client_capabilities & sess.handshake_request.server_capabilities;
    
    resp.max_packet_size = audit_data_get_uint32(&start, end);
    resp.character_set = audit_data_get_uint8(&start, end);
    audit_data_skip_bytes(&start, end, 23);

    size_t remain = audit_data_get_remain_length(&start, end);
    if (remain == 0) {// This is a SSLRequest Packet
        auto ok = mysql_create_tls_session(sess);
        if (!ok) {
            audit_debug_err("Found SSLRequest Packet,  But TLS INIT FAILED");
            return RET_ES;
        }

        audit_debug_dbg("Found SSLRequest Packet");
        sess.state = MYSQL_STATE_HANDSHAKE_RESPONSE;
        sess.packet_type = MYSQL_PACK_TYPE_HANDSHAKE_SSL_REQUEST;
        return RET_OK;
    }

    resp.username = audit_data_get_string(&start, end);
    if (mysql_dissect_check_capabilities(sess, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)) {
        resp.auth_response_length = mysql_util_get_encode_uint(&start, end);
    } else {
        resp.auth_response_length = audit_data_get_uint8(&start, end);
    }
    audit_data_get_bytes(&start, end, resp.auth_response, resp.auth_response_length);

    if (mysql_dissect_check_capabilities(sess,  CLIENT_CONNECT_WITH_DB)) {
        resp.database = audit_data_get_string(&start, end);
    }

    if (mysql_dissect_check_capabilities(sess,  CLIENT_PLUGIN_AUTH)) {
        resp.client_plugin_name = audit_data_get_string(&start, end);
    }

    if (mysql_dissect_check_capabilities(sess,  CLIENT_CONNECT_ATTRS)) {
        resp.client_attr_length = mysql_util_get_encode_uint(&start, end);
        uint8_t* attr_end = start + resp.client_attr_length;
        while (start < attr_end) {
            auto key = mysql_util_get_encode_string(&start, end);
            auto val = mysql_util_get_encode_string(&start, end);
            resp.client_attr.insert({key, val});
        }
    }

    /* protocol_compression_algorithms=zlib,zstd,uncompressed */
    sess.compress_type = mysql_dissect_get_compress_kind(sess);
    if (sess.compress_type == MYSQL_COMPRESS_ZSTD) {
       /* if matching flag is CLIENT_ZSTD_COMPRESSION_ALGORITHM then client sends extra 1 byte in Protocol::HandshakeResponse */
        if (end - start == 1) {
            resp.zstd_compression_level = audit_data_get_uint8(&start, end);
            /* The ZSTD library supports compression levels from 1 to 22. default compression level is 3. */
            if ((resp.zstd_compression_level > 23) || (resp.zstd_compression_level < 1)) {
                audit_debug_err("Invalid ZSTD compression level: %d", resp.zstd_compression_level);
            }
        } else {
            audit_debug_err("enable ZSTD compression, but no level found");
        }
    }
    audit_debug_dbg("compress_type is %d", sess.compress_type);

    sess.state = MYSQL_STATE_AUTH_SWITCH_REQUEST;
    sess.packet_type = MYSQL_PACK_TYPE_HANDSHAKE_RESPONSE;
    sess.user = resp.username;
    if (!resp.database.empty()) {
        sess.database = resp.database;
    }

    mysql_debug_handshake_response(sess);

    return RET_OK;
}


static audit_ret_t mysql_dissect_auth_switch_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_auth_switch_response_t resp = {};

    audit_data_get_eof_bytes(&start, end, resp.data);

    sess.state = MYSQL_STATE_AUTH_MOREDATA;
    sess.packet_type = MYSQL_PACK_TYPE_AUTH_SWICH_RESPONSE;

    mysql_debug_auth_switch_response(sess, resp);

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_quit(mysql_sess_t& sess, mysql_packet_t* packet)
{
    /* packet check */
    if (packet->payload_length != 1) {
        return RET_NG;
    }

    sess.state = MYSQL_STATE_CLOSED;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_QUIT;
    sess.statement = "nul";

    mysql_debug_cmd_quit(sess);

    /* Server closes the connection or returns ERR_Packet.
     * So we need logit in mysql_dissect_destroy_session()
     */

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_query(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_cmd_query_t req = {};

    req.command = audit_data_get_uint8(&start, end);

    if (mysql_dissect_check_capabilities(sess, CLIENT_QUERY_ATTRIBUTES)) {
        req.parameter_count = mysql_util_get_encode_uint(&start, end);
        req.parameter_set_count = mysql_util_get_encode_uint(&start, end);

        if (req.parameter_count > 0) {
            size_t length = (req.parameter_count + 7) / 8;
            audit_data_get_bytes(&start, end, req.null_bitmap, length);
            req.new_params_bind_flag = audit_data_get_uint8(&start, end);

            if (req.new_params_bind_flag) {
                for (uint64_t i = 0; i < req.parameter_count; i++) {
                    mysql_binary_param_t param = {};
                    param.parameter_type = audit_data_get_uint16(&start, end);
                    param.parameter_name = mysql_util_get_encode_string(&start, end);
                    req.parameters.push_back(param);
                }
                
                for (uint64_t i = 0; i < req.parameter_count; i++) {
                    auto ok = mysql_util_get_bitmap_null(req.null_bitmap, (uint32_t)i);
                    mysql_binary_param_t& param = req.parameters[i];
                    if (!ok) {
                        param.parameter_value = mysql_util_get_binary_data(&start, end, param.parameter_type);
                    }
                }
            } else { // new_params_bind_flag = 0
                /* I don't how to process the parameter_values without paramter type,
                  how to get the query offset ? */
                audit_debug_err("query packet got %d parameters, but no new_params_bind_flag set", req.parameter_count);
                return RET_NG;
            }
        }
    }

    /* Is this a Multi-Statement Query ?  
     * OK/EOF Packet has the SERVER_MORE_RESULTS_EXISTS flag to test it
     *
     * Is it contain BLOB object(binary string) ?
     *  - How to detect ?
     *  - How to decode ?
     */
    req.query = mysql_util_get_eof_query_string(&start, end);
    sess.statement = req.query;

    sess.state = MYSQL_STATE_CMD_QUERY_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_QUERY;

    mysql_debug_cmd_query(sess, req);

    return RET_OK;
}


static audit_ret_t mysql_dissect_local_infile_response(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_infile_response_t resp = {};

    if (packet->payload_length == 0) {/* empty packet */
        sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    } else {
        audit_data_get_eof_bytes(&start, end, resp.raw_data);
    }
    sess.packet_type = MYSQL_PACK_TYPE_LOCAL_INFILE_RESPONSE;

    mysql_debug_local_inflie_response(sess, resp);

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_initdb(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_cmd_initdb_t initdb = {};

    initdb.command = audit_data_get_uint8(&start, end);
    initdb.schema_name = audit_data_get_eof_string(&start, end);

    /* This command maybe fail, So we need cache it 
     * When this command success, Then change sess.database to it.
     */
    sess.initdb = initdb.schema_name;

    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_INIT_DB;
    sess.statement = audit_str_t("schema: ") + initdb.schema_name;

    mysql_debug_cmd_initdb(sess, initdb);
    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_field_list(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_cmd_field_list_t list = {};

    list.command = audit_data_get_uint8(&start, end);
    list.table = audit_data_get_string(&start, end);
    list.wildcard = audit_data_get_eof_string(&start, end);

    sess.state = MYSQL_STATE_CMD_FIELDLIST_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_FIELD_LIST;

    sess.statement = audit_str_t("table: ") + list.table;
    if (!list.wildcard.empty()) {
        sess.statement += audit_str_t(",wildcard:") + list.wildcard;
    }

    mysql_debug_cmd_field_list(sess, list);
    return RET_OK;
}


/* https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_refresh.html
 *
 * As of MySQL 5.7.11, COM_REFRESH is deprecated and will be removed in a future version of MySQL. 
 * Instead, use COM_QUERY to execute a FLUSH statement.
 */
static audit_ret_t mysql_dissect_cmd_refresh(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t* start  = packet->payload;
    uint8_t* end    = start + packet->payload_length;

    mysql_cmd_refresh_t refresh = {};

    refresh.command = audit_data_get_uint8(&start, end);
    /* enum_mysql_refresh_flag */
    refresh.sub_command = audit_data_get_uint8(&start, end);

    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_REFRESH;

    uint32_t subcmd = refresh.sub_command;
    sess.statement = "REFRESH:";
    if (subcmd & REFRESH_GRANT) {
        sess.statement += "Refresh grant tables;";
    } 
    if (subcmd & REFRESH_LOG) {
        sess.statement += "Start on new log file;";
    } 
    if (subcmd & REFRESH_TABLES) {
        sess.statement += "Close all tables;";
    }
    if (subcmd & REFRESH_HOSTS) {
        sess.statement += "Flush host cache;";
    }
    if (subcmd & REFRESH_STATUS) {
        sess.statement += "Flush status variables;";
    }
    if (subcmd & REFRESH_THREADS) {
        sess.statement += "Flush thread cache;";
    }
    if (subcmd & REFRESH_SLAVE) {
        sess.statement += "Reset master info and restart slave thread;";
    }
    if (subcmd & REFRESH_MASTER) {
        sess.statement += "Remove all bin logs in the index and truncate the index;";
    }

    mysql_debug_cmd_refresh(sess, refresh);
    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_statistics(mysql_sess_t& sess, mysql_packet_t* packet)
{
    sess.state = MYSQL_STATE_CMD_STATISTICS_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_STATISTICS;

    sess.statement = "nul";

    mysql_debug_cmd_statistics_request(sess);
    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_process_info(mysql_sess_t& sess, mysql_packet_t* packet)
{
    //no data to proc

    sess.state = MYSQL_STATE_CMD_PROCESS_INFO_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_PROCESS_INFO;

    sess.statement = "nul";

//   mysql_debug_cmd_process_info(sess);

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_process_kill(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end = start + packet->payload_length;

    mysql_cmd_process_kill_t kill = {};

    kill.command = audit_data_get_uint8(&start, end);
    kill.connection_id = audit_data_get_uint32(&start, end);

    /* Returns:
     * Text Resultset
     * ERR_Packet
     */
    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_PROCESS_KILL;

    sess.statement = "connection id: " + std::to_string(kill.connection_id);

    mysql_debug_cmd_process_kill(sess, kill);
    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_debug(mysql_sess_t& sess, mysql_packet_t* packet)
{
    //no data to proc

    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_DEBUG;

    sess.statement = "nul";

    mysql_debug_cmd_debug(sess);
    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_ping(mysql_sess_t& sess, mysql_packet_t* packet)
{
    /* Returns:
     * Text Resultset
     * ERR_Packet
     */
    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_PING;

    sess.statement = "nul";

    mysql_debug_cmd_ping(sess);
    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_change_user(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end = start + packet->payload_length;

    mysql_cmd_change_user_t user = {};

    user.command = audit_data_get_uint8(&start, end);
    user.user = audit_data_get_string(&start, end);
    user.auth_plugin_data_len = audit_data_get_uint8(&start, end);
    audit_data_get_bytes(&start, end, user.auth_plugin_data, user.auth_plugin_data_len);
    user.database = audit_data_get_string(&start, end);

    if (start != end) {/* if more data available */
        if (mysql_dissect_check_capabilities(sess, CLIENT_PROTOCOL_41)) {
            user.character_set = audit_data_get_uint16(&start, end);
        }
        if (mysql_dissect_check_capabilities(sess, CLIENT_PLUGIN_AUTH)) {
            user.auth_plugin_name = audit_data_get_string(&start, end);
        }
        if (mysql_dissect_check_capabilities(sess, CLIENT_CONNECT_ATTRS)) {
            user.connection_attributes_length = mysql_util_get_encode_uint(&start, end);
            uint8_t* attr_end = start + user.connection_attributes_length;
            while (start < attr_end) {
                auto key = mysql_util_get_encode_string(&start, end);
                auto val = mysql_util_get_encode_string(&start, end);
                user.connection_attributes.insert({key, val});
            }
        }
    }

    /* Returns:
     * AuthSwitchRequest
     * ERR_Packet
     */
    sess.state = MYSQL_STATE_AUTH_SWITCH_REQUEST;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_CHANGE_USER;
    sess.chg_user = user.user;
    sess.statement = "user: " + user.user;

    mysql_debug_cmd_change_user(sess, user);
    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_reset_connection(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end = start + packet->payload_length;

    mysql_cmd_reset_connection_t conn = {};
    conn.command = audit_data_get_uint8(&start, end);

    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_RESET_CONNECTION;
    sess.statement = "nul";

    mysql_debug_com_reset_connection(sess, conn);
    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_set_option(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end = start + packet->payload_length;

    mysql_cmd_set_option_t opt = {};

    opt.command = audit_data_get_uint8(&start, end);
    opt.option_operation = audit_data_get_uint16(&start, end);

    /* Returns:
     * Text Resultset
     * ERR_Packet
     */
    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_SET_OPTION;
    if (opt.option_operation == MYSQL_OPTION_MULTI_STATEMENTS_ON) {
        sess.statement = "muti-statements: enable";
    } else {
        sess.statement = "muti-statements: disable";
    }

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_stmt_prepare(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end = start + packet->payload_length;

    mysql_cmd_stmt_prepare_t pre = {};

    pre.command = audit_data_get_uint8(&start, end);
    pre.query = audit_data_get_eof_string(&start, end);

    /* Returns:
     * COM_STMT_PREPARE_OK
     * ERR_Packet
     */
    sess.state = MYSQL_STATE_CMD_SMST_PREPARE_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_STMT_PREPARE;
    sess.statement = pre.query;

    mysql_debug_cmd_smst_prepare(sess, pre);

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_stmt_execute(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end = start + packet->payload_length;

    mysql_cmd_stmt_execute_t exe = {};

    exe.command = audit_data_get_uint8(&start, end);
    exe.statement_id = audit_data_get_uint32(&start, end);
    exe.flags = audit_data_get_uint8(&start, end);
    exe.iteration_count = audit_data_get_uint32(&start, end);

    size_t remain = audit_data_get_remain_length(&start, end);
    if (remain > 0) { // num_params > 0 || (CLIENT_QUERY_ATTRIBUTES && (exe.flags & PARAMETER_COUNT_AVAILABLE)
        bool client_query_attr = mysql_dissect_check_capabilities(sess, CLIENT_QUERY_ATTRIBUTES);
        if (client_query_attr) {
            //The number of parameter metadata and values supplied. Overrides the count coming from prepare (num_params) if present.
            exe.parameter_count = mysql_util_get_encode_uint(&start, end);
        }

        if (exe.parameter_count > 0) {
            size_t null_bitmap_length = (exe.parameter_count + 7) / 8;
            audit_data_get_bytes(&start, end, exe.null_bitmap, null_bitmap_length);
            exe.new_params_bind_flag = audit_data_get_uint8(&start, end);

            if (exe.new_params_bind_flag) {
                for (uint64_t i = 0; i < exe.parameter_count; i++) {
                    mysql_binary_param_t param = {};
                    param.parameter_type = audit_data_get_uint16(&start, end);
                    if (client_query_attr) {
                        param.parameter_name = mysql_util_get_encode_string(&start, end);
                    }
                    exe.parameters.push_back(param);
                }

                for (uint64_t i = 0; i < exe.parameter_count; i++) {
                    auto ok = mysql_util_get_bitmap_null(exe.null_bitmap, (uint32_t)i);
                    mysql_binary_param_t& param = exe.parameters[i];
                    if (!ok) {
                        param.parameter_value = mysql_util_get_binary_data(&start, end, param.parameter_type);
                    }
                }
            } else { /* I don't how to process the parameter_values without paramter type, how to get the query offset ? */
                audit_debug_err("stmt-execute packet got %d parameters, but no new_params_bind_flag set", exe.parameter_count);
                return RET_NG;
            }
        }
    }

    if (MYSQL_VARIANT_MARIADB == sess.variant) {
        sess.state = MYSQL_STATE_CMD_SMST_PREPARE_RESPONSE;
    } else {
        sess.state = MYSQL_STATE_CMD_SMST_EXECUTE_RESPONSE;
    }
    sess.packet_type = MYSQL_PACK_TYPE_CMD_STMT_EXECUTE;
    sess.statement = "statement id: " + std::to_string(exe.statement_id);

    mysql_debug_cmd_smst_execute(sess, exe);

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_stmt_fetch(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end   = start + packet->payload_length;

    mysql_cmd_stmt_fetch_t fetch = {};

    fetch.command = audit_data_get_uint8(&start, end);
    fetch.statement_id = audit_data_get_uint32(&start, end);
    fetch.num_rows = audit_data_get_uint32(&start, end);

    sess.state = MYSQL_STATE_CMD_SMST_FETCH_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_STMT_FETCH;
    sess.statement = "statement id: " + std::to_string(fetch.statement_id) + "rows: " + std::to_string(fetch.num_rows);

    mysql_debug_cmd_smst_fetch(sess, fetch);

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_stmt_close(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end   = start + packet->payload_length;

    mysql_cmd_stmt_close_t close = {};

    close.command = audit_data_get_uint8(&start, end);
    close.statement_id = audit_data_get_uint32(&start, end);

    sess.state = MYSQL_STATE_GENGRIC_RQUEST;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_STMT_CLOSE;
    sess.statement = "statement id: " + std::to_string(close.statement_id);

    mysql_debug_cmd_smst_close(sess, close);

    //No response packet is sent back to the client. so we need logit here
    mysql_audit_log(sess, true, nullptr);

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_stmt_reset(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end   = start + packet->payload_length;

    mysql_cmd_stmt_reset_t reset = {};

    reset.command = audit_data_get_uint8(&start, end);
    reset.statement_id = audit_data_get_uint32(&start, end);

    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_STMT_RESET;
    sess.statement = "statement id: " + std::to_string(reset.statement_id);

    mysql_debug_cmd_smst_reset(sess, reset);

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_stmt_send_long_data(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end   = start + packet->payload_length;

    mysql_cmd_stmt_send_long_data_t data = {};

    data.command = audit_data_get_uint8(&start, end);
    data.statement_id = audit_data_get_uint32(&start, end);
    data.param_id = audit_data_get_uint16(&start, end);
    audit_data_get_eof_bytes(&start, end, data.data);

    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_STMT_SEND_LONG_DATA;
    sess.statement = "statement id: " + std::to_string(data.statement_id);

    mysql_debug_cmd_smst_send_long_data(sess, data);

    //No response packet is sent back to the client. so we need logit here
    mysql_audit_log(sess, true, nullptr);

    return RET_OK;
}

/* COM_STMT_BULK_EXECUTE (only in MariaDB)
 * https://mariadb.com/kb/en/com_stmt_bulk_execute/
 *
 * A command that returns a resultset will return an error (Error packet).
 */

static audit_ret_t mysql_dissect_cmd_stmt_bulk_execute(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end   = start + packet->payload_length;

    mysql_cmd_stmt_bulk_execute_t bulk = {};

    bulk.command = audit_data_get_uint8(&start, end);
    bulk.statement_id = audit_data_get_uint32(&start, end);
    bulk.bulk_flag = audit_data_get_uint16(&start, end);
#if 0
    if (bulk.bulk_flag & MARIADB_BULK_SEND_TYPES) {
    }
#endif

    sess.state = MYSQL_STATE_CMD_SMST_PREPARE_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_STMT_BULK_EXECUTE;
    sess.statement = "nil";

    mysql_debug_cmd_smst_bulk_execute(sess, bulk);

    return RET_OK;
}




static audit_ret_t mysql_dissect_cmd_binlog_dump(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end   = start + packet->payload_length;

    mysql_cmd_binlog_dump_t dump = {};

    dump.status = audit_data_get_uint8(&start, end);
    dump.binlog_pos = audit_data_get_uint32(&start, end);
    dump.flags = audit_data_get_uint16(&start, end);
    dump.server_id = audit_data_get_uint32(&start, end);
    dump.binlog_filename = audit_data_get_eof_string(&start, end);

    sess.state = MYSQL_STATE_CMD_BINLOG_DUMP_RESPONSE;
    sess.packet_type = MYSQL_PACK_TYPE_CMD_BINLOG_DUMP;
    sess.statement = "nul";

    mysql_debug_cmd_binlog_dump(sess, dump);

    return RET_OK;
}


static audit_ret_t mysql_dissect_cmd_unknonw(mysql_sess_t& sess, mysql_packet_t* packet)
{
    sess.state = MYSQL_STATE_GENGRIC_RESPONSE;
    sess.statement = "nul";

    return RET_NG;
}


static audit_ret_t mysql_dissect_request(mysql_sess_t& sess, mysql_packet_t* packet)
{
    uint8_t *start = packet->payload;
    uint8_t *end   = start + packet->payload_length;

    uint8_t cmd = audit_data_get_uint8(&start, end);

    audit_ret_t ret = RET_NG;

    sess.command = (enum_server_command)cmd;

    switch (cmd) {
    case COM_QUIT:
        ret = mysql_dissect_cmd_quit(sess, packet);
        break;

    case COM_INIT_DB:
        ret = mysql_dissect_cmd_initdb(sess, packet);
        break;

    case COM_QUERY:
        ret = mysql_dissect_cmd_query(sess, packet);
        break;

    case COM_FIELD_LIST:
        ret = mysql_dissect_cmd_field_list(sess, packet);
        break;

    case COM_REFRESH:
        ret = mysql_dissect_cmd_refresh(sess, packet);
        break;

    case COM_STATISTICS:
        ret = mysql_dissect_cmd_statistics(sess, packet);
        break;

    case COM_PROCESS_INFO:
        ret = mysql_dissect_cmd_process_info(sess, packet);
        break;

    case COM_PROCESS_KILL:
        ret = mysql_dissect_cmd_process_kill(sess, packet);
        break;

    case COM_DEBUG:
        ret = mysql_dissect_cmd_debug(sess, packet);
        break;

    case COM_PING:
        ret = mysql_dissect_cmd_ping(sess, packet);
        break;

    case COM_CHANGE_USER:
        ret = mysql_dissect_cmd_change_user(sess, packet);
        break;

    case COM_RESET_CONNECTION:
        ret = mysql_dissect_cmd_reset_connection(sess, packet);
        break;

    case COM_SET_OPTION:
        return mysql_dissect_cmd_set_option(sess, packet);
        break;

    case COM_STMT_PREPARE:
        ret = mysql_dissect_cmd_stmt_prepare(sess, packet);
        break;

    case COM_STMT_EXECUTE:
        ret = mysql_dissect_cmd_stmt_execute(sess, packet);
        break;

    case COM_STMT_SEND_LONG_DATA:
        return mysql_dissect_cmd_stmt_send_long_data(sess, packet);
        break;

    case COM_STMT_CLOSE:
        ret = mysql_dissect_cmd_stmt_close(sess, packet);
        break;

    case COM_STMT_RESET:
        ret = mysql_dissect_cmd_stmt_reset(sess, packet);
        break;

    case COM_STMT_FETCH:
        ret = mysql_dissect_cmd_stmt_fetch(sess, packet);
        break;

    case COM_STMT_BULK_EXECUTE:
        ret = mysql_dissect_cmd_stmt_bulk_execute(sess, packet);
        break;

    case COM_BINLOG_DUMP:
        ret = mysql_dissect_cmd_binlog_dump(sess, packet);
        break;

    default:
        ret = mysql_dissect_cmd_unknonw(sess, packet);
        break;
    }

    if (ret != RET_OK) {
        audit_debug_err("Unsupported CMD: %d", cmd);
    }

    return ret;
}


audit_ret_t client_one_packet_proc(Stream& stream, mysql_sess_t& sess, mysql_packet_t* packet)
{
    audit_ret_t ret = RET_NG;

    sess.statistics_session_client += packet->payload_length;


    if (packet->sequence_id == 0) { /* New Command is coming ... */
        /* The sequence-id is incremented with each packet and may wrap around. 
         * It starts at 0 and is reset to 0 when a new command begins in the Command Phase. 
         */
        if (sess.command_is_logd == false) {
            if ((MYSQL_VARIANT_MARIADB == sess.variant) && (COM_STMT_PREPARE == sess.command)) {
                mysql_audit_log(sess, true, nullptr);
                sess.command_is_logd = false;
            } else {
                auto& server_payload = stream.server_payload();
                auto payload_size = server_payload.size();
                audit_debug_err("Previous Command(%s) is Not Finished, Server Side Left %u bytes", mysql_info_get_cmd(sess.command).c_str(), payload_size);
                if (payload_size) {
                    server_payload.clear();
                }
            }
        } else {
            sess.command_is_logd = false;
        }
        timespec_get(&sess.cmd_start_time, TIME_UTC);
        sess.affected_rows = 0;
        sess.state = MYSQL_STATE_GENGRIC_RQUEST;

        sess.statistics_command_client = packet->payload_length;
        sess.statistics_command_server = 0;
    } else {
        sess.statistics_command_client += packet->payload_length;
    }

    switch (sess.state) {
    case MYSQL_STATE_GENGRIC_RQUEST:
        ret = mysql_dissect_request(sess, packet);
        break;

    case MYSQL_STATE_HANDSHAKE_RESPONSE:
        ret = mysql_dissect_handshake_response(sess, packet);
        break;

    case MYSQL_STATE_AUTH_SWITCH_RESPONSE:
        ret = mysql_dissect_auth_switch_response(sess, packet);
        break;

    case MYSQL_STATE_LOCAL_INFILE_RESPONSE:
        ret = mysql_dissect_local_infile_response(sess, packet);
        break;

    default:
        break;
    }

    if (ret != RET_OK) {
        audit_debug_err("Unknown Client Packet Or Malformad Packet");
//        mysql_debug_packet(packet);
    }

    return ret;
}

/*****************************************************************************/

