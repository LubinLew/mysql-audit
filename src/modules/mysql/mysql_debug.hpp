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


#ifndef __MYSQL_DEBUG_H__
#define __MYSQL_DEBUG_H__
/*****************************************************************************/

#include <audit_debug.hpp>

#include "mysql_internal.hpp"

/*****************************************************************************/

void mysql_debug_start_session(mysql_sess_t& sess);
void mysql_debug_end_session(mysql_sess_t& sess);
void mysql_debug_exit_session(mysql_sess_t& sess);

void mysql_debug_data_coming(mysql_sess_t& sess, mysql_data_dir_t dir, size_t len);
void mysql_debug_print_packet(mysql_sess_t& sess, mysql_packet_t* packet, size_t len);

void mysql_debug_handshake_request(mysql_sess_t &sess);
void mysql_debug_handshake_response(mysql_sess_t& sess);

void mysql_debug_auth_more_data(mysql_sess_t &sess, mysql_auth_more_data_t& data);
void mysql_debug_auth_switch_request(mysql_sess_t &sess, mysql_auth_switch_request_t& req);
void mysql_debug_auth_switch_response(mysql_sess_t &sess,  mysql_auth_switch_response_t& resp);

void mysql_debug_response_ok(mysql_sess_t &sess, mysql_ok_packet_t &ok);
void mysql_debug_response_err(mysql_sess_t &sess, mysql_err_packet_t& err);
void mysql_debug_response_eof(mysql_sess_t &sess, mysql_eof_packet_t& eof);

void mysql_debug_cmd_quit(mysql_sess_t &sess);
void mysql_debug_cmd_ping(mysql_sess_t &sess);
void mysql_debug_cmd_debug(mysql_sess_t &sess);
void mysql_debug_cmd_change_user(mysql_sess_t &sess, mysql_cmd_change_user_t& user);
void mysql_debug_com_reset_connection(mysql_sess_t &sess, mysql_cmd_reset_connection_t& conn);
void mysql_debug_cmd_statistics_request(mysql_sess_t &sess);
void mysql_debug_cmd_statistics_response(mysql_sess_t &sess, mysql_cmd_statistics_t& statistics);

void mysql_debug_cmd_query(mysql_sess_t &sess, mysql_cmd_query_t& req);
void mysql_debug_cmd_initdb(mysql_sess_t &sess, mysql_cmd_initdb_t& db);
void mysql_debug_cmd_field_list(mysql_sess_t &sess, mysql_cmd_field_list_t& list);
void mysql_debug_cmd_refresh(mysql_sess_t &sess, mysql_cmd_refresh_t& refresh);
void mysql_debug_cmd_process_kill(mysql_sess_t &sess, mysql_cmd_process_kill_t& kill);

void mysql_debug_cmd_smst_prepare(mysql_sess_t &sess, mysql_cmd_stmt_prepare_t& pre);
void mysql_debug_cmd_smst_prepare_response(mysql_sess_t &sess, mysql_cmd_stmt_prepare_ok_t& pre);
void mysql_debug_cmd_smst_fetch(mysql_sess_t &sess, mysql_cmd_stmt_fetch_t& fetch);
void mysql_debug_cmd_smst_execute(mysql_sess_t &sess, mysql_cmd_stmt_execute_t& exe);
void mysql_debug_cmd_smst_close(mysql_sess_t &sess, mysql_cmd_stmt_close_t& close);
void mysql_debug_cmd_smst_reset(mysql_sess_t &sess, mysql_cmd_stmt_reset_t& rst);
void mysql_debug_cmd_smst_send_long_data(mysql_sess_t &sess, mysql_cmd_stmt_send_long_data_t& data);
void mysql_debug_cmd_smst_bulk_execute(mysql_sess_t &sess, mysql_cmd_stmt_bulk_execute_t& bulk);
void mysql_debug_cmd_binlog_dump(mysql_sess_t &sess, mysql_cmd_binlog_dump_t& dump);

void mysql_debug_column_count_packet(mysql_sess_t &sess, mysql_column_count_t& count);
void mysql_debug_column_definition_packet(mysql_sess_t &sess, mysql_column_def41_t& column);
void mysql_debug_text_resultset_row_packet(mysql_sess_t &sess, mysql_text_resultset_row_packet_t& row);
void mysql_debug_binary_resultset_row_packet(mysql_sess_t &sess, mysql_binary_resultset_row_packet_t& row);

void mysql_debug_local_inflie_request(mysql_sess_t &sess, mysql_infile_request_t& data);
void mysql_debug_local_inflie_response(mysql_sess_t &sess, mysql_infile_response_t& data);

/*****************************************************************************/
#endif /* __MYSQL_DEBUG_H__ */

